"""crt.sh Certificate Transparency subdomain discovery.

Passive, read-only subdomain discovery from the crt.sh CT log API.  crt.sh is
a fixed host queried through the shared egress helper (SSRF-pinned, validated
IPs only) with strict connect/read timeouts, a response-size cap, bounded
retries with backoff (crt.sh often returns 502/503), a per-domain Redis cache
with TTL, and a global Redis token-bucket rate limit shared by all workers.

All external data is treated as untrusted: hostnames are normalized, only the
registered domain (and its subdomains) are kept, results are deduplicated, and
raw responses are never logged.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

from services.discovery.providers.base import (
    DiscoveredHost,
    DiscoveryProvider,
    ProviderError,
    ProviderResult,
    now_utc,
    normalize_host,
)
from utils.egress import EgressBlocked, fetch_url_validated
from utils.logger import logger
from utils.redis_client import get_redis

CRT_API = "https://crt.sh/?q=%25.{domain}&output=json"

# Lua script for an atomic, shared token bucket (global across all workers).
# Returns 1 if a token was granted, 0 otherwise. rate = tokens per second.
_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local max_burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])
if tokens == nil then tokens = max_burst end
if last_refill == nil then last_refill = now end
local elapsed = now - last_refill
tokens = math.min(max_burst, tokens + elapsed * rate)
local granted = 0
if tokens >= 1 then
    tokens = tokens - 1
    granted = 1
end
redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
redis.call('EXPIRE', key, 300)
return granted
"""


class CrtShProvider(DiscoveryProvider):
    """crt.sh CT-log discovery provider (no API key required)."""

    name = "crt_sh"
    requires_key = False

    def __init__(
        self,
        rate_limit_per_min: int = 60,
        cache_ttl_seconds: int = 3600,
        timeout_seconds: float = 15.0,
        max_retries: int = 3,
        max_bytes: int = 524288,
    ) -> None:
        self._rate_limit_per_min = max(rate_limit_per_min, 1)
        self._cache_ttl_seconds = max(cache_ttl_seconds, 1)
        self._timeout_seconds = max(timeout_seconds, 1.0)
        self._max_retries = max(max_retries, 0)
        self._max_bytes = max_bytes
        self._rate_per_sec = self._rate_limit_per_min / 60.0
        self._bucket_key = "ratelimit:discovery:crt_sh"

    # ── rate limiting (global token bucket, shared by all workers) ──
    def _grant_token(self) -> bool | None:
        """Atomically grant one token from the shared bucket via Lua.

        Returns:
          True  -- token granted, proceed with lookup.
          False -- bucket empty (rate limited), retry with backoff.
          None  -- Redis unavailable: fail closed, skip the lookup.
        """
        r = get_redis()
        try:
            granted = r.eval(
                _TOKEN_BUCKET_LUA,
                1,
                self._bucket_key,
                self._rate_per_sec,
                self._rate_limit_per_min,
                time.time(),
            )
            return bool(granted)
        except Exception as exc:  # Redis down: fail closed, do not bypass
            logger.warning(
                "crt.sh rate-limit bucket unavailable (%s), lookup skipped",
                type(exc).__name__,
            )
            return None

    # ── per-domain Redis cache ──
    def _cache_key(self, domain: str) -> str:
        return f"discovery:crt_sh:cache:{domain}"

    def _cache_get(self, domain: str) -> Optional[list[dict]]:
        r = get_redis()
        raw = r.get(self._cache_key(domain))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def _cache_set(self, domain: str, results: list[dict]) -> None:
        r = get_redis()
        try:
            r.set(
                self._cache_key(domain),
                json.dumps(results),
                ex=self._cache_ttl_seconds,
            )
        except Exception as exc:  # cache failure must not fail discovery
            logger.debug("crt.sh cache write failed (%s)", type(exc).__name__)

    # ── lookup ──
    async def lookup(self, domain: str) -> ProviderResult:
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            return ProviderResult(
                provider=self.name, error="empty domain", hosts_returned=0
            )

        # Cache hit (per domain, TTL-bound).
        cached = self._cache_get(domain)
        if cached is not None:
            hosts = self._normalize_list(cached, domain)
            return ProviderResult(
                provider=self.name,
                hosts=hosts,
                cache_hit=True,
                hosts_returned=len(hosts),
            )

        # Global rate limit (shared by all workers).  Fail CLOSED on Redis
        # outage (skip the lookup, report rate_limit_unavailable); retry
        # with backoff when the bucket is merely exhausted.
        rate_unavailable = False
        for attempt in range(self._max_retries + 1):
            granted = self._grant_token()
            if granted is None:
                # Redis down: fail closed, skip lookup non-fatally.
                rate_unavailable = True
                break
            if granted:
                break
            wait = min(1.0 * (2**attempt), 8.0)
            logger.debug(
                "crt.sh rate-limited for %s, retrying in %.1fs", domain, wait
            )
            await _sleep(wait)
        else:
            return ProviderResult(
                provider=self.name,
                error="rate_limit_exceeded",
                hosts_returned=0,
            )
        if rate_unavailable:
            return ProviderResult(
                provider=self.name,
                error="rate_limit_unavailable",
                hosts_returned=0,
            )

        url = CRT_API.format(domain=domain)
        last_error: Optional[str] = None
        for attempt in range(self._max_retries + 1):
            try:
                result = await _fetch_crt(url, self._timeout_seconds, self._max_bytes)
            except EgressBlocked as exc:
                # SSRF/egress violation: fail closed, do not retry.
                return ProviderResult(
                    provider=self.name,
                    error=f"egress_blocked: {type(exc).__name__}",
                    hosts_returned=0,
                )
            except Exception as exc:
                last_error = type(exc).__name__
                if attempt < self._max_retries:
                    wait = min(1.0 * (2**attempt), 8.0)
                    await _sleep(wait)
                    continue
                return ProviderResult(
                    provider=self.name,
                    error=f"fetch_failed: {last_error}",
                    hosts_returned=0,
                )

            if result.status_code == 200:
                try:
                    data = json.loads(result.body)
                except (ValueError, TypeError) as exc:
                    return ProviderResult(
                        provider=self.name,
                        error=f"json_parse_failed: {type(exc).__name__}",
                        hosts_returned=0,
                    )
                hosts = self._normalize_list(data, domain)
                self._cache_set(domain, data)
                return ProviderResult(
                    provider=self.name,
                    hosts=hosts,
                    hosts_returned=len(hosts),
                )
            # Retry on 502/503/504 (crt.sh flakiness).
            if result.status_code in (502, 503, 504) and attempt < self._max_retries:
                last_error = f"HTTP {result.status_code}"
                wait = min(1.0 * (2**attempt), 8.0)
                await _sleep(wait)
                continue
            return ProviderResult(
                provider=self.name,
                error=f"HTTP {result.status_code}",
                hosts_returned=0,
            )

        return ProviderResult(
            provider=self.name,
            error=last_error or "unknown",
            hosts_returned=0,
        )

    # ── normalization / filtering ──
    def _normalize_list(self, data: list, domain: str) -> list[DiscoveredHost]:
        hosts: list[DiscoveredHost] = []
        seen: set[str] = set()
        now = now_utc()
        wildcard_seen = False
        for item in data if isinstance(data, list) else []:
            item_hosts, was_wildcard = self._normalize_item(item, domain)
            if was_wildcard:
                wildcard_seen = True
            for host in item_hosts:
                if host in seen:
                    continue
                seen.add(host)
                hosts.append(
                    DiscoveredHost(
                        host=host,
                        source=self.name,
                        is_wildcard=was_wildcard,
                        first_seen=now,
                        last_seen=now,
                    )
                )
        if wildcard_seen:
            # Record that a wildcard cert covered this domain without
            # creating a literal wildcard host.
            hosts.append(
                DiscoveredHost(
                    host=domain,
                    source=self.name,
                    is_wildcard=True,
                    first_seen=now,
                    last_seen=now,
                )
            )
        return hosts

    def _normalize_item(
        self, item: dict, domain: str
    ) -> tuple[list[str], bool]:
        """Return (in-scope hosts, whether any wildcard cert covered them)."""
        name_value = item.get("name_value") if isinstance(item, dict) else None
        if not name_value or not isinstance(name_value, str):
            return [], False
        was_wildcard = False
        hosts: list[str] = []
        for entry in name_value.split("\n"):
            entry = entry.strip()
            if not entry:
                continue
            entry_wildcard = entry.startswith("*.")
            if entry_wildcard:
                was_wildcard = True
                entry = entry[2:]
            normalized = normalize_host(entry)
            if normalized is None:
                continue
            # Only keep the registered domain or its subdomains.
            if normalized == domain or normalized.endswith("." + domain):
                hosts.append(normalized)
        return hosts, was_wildcard


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


async def _fetch_crt(url: str, timeout: float, max_bytes: int):
    """Fetch crt.sh through the validated egress helper.

    Runs the async fetch on the current event loop; callers run this inside
    an asyncio context (the provider coordinator).
    """
    from utils.egress import fetch_url_validated

    return await fetch_url_validated(url, timeout=timeout, max_bytes=max_bytes)
