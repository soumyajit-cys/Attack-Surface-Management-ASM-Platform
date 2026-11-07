"""Subdomain discovery pipeline.

Merges discovery sources (crt.sh Certificate Transparency logs and DNS
brute-force resolution) into a single list of candidate subdomains for a
registered domain.

Every source result carries a ``source`` attribute plus ``first_seen`` /
``last_seen`` timestamps.  All external data is treated as untrusted:
hostnames are normalized, only the registered domain (and its subdomains)
are kept, results are deduplicated and capped per source, and raw responses
are never logged.

crt.sh is passive (public CT logs, no connections to the target).  DNS
brute-force is *active* discovery (it resolves candidate names against the
target's DNS) -- it is bounded, and its results are subject to the same
scope/verification gating as other active discovery (see
tasks.discovery_tasks).

Per-source results are capped at ``settings.max_subdomains_per_source_per_scan``;
truncated sources are flagged so the scan record and UI can surface it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

from app.core.config import settings
from services.discovery.enrichment_coordinator import DiscoveryCoordinator
from services.discovery.providers.crt_sh import CrtShProvider
from utils.egress import fetch_url_validated
from utils.logger import logger

CRT_API = "https://crt.sh/?q=%25.{}&output=json"

# Subdomain enumeration arrays scale with the target footprint; bounded here.
CRTSH_MAX_BYTES = 524288

# DNS brute-force wordlist: bounded to keep active discovery cheap and
# predictable.  This is active DNS querying against the target, not passive
# enumeration -- kept small on purpose.
DNS_BRUTE_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
    "ns1", "ns2", "dns1", "dns2", "mx1", "mx2", "api", "admin",
    "app", "dev", "staging", "test", "vpn", "portal", "blog",
    "shop", "support", "dev", "gitlab", "jenkins",
]
# Concurrency cap for the active DNS brute-force sweep.
DNS_BRUTE_CONCURRENCY = 10

logger = logging.getLogger("sentinelasm.discovery")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_hostname(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


async def discover_subdomains(domain: str) -> list[dict]:
    """Discover subdomains for *domain* from all enabled sources.

    Returns a list of dicts: ``{"subdomain", "source", "first_seen",
    "last_seen"}``.  Only the registered domain and its subdomains are kept;
    results are deduplicated across sources and capped per source.

    Each result dict may also carry ``truncated`` (bool) and
    ``truncated_count`` (int) when a source was capped by
    ``settings.max_subdomains_per_source_per_scan``.
    """
    domain = _normalize_hostname(domain)
    if not domain:
        return []

    providers = _build_providers()
    coordinator = DiscoveryCoordinator(
        providers,
        max_hosts_per_source_per_scan=settings.max_subdomains_per_source_per_scan,
    )
    hosts, results = await coordinator.discover(domain)

    # Collect truncation flags from provider results.
    truncation = {}
    for r in results:
        if getattr(r, "truncated", False):
            truncation[r.provider] = getattr(r, "truncated_count", 0)

    # Defense-in-depth: only keep the registered domain and its subdomains
    # from provider results (providers are expected to filter, but we verify).
    hosts = [
        h for h in hosts
        if h.host == domain or h.host.endswith("." + domain)
    ]

    # DNS brute-force is *active* discovery (DNS queries against the target).
    # It is bounded by DNS_BRUTE_WORDLIST / DNS_BRUTE_CONCURRENCY and subject
    # to the same scope gating as other active discovery downstream.
    brute = await _dns_brute_force(domain)
    now = _now()

    # Apply per-source cap to brute-force results, same as provider results.
    brute_kept = 0
    brute_truncated = 0
    for sub in brute:
        normalized = _normalize_hostname(sub)
        if not normalized or not (
            normalized == domain or normalized.endswith("." + domain)
        ):
            continue
        if brute_kept >= settings.max_subdomains_per_source_per_scan:
            brute_truncated += 1
            continue
        brute_kept += 1
        hosts.append(
            DiscoveredHostView(
                host=normalized,
                source="dns_brute",
                first_seen=now,
                last_seen=now,
            )
        )
    if brute_truncated > 0:
        truncation["dns_brute"] = brute_truncated

    # Dedup across sources: keep earliest first_seen, latest last_seen,
    # merge sources.
    merged: dict[str, dict] = {}
    for h in hosts:
        entry = merged.get(h.host)
        if entry is None:
            merged[h.host] = {
                "subdomain": h.host,
                "source": h.source,
                "sources": [h.source],
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
                "truncated": bool(truncation.get(h.source, False)),
                "truncated_count": truncation.get(h.source, 0),
            }
        else:
            if h.source not in entry["sources"]:
                entry["sources"].append(h.source)
            entry["first_seen"] = min(entry["first_seen"], h.first_seen)
            entry["last_seen"] = max(entry["last_seen"], h.last_seen)
            # A source is truncated if any of its entries were truncated.
            if truncation.get(h.source, False):
                entry["truncated"] = True
                entry["truncated_count"] = truncation.get(h.source, 0)

    result = [
        {
            "subdomain": sub,
            "source": entry["sources"][0] if entry["sources"] else "unknown",
            "sources": entry["sources"],
            "first_seen": entry["first_seen"].isoformat(),
            "last_seen": entry["last_seen"].isoformat(),
            "truncated": entry.get("truncated", False),
            "truncated_count": entry.get("truncated_count", 0),
        }
        for sub, entry in sorted(merged.items())
    ]
    return result


def _build_providers():
    from app.core.config import settings

    enabled = [
        name.strip() for name in (settings.discovery_providers or "crt_sh").split(",")
        if name.strip()
    ]
    providers = []
    if "crt_sh" in enabled:
        providers.append(
            CrtShProvider(
                rate_limit_per_min=settings.crt_sh_rate_limit_per_min,
                cache_ttl_seconds=settings.crt_sh_cache_ttl_seconds,
                timeout_seconds=settings.crt_sh_timeout_seconds,
                max_retries=settings.crt_sh_max_retries,
            )
        )
    return providers


async def _dns_brute_force(domain: str) -> list[str]:
    """Active DNS brute-force: resolve candidate names against the target.

    Bounded wordlist and concurrency -- this is active discovery, not
    passive enumeration.  Every resolved IP passes the full SSRF guard
    before being stored or scanned (see resolve_subdomain_ips).
    """
    semaphore = asyncio.Semaphore(DNS_BRUTE_CONCURRENCY)

    async def resolve_one(prefix: str) -> Optional[str]:
        async with semaphore:
            fqdn = f"{prefix}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                return fqdn
            except Exception:
                return None

    tasks = [resolve_one(prefix) for prefix in DNS_BRUTE_WORDLIST]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


async def resolve_subdomain_ips(subdomain: str) -> list[str]:
    """Resolve a subdomain's IPs, keeping only globally-routable addresses."""
    from utils.ssrf_guard import is_globally_routable_ip

    try:
        loop = asyncio.get_event_loop()
        addrs = await loop.run_in_executor(None, socket.getaddrinfo, subdomain, None)
        ips = set()
        for addr in addrs:
            ip = addr[4][0]
            # Full guard (not just fe80/127 prefixes): blocked IPs are
            # discarded before they are stored or scanned.
            if is_globally_routable_ip(ip):
                ips.add(ip)
            else:
                logger.debug("Discarding non-routable IP %s for %s", ip, subdomain)
        return list(ips)
    except Exception as exc:
        logger.warning("Failed to resolve IPs for %s: %s", subdomain, exc)
        return []


class DiscoveredHostView:
    """In-memory view of one discovered subdomain from the coordinator."""

    def __init__(
        self,
        host: str,
        source: str,
        first_seen: datetime,
        last_seen: datetime,
    ) -> None:
        self.host = host
        self.source = source
        self.first_seen = first_seen
        self.last_seen = last_seen
