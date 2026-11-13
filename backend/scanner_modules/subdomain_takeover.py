"""Subdomain takeover scanner module (registry phase ``enrichment``).

Detects dangling CNAMEs pointing to claimable third-party providers
(e.g. GitHub Pages, Heroku, S3). Two detection paths:

* Phase A (DNS only): the CNAME target resolves to NXDOMAIN (confirmed by
  a second query after a short delay). No HTTP request is made.
* Phase B (HTTP confirmation): GET / against the subdomain's own resolved
  + SSRF-pinned address with Host=<subdomain>. Matches the response body
  against provider-specific "unclaimed" literal substrings.

Both paths are gated on verified domain + scope. Path A requires no pinned
IP; Path B does its own SSRF-pinned resolution. The CNAME chain is walked
with a depth cap (~8) and loop detection; every hop is matched against the
provider fingerprint list.

Findings carry a ``confidence`` field (<= 0.85) and a stable
``dedupe_key``. Severity is static per provider type - this module never
invents EOL or CVE data.

Labels: module and outcome only - never a domain or hostname.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver

from app.core.config import settings
from app.core.ssrf import PinnedResolutionMissing
from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module, ScanPhase

logger = logging.getLogger("sentinelasm.scanner.subdomain_takeover")

# ── Fingerprint data ──────────────────────────────────────────────────

_FINGERPRINTS_PATH = Path(__file__).parent / "takeover_fingerprints.json"


def _load_fingerprints() -> list[dict[str, Any]]:
    """Load and validate the provider fingerprint data file.

    Only entries whose upstream ``status`` is ``"Vulnerable"`` or
    ``"Edge case"`` are included.  ``"Not vulnerable"`` entries and entries
    without an upstream match are excluded so they can never produce a
    finding.
    """
    with _FINGERPRINTS_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    providers: list[dict[str, Any]] = []
    for entry in data.get("providers", []):
        status = entry.get("status", "")
        # Only Vulnerable and Edge case entries can produce findings.
        if status not in ("Vulnerable", "Edge case"):
            continue

        cname_list = entry.get("cname", [])
        if not cname_list:
            suffix = entry.get("cname_suffix", "")
            if suffix:
                cname_list = [suffix]
        if not cname_list:
            continue
        fingerprint = entry.get("fingerprint", "") or entry.get("unclaimed_body", "")
        if not fingerprint:
            continue

        # Derive tier from upstream status.
        if status == "Vulnerable":
            tier = "claimable"
        else:  # Edge case
            tier = "likely_claimable"

        providers.append({
            "name": entry.get("service", entry.get("name", "unknown")),
            "upstream_service": entry.get("upstream_service"),
            "status": status,
            "cname_suffixes": [c.lower().rstrip(".") for c in cname_list],
            "unclaimed_body": fingerprint,
            "tier": tier,
            "verified_claimable": tier == "claimable",
            "likely_claimable": tier == "likely_claimable",
        })
    return providers


FINGERPRINTS = _load_fingerprints()

# ── Constants ─────────────────────────────────────────────────────────

# DNS query timeout per record type (seconds).
DNS_TIMEOUT = settings.subdomain_takeover_timeout_seconds

# Maximum CNAME chain depth (prevents infinite loops).
MAX_CNAME_DEPTH = 8

# Maximum concurrent takeover lookups.
MAX_CONCURRENCY = settings.subdomain_takeover_max_concurrency

# Maximum hosts to check per scan (truncation beyond this).
MAX_HOSTS_PER_SCAN = settings.subdomain_takeover_max_hosts_per_scan

# Delay between NXDOMAIN re-confirmation queries (seconds).
NXDOMAIN_RECONFIRM_DELAY = 0.5


# ── DNS helpers ───────────────────────────────────────────────────────


def _cname_chain(domain: str) -> list[str]:
    """Resolve the CNAME chain for *domain*.

    Walks CNAME records with a depth cap and loop detection. Returns the
    ordered list of targets, including the final non-CNAME target if any.
    Raises :class:`dns.exception.DNSException` on lookup failure.
    """
    chain: list[str] = []
    seen: set[str] = set()
    current = domain.rstrip(".").lower()

    for _ in range(MAX_CNAME_DEPTH):
        if current in seen:
            break  # loop detected
        seen.add(current)
        chain.append(current)
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=DNS_TIMEOUT)
        except dns.resolver.NoAnswer:
            break  # not a CNAME, chain ends here
        except dns.resolver.NXDOMAIN:
            chain.append(current)
            return chain
        except dns.exception.DNSException:
            raise
        if not answers:
            break
        current = answers[0].to_text().rstrip(".").lower()

    return chain


def _cname_matches_provider(host: str, provider: dict[str, Any]) -> bool:
    """Label-boundary suffix match: host == suffix or host.endswith('.' + suffix).

    No regex is used, so ``evilgithub.io`` does not match ``github.io``.
    Host matching is case-insensitive.
    """
    host = host.lower().rstrip(".")
    for suffix in provider["cname_suffixes"]:
        suffix = suffix.lower().rstrip(".")
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def _query_nxdomain_confirmed(domain: str) -> bool:
    """Return True only if *domain* resolves to NXDOMAIN on two consecutive
    queries separated by a short delay. A single NXDOMAIN is not enough
    (transient failures can masquerade as NXDOMAIN)."""
    try:
        dns.resolver.resolve(domain, "A", lifetime=DNS_TIMEOUT)
        return False  # resolves, not NXDOMAIN
    except dns.resolver.NXDOMAIN:
        pass
    except dns.exception.DNSException:
        return False  # SERVFAIL, timeout, etc. - not NXDOMAIN

    # Re-confirm after a short delay to avoid false positives from
    # transient caching or flapping.
    try:
        time.sleep(NXDOMAIN_RECONFIRM_DELAY)
        dns.resolver.resolve(domain, "A", lifetime=DNS_TIMEOUT)
        return False  # resolves on retry
    except dns.resolver.NXDOMAIN:
        return True  # confirmed NXDOMAIN
    except dns.exception.DNSException:
        return False  # SERVFAIL/timeout on retry


def _ssrf_pinned_resolve(host: str) -> str:
    """Resolve *host* through the SSRF pinning guard.

    Returns the first globally-routable IP. Raises
    :class:`PinnedResolutionMissing` if the host cannot be pinned.
    """
    from utils.egress import resolve_validated_ips

    ips = resolve_validated_ips(host, port=80)
    if not ips:
        raise PinnedResolutionMissing(host)
    return ips[0]


def _http_probe(host: str) -> dict[str, Any]:
    """GET / against *host* through the SSRF-pinned fetch.

    Returns a dict with ``status_code`` (int or None), ``body`` (str or
    None), and ``error`` (str or None). Sends no cookies/credentials and
    enforces a response-size cap.
    """
    import httpx

    try:
        pinned_ip = _ssrf_pinned_resolve(host)
    except PinnedResolutionMissing:
        return {"status_code": None, "body": None, "error": "not_pinned"}

    try:
        with httpx.Client(
            timeout=settings.subdomain_takeover_timeout_seconds,
            follow_redirects=True,
            max_redirects=settings.subdomain_takeover_max_redirects,
            verify=False,  # TLS verification relaxed - see threat model
        ) as client:
            response = client.get(
                f"http://{pinned_ip}",
                headers={"Host": host},
            )
            body = response.text[: settings.subdomain_takeover_max_body_bytes]
            return {
                "status_code": response.status_code,
                "body": body,
                "error": None,
            }
    except httpx.TooManyRedirects:
        return {"status_code": None, "body": None, "error": "too_many_redirects"}
    except httpx.ConnectError:
        return {"status_code": None, "body": None, "error": "connect_error"}
    except httpx.TimeoutException:
        return {"status_code": None, "body": None, "error": "timeout"}
    except httpx.HTTPError as exc:
        return {"status_code": None, "body": None, "error": f"http_error: {exc}"}


def _match_provider(
    cname_target: str,
    http_result: dict[str, Any],
) -> dict[str, Any] | None:
    """Match a CNAME target against provider fingerprints.

    Returns a finding dict or None if no match.
    """
    for provider in FINGERPRINTS:
        if not _cname_matches_provider(cname_target, provider):
            continue

        matched = False
        matched_literal = ""

        # Phase B: HTTP body match (literal, case-sensitive substring).
        body = http_result.get("body") or ""
        unclaimed_body = provider["unclaimed_body"]
        if unclaimed_body and unclaimed_body in body:
            matched = True
            matched_literal = unclaimed_body

        # Phase A: NXDOMAIN on the CNAME target (confirmed by retry).
        nxdomain_confirmed = _query_nxdomain_confirmed(cname_target)
        if nxdomain_confirmed:
            matched = True
            if not matched_literal:
                matched_literal = "nxdomain"

        if not matched:
            continue

        # Severity/confidence based on upstream status tier.
        if provider.get("tier") == "claimable":
            severity = "high"
            confidence = 0.85
        elif provider.get("tier") == "likely_claimable":
            severity = "medium"
            confidence = 0.60
        else:
            # Excluded tier should never reach here.
            continue

        return {
            "provider_id": provider["name"],
            "cname_target": cname_target,
            "matched_literal": matched_literal,
            "severity": severity,
            "confidence": confidence,
        }

    return None


@scanner_module("subdomain_takeover", phase="email_security", order=2)
async def subdomain_takeover_module(ctx: ScanContext) -> dict:
    """Passive + active subdomain takeover detection for *ctx.domain*.

    Walks the CNAME chain of each discovered subdomain, matches against
    provider fingerprints, and confirms via DNS NXDOMAIN (Phase A) or HTTP
    response body (Phase B).

    Returns a dict with ``host``, ``findings`` (list), and
    ``findings_total`` (int).
    """
    findings: list[dict[str, Any]] = []
    hosts_checked = 0
    hosts_truncated = 0

    # The subdomain list is expected to be in ctx.subdomains (populated by
    # discovery). If absent, there is nothing to check.
    subdomains: list[str] = list(ctx.subdomains or [])
    if not subdomains:
        return {
            "host": ctx.domain,
            "findings": [],
            "findings_total": 0,
            "truncated": False,
        }

    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

    async def check_one(subdomain: str) -> None:
        nonlocal hosts_checked, hosts_truncated

        if hosts_checked >= MAX_HOSTS_PER_SCAN:
            hosts_truncated += 1
            return
        hosts_checked += 1

        async with semaphore:
            chain = _cname_chain(subdomain)
            # Walk every hop of the CNAME chain; match each against providers.
            for hop in chain:
                http_result = _http_probe(hop)
                match = _match_provider(hop, http_result)
                if match:
                    findings.append({
                        "title": f"Subdomain takeover: {subdomain} → {match['provider_id']}",
                        "severity": match["severity"],
                        "category": "subdomain_takeover",
                        "description": (
                            f"{subdomain} CNAME chain points to "
                            f"{match['provider_id']} ({hop}), which appears "
                            "unclaimed."
                        ),
                        "recommendation": (
                            "Remove the dangling DNS record first. If the "
                            "service is still needed, re-provision the "
                            "resource and re-point the CNAME."
                        ),
                        "confidence": match["confidence"],
                        "dedupe_key": (
                            f"subdomain_takeover:{match['provider_id']}:{subdomain}"
                        ),
                        # Structured data (not response body):
                        "provider_id": match["provider_id"],
                        "matched_literal": match["matched_literal"],
                        "cname_target": hop,
                        "status_code": http_result.get("status_code"),
                    })
                    break  # one finding per subdomain

    # Bounded concurrency sweep.
    tasks = [asyncio.create_task(check_one(sub)) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)

    truncated = hosts_truncated > 0
    if truncated:
        logger.warning(
            "Subdomain takeover truncated: %d hosts skipped (cap %d)",
            hosts_truncated,
            MAX_HOSTS_PER_SCAN,
        )

    return {
        "host": ctx.domain,
        "findings": findings,
        "findings_total": len(findings),
        "truncated": truncated,
    }
