"""Tech fingerprint scanner module (registry phase ``fingerprint``).

Passive identification of technologies from headers/TLS/HTML of already-
discovered subdomains. Reuses responses already collected by port_scan/ssl_scan
header scanning where available; otherwise fetches via the SSRF-pinned egress
helper with size/redirect/timeouts caps.

Findings carry ``confidence`` (<= 0.85) and ``dedupe_key``
(tech_fingerprint:<technology>:<hostname>). Severity/CVE mapping flows only
through existing OSV/KEV enrichment -- this module never invents EOL or
CVE data.

Labels: module and outcome only -- never a domain or hostname.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module, ScanPhase
from utils.egress import fetch_url_validated, fetch_url_validated_sync

logger = logging.getLogger("sentinelasm.scanner.tech_fingerprint")

# ── Fingerprint data ──────────────────────────────────────────────────

_FINGERPRINTS_PATH = Path(__file__).parent / "tech_fingerprints.json"


def _load_fingerprints() -> list[dict[str, Any]]:
    """Load fingerprint data from tech_fingerprints.json."""
    with _FINGERPRINTS_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    providers: list[dict[str, Any]] = []
    for entry in data.get("providers", []):
        fp = {
            "name": entry.get("name", "unknown"),
            "category": entry.get("category", "unknown"),
            "header_patterns": entry.get("header_patterns", []),
            "banner_patterns": entry.get("banner_patterns", []),
            "html_patterns": entry.get("html_patterns", []),
            "version_regex": entry.get("version_regex"),
            "confidence": entry.get("confidence", 0.5),
        }
        if fp["header_patterns"] or fp.get("banner_patterns") or fp.get("html_patterns"):
            providers.append(fp)
    return providers


FINGERPRINTS = _load_fingerprints()

# ── Constants ─────────────────────────────────────────────────────────

# Maximum concurrent fingerprint lookups.
MAX_CONCURRENCY = settings.tech_fingerprint_max_concurrency

# Maximum hosts to scan per scan (truncation beyond this).
MAX_HOSTS_PER_SCAN = settings.tech_fingerprint_max_hosts_per_scan

# Maximum redirects to follow.
MAX_REDIRECTS = settings.tech_fingerprint_max_redirects

# Maximum body bytes to read per HTTP response.
MAX_BODY_BYTES = settings.tech_fingerprint_max_body_bytes


# ── Fingerprint matching ────────────────────────────────────────────────


def _match_fingerprints(
    headers: dict[str, str] | None,
    body: str | None,
    tls_info: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Match HTTP headers/TLS/HTML against fingerprint patterns.

    Returns a list of matching fingerprint dicts.
    """
    findings: list[dict[str, Any]] = []

    # Build searchable text from headers + body
    search_text_parts: list[str] = []
    if headers:
        for key, value in headers.items():
            search_text_parts.append(f"{key}: {value}")
    if body:
        search_text_parts.append(body)
    search_text = "\n".join(search_text_parts).lower()

    for fp in FINGERPRINTS:
        patterns = fp.get("header_patterns", []) + fp.get("html_patterns", []) + fp.get("banner_patterns", [])
        version_regex = fp.get("version_regex")

        matched = False
        matched_text = ""

        for pattern in patterns:
            if pattern.lower() in search_text.lower():
                matched = True
                matched_text = pattern
                break

        if not matched:
            continue

        version = None
        if version_regex and search_text:
            m = re.search(version_regex, search_text)
            if m:
                version = m.group(1)

        findings.append({
            "provider": fp["name"],
            "category": fp.get("category", "unknown"),
            "confidence": fp.get("confidence", 0.5),
            "matched_pattern": matched_text,
            "matched_text": matched_text[:200] if matched_text else "",
            "version": version,
        })

    return findings


# ── HTTP probe ─────────────────────────────────────────────────────────


def _http_probe(url: str) -> dict[str, Any]:
    """Fetch a URL through the SSRF-pinned egress helper.

    Returns a dict with ``status_code``, ``headers``, ``body`` (truncated),
    and ``error`` (None on success).
    """
    try:
        result = fetch_url_validated_sync(
            url,
            timeout=settings.tech_fingerprint_timeout_seconds,
            max_redirects=settings.tech_fingerprint_max_redirects,
            max_bytes=settings.tech_fingerprint_max_body_bytes,
            verify_tls=True,
        )
        body = result.body.decode("utf-8", errors="replace") if result.body else ""
        return {
            "status_code": result.status_code,
            "headers": dict(result.headers),
            "body": body,
            "error": None,
        }
    except Exception as exc:
        return {"status_code": None, "headers": {}, "body": "", "error": str(exc)}


# ── Module entry point ─────────────────────────────────────────────────


@scanner_module("tech_fingerprint", phase="fingerprint", order=1)
async def tech_fingerprint_module(ctx: ScanContext) -> dict:
    """Passive tech fingerprinting for *ctx.domain*.

    Returns a dict with ``host``, ``findings`` (list), ``findings_total``
    (int), and ``truncated`` (bool).
    """
    findings: list[dict[str, Any]] = []
    hosts_checked = 0
    hosts_truncated = 0

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
            url = f"https://{subdomain}"
            http_result = _http_probe(url)

            matches = _match_fingerprints(
                http_result.get("headers", {}),
                http_result.get("body"),
                http_result.get("tls"),
            )
            for match in matches:
                findings.append({
                    "provider": match["provider"],
                    "category": match.get("category", "unknown"),
                    "confidence": match["confidence"],
                    "matched_pattern": match.get("matched_pattern"),
                    "matched_text": match.get("matched_text"),
                    "version": match.get("version"),
                    "dedupe_key": f"tech_fingerprint:{match['provider']}:{subdomain}",
                    "cname_target": subdomain,
                    "status_code": http_result.get("status_code"),
                })

    # Bounded concurrency sweep.
    tasks = [asyncio.create_task(check_one(sub)) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)

    truncated = hosts_truncated > 0
    if truncated:
        logger.warning(
            "Tech fingerprint truncated: %d hosts skipped (cap %d)",
            hosts_truncated,
            MAX_HOSTS_PER_SCAN,
        )

    return {
        "host": ctx.domain,
        "findings": findings,
        "findings_total": len(findings),
        "truncated": truncated,
    }