"""Tech fingerprint scanner module (registry phase ``enrichment``).

Passive identification of technologies from headers/TLS/HTML of already-
discovered subdomains. Does NOT make its own outbound connections --
reuses responses already collected by port_scan/ssl_scan header scanning.
Only new outbound connections (if a fingerprint requires fetching a page
not already collected) go through the SSRF-pinned egress helper with
size/redirect/timeouts caps.

Findings carry ``confidence`` (<= 0.85) and ``dedupe_key``
(tech_fingerprint:<technology>:<hostname>). Severity/CVE mapping flows
only through existing OSV/KEV enrichment -- this module never invents
EOL or CVE data.

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
from utils.egress import fetch_url_validated

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
            "provider_type": entry.get("provider_type", ""),
            "header_patterns": entry.get("header_patterns", []),
            "tls_patterns": entry.get("tls_patterns", []),
            "html_patterns": entry.get("html_patterns", []),
            "version_regex": entry.get("version_regex"),
            "confidence": entry.get("confidence", 0.5),
        }
        if fp["provider_type"] and (fp["header_patterns"] or fp.get("tls_patterns") or fp.get("html_patterns")):
            providers.append(fp)
    return providers


FINGERPRINTS = _load_fingerprints()

# ── Constants ─────────────────────────────────────────────────────────

# DNS/HTTP timeout per request (seconds).
DNS_TIMEOUT = settings.tech_fingerprint_timeout_seconds

# Maximum concurrent fingerprint lookups.
MAX_CONCURRENCY = settings.tech_fingerprint_max_concurrency

# Maximum hosts to scan per scan (truncation beyond this).
MAX_HOSTS_PER_SCAN = settings.tech_fingerprint_max_hosts_per_scan

# Maximum redirects to follow.
MAX_REDIRECTS = settings.tech_fingerprint_max_redirects

# Maximum body bytes to read per HTTP response.
MAX_BODY_BYTES = settings.tech_fingerprint_max_body_bytes

# ── DNS helpers ───────────────────────────────────────────────────────


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
        provider = fp["name"]
        patterns = fp.get("header_patterns", []) + fp.get("html_patterns", [])
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

        confidence = fp.get("confidence", 0.5)
        version = None
        if version_regex and search_text:
            m = re.search(version_regex, search_text)
            if m:
                version = m.group(1)

        findings.append({
            "provider": fp["name"],
            "provider_type": fp.get("provider_type", ""),
            "confidence": fp.get("confidence", 0.5),
            "matched_pattern": pattern,
            "matched_text": matched_text[:200] if matched_text else "",
            "version": version,
        })

    return findings
