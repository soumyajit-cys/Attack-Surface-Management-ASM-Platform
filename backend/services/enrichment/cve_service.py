"""CVE enrichment: match banner-grabbed software versions against OSV.dev.

Pipeline:
1. :func:`extract_software` parses a port banner (plus the port-service hint)
   into a ``(product, version)`` pair for known server software.
2. :func:`query_osv` POSTs ``{package, version}`` to the OSV.dev API and
   returns matched vulnerabilities with CVE IDs + CVSS base scores.
3. Callers persist one ``vulnerability`` finding per CVE and feed the CVSS
   score into :func:`services.scoring.risk_engine.calculate_risk`.

Outbound-request safety (same posture as the rest of the codebase):
- The feed hostname comes from validated app config (not user input) and is
  *additionally* resolved + checked against the SSRF guard
  (:mod:`utils.ssrf_guard`) before every request, so a poisoned resolver
  pointing ``api.osv.dev`` at a private/metadata IP fails closed.
- Only ``https://`` feed URLs are allowed; requests carry a short timeout.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

import requests

from utils.logger import logger
from utils.ssrf_guard import is_allowed_target

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

OSV_QUERY_PATH = "/v1/query"


def _settings():
    from app.core.config import settings

    return settings


def feed_url() -> str:
    """Configured OSV.dev query URL (``OSV_API_URL`` env override supported)."""
    base = (_settings().osv_api_url or "https://api.osv.dev/v1/query").rstrip("/")
    if base.endswith("/v1/query"):
        return base
    if base.endswith("/v1"):
        return base + "/query"
    return base + OSV_QUERY_PATH


def assert_feed_host_safe(url: str) -> str:
    """Resolve the feed hostname and fail closed if it maps to a blocked IP.

    Returns the resolved IP. Raises ``ValueError`` for non-HTTPS URLs,
    unresolvable hosts, or private/link-local/cloud-metadata targets.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"OSV feed URL must use https: {url!r}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"OSV feed URL has no hostname: {url!r}")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"OSV feed host {host!r} does not resolve: {exc}") from exc
    if not is_allowed_target(ip):
        raise ValueError(f"OSV feed host {host!r} resolved to blocked IP {ip!r}")
    return ip


# ── Banner → software parsing ─────────────────────────────────────────────

# product -> (banner regexes tried in order, OSV package candidates).
# Package candidates are (ecosystem, package-name) pairs queried in order;
# results are merged and deduped by CVE ID.
PRODUCT_MAP: dict[str, dict] = {
    "nginx": {
        "patterns": [re.compile(r"nginx/(\d+\.\d+\.\d+)", re.IGNORECASE)],
        "packages": [("Alpine", "nginx"), ("Debian", "nginx"), ("Ubuntu", "nginx")],
    },
    "apache": {
        "patterns": [re.compile(r"apache/(\d+\.\d+\.\d+)", re.IGNORECASE)],
        "packages": [("Alpine", "apache2"), ("Debian", "apache2"), ("Ubuntu", "apache2")],
    },
    "openssh": {
        "patterns": [re.compile(r"openssh[_/](\d+\.\d+(?:p\d+)?)", re.IGNORECASE)],
        "packages": [("Alpine", "openssh"), ("Debian", "openssh"), ("Ubuntu", "openssh")],
    },
    "vsftpd": {
        "patterns": [re.compile(r"vsftpd\s+(\d+\.\d+\.\d+)", re.IGNORECASE)],
        "packages": [("Debian", "vsftpd"), ("Ubuntu", "vsftpd"), ("Alpine", "vsftpd")],
    },
    "exim": {
        "patterns": [re.compile(r"exim\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "packages": [("Debian", "exim4"), ("Ubuntu", "exim4")],
    },
    "mysql": {
        "patterns": [
            re.compile(r"(\d+\.\d+\.\d+)[\w\-.]*\s*(?:mysql|mariadb)", re.IGNORECASE),
            re.compile(r"mysql[\w\-.]*\s*(\d+\.\d+\.\d+)", re.IGNORECASE),
        ],
        "packages": [("Debian", "mysql"), ("Ubuntu", "mysql")],
    },
    "postgresql": {
        "patterns": [re.compile(r"postgresql\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)],
        "packages": [("Debian", "postgresql"), ("Ubuntu", "postgresql")],
    },
    "redis": {
        "patterns": [re.compile(r"redis_version:(\d+\.\d+\.\d+)", re.IGNORECASE)],
        "packages": [("Alpine", "redis"), ("Debian", "redis")],
    },
}


def extract_software(banner: str | None, service: str | None = None) -> dict | None:
    """Parse ``(product, version)`` from a banner grabbed during port scanning.

    Returns ``{"product", "version", "packages"}`` or ``None`` when no known
    software with a queryable version is found. OSV requires an exact
    version, so banners without one (e.g. bare ``Postfix`` greetings) yield
    ``None`` rather than a guess.
    """
    if not banner:
        return None
    text = banner.strip()
    if not text:
        return None
    for product, spec in PRODUCT_MAP.items():
        for pattern in spec["patterns"]:
            match = pattern.search(text)
            if match:
                return {
                    "product": product,
                    "version": match.group(1),
                    "packages": spec["packages"],
                }
    return None


# ── OSV.dev querying ──────────────────────────────────────────────────────

def query_osv(package_name: str, ecosystem: str, version: str) -> list[dict]:
    """Query OSV.dev for vulns affecting ``package_name@version``.

    Raises ``ValueError`` if the feed host fails the SSRF check; transient
    network errors propagate as ``requests.RequestException`` so Celery can
    retry with backoff.
    """
    url = feed_url()
    assert_feed_host_safe(url)
    timeout = float(_settings().osv_timeout_seconds or 10.0)
    resp = requests.post(
        url,
        json={"package": {"name": package_name, "ecosystem": ecosystem}, "version": version},
        timeout=timeout,
    )
    resp.raise_for_status()
    return parse_osv_response(resp.json())


def parse_osv_response(data: dict) -> list[dict]:
    """Extract ``[{cve_id, cvss, severity, summary}]`` from an OSV response."""
    results: list[dict] = []
    for vuln in data.get("vulns", []) or []:
        cve_ids: list[str] = []
        seen: set[str] = set()

        own_id = str(vuln.get("id", "")).upper()
        if CVE_RE.fullmatch(own_id):
            cve_ids.append(own_id)
            seen.add(own_id)
        for alias in vuln.get("aliases", []) or []:
            alias_up = str(alias).upper()
            if CVE_RE.fullmatch(alias_up) and alias_up not in seen:
                cve_ids.append(alias_up)
                seen.add(alias_up)

        if not cve_ids:
            continue

        cvss = _max_cvss(vuln.get("severity", []) or [])
        severity = cvss_to_severity(cvss) if cvss is not None else "medium"
        for cve_id in cve_ids:
            results.append({
                "cve_id": cve_id,
                "cvss": cvss,
                "severity": severity,
                "summary": vuln.get("summary") or vuln.get("details", "")[:500],
            })
    return results


def _max_cvss(severities: list[dict]) -> float | None:
    best: float | None = None
    for entry in severities:
        if not str(entry.get("type", "")).upper().startswith("CVSS"):
            continue
        score = cvss_v31_base_score(str(entry.get("score", "")))
        if score is not None and (best is None or score > best):
            best = score
    return best


def enrich_service_banner(service: str | None, banner: str | None) -> list[dict]:
    """Match one banner against OSV.dev; returns CVE dicts sorted by CVSS desc.

    Fail-soft: unparseable banners return ``[]`` without any network call.
    Network/SSRF errors propagate to the caller (the Celery task retries
    transient ones and fails closed on SSRF violations).
    """
    found = extract_software(banner, service)
    if not found:
        return []
    merged: dict[str, dict] = {}
    for ecosystem, package_name in found["packages"]:
        for vuln in query_osv(package_name, ecosystem, found["version"]):
            vuln = {**vuln, "product": found["product"], "version": found["version"]}
            existing = merged.get(vuln["cve_id"])
            if existing is None or (vuln["cvss"] or 0) > (existing["cvss"] or 0):
                merged[vuln["cve_id"]] = vuln
    return sorted(merged.values(), key=lambda v: (v["cvss"] is not None, v["cvss"] or 0), reverse=True)


# ── CVSS → severity ───────────────────────────────────────────────────────

def cvss_to_severity(cvss: float) -> str:
    """Map a CVSS v3 base score to a SentinelASM severity label."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


# ── CVSS v3.1 base-score calculator ────────────────────────────────────────
# Implements the CVSS v3.1 specification (FIRST.org) so OSV vector strings
# (e.g. "CVSS:3.1/AV:N/AC:L/...") yield numeric base scores without extra deps.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS spec Roundup: smallest 1-decimal number >= value.

    Mirrors the FIRST.org reference implementation (round to 5 decimals
    first so float noise like 4.1000000001 still yields 4.1, not 4.2).
    """
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (scaled // 10000 + 1) / 10


def cvss_v31_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.0/v3.1 base score for a vector string.

    Returns ``None`` when the vector is missing or malformed.
    """
    try:
        parts = str(vector).strip().split("/")
        if len(parts) < 2 or not parts[0].startswith("CVSS:3."):
            return None
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            if ":" not in part:
                return None
            key, val = part.split(":", 1)
            metrics[key] = val
        if metrics.get("S") not in ("U", "C"):
            return None
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = pr_table[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except (KeyError, AttributeError, TypeError):
        return None

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    exploit = 8.22 * av * ac * pr * ui

    if not scope_changed:
        impact = 6.42 * isc_base
        if impact <= 0:
            return 0.0
        return _roundup(min(impact + exploit, 10.0))

    impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.029) ** 15)
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10.0))
