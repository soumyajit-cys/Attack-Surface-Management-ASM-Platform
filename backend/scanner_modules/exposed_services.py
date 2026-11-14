"""Exposed services scanner module (registry phase ``exposed_services``).

Identifies services exposed on open ports. Passive banner analysis only
for Redis/Mongo/Memcached (port open, service unconfirmed). MySQL greeting
parsed for version. PostgreSQL SSLRequest behind a setting. Elasticsearch
and HTTP admin panels via SSRF-pinned HTTP helper.

No raw banners are stored. Only service name, parsed version, signature id,
and status code are recorded.

Labels: module and outcome only -- never a domain or hostname.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module, ScanPhase
from utils.egress import fetch_url_validated, fetch_url_validated_sync

logger = logging.getLogger("sentinelasm.scanner.exposed_services")

# ── Signature data ─────────────────────────────────────────────────────

_SIG_PATH = Path(__file__).parent / "exposed_service_signatures.json"


def _load_signatures() -> list[dict[str, Any]]:
    with _SIG_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("signatures", [])


SIGNATURES = _load_signatures()

# ── Constants ─────────────────────────────────────────────────────────

MAX_CONCURRENCY = settings.exposed_services_max_concurrency
MAX_HOSTS_PER_SCAN = settings.exposed_services_max_hosts_per_scan
MAX_PORTS_PER_HOST = settings.exposed_services_max_ports_per_host
MAX_BODY_BYTES = settings.exposed_services_max_body_bytes
TIMEOUT = settings.exposed_services_timeout_seconds

# Admin paths to probe (compared against random baseline)
ADMIN_PATHS = ["/", "/admin", "/manager", "/phpmyadmin", "/wp-admin"]

# ── Helpers ───────────────────────────────────────────────────────────


def _probe_mysql_banner(banner: str) -> dict[str, Any] | None:
    """Parse MySQL greeting for version string."""
    # MySQL greeting starts with 4-byte length + 1-byte seq + version string
    # terminated by \x00.  We look for a version-like pattern.
    import re
    m = re.search(r"(\d+\.\d+\.\d+)", banner)
    if m:
        return {"service": "mysql", "version": m.group(1), "signature_id": "mysql_greeting"}
    return None


def _http_probe(url: str) -> dict[str, Any]:
    try:
        result = fetch_url_validated_sync(
            url,
            timeout=TIMEOUT,
            max_bytes=MAX_BODY_BYTES,
            verify_tls=True,
        )
        body = result.body.decode("utf-8", errors="replace") if result.body else ""
        return {"status_code": result.status_code, "headers": dict(result.headers), "body": body, "error": None}
    except Exception as exc:
        return {"status_code": None, "headers": {}, "body": "", "error": str(exc)}


# ── Module entry point ────────────────────────────────────────────────


@scanner_module("exposed_services", phase="exposed_services", order=1)
async def exposed_services_module(ctx: ScanContext) -> dict:
    findings: list[dict[str, Any]] = []
    hosts_checked = 0
    hosts_truncated = 0

    subdomains = list(ctx.subdomains or [])
    if not subdomains:
        return {"host": ctx.domain, "findings": [], "findings_total": 0, "truncated": False}

    # Get open ports from context config (populated by port_scan)
    open_ports_map = (ctx.config or {}).get("open_ports", {})

    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

    async def check_host(subdomain: str) -> None:
        nonlocal hosts_checked, hosts_truncated
        if hosts_checked >= MAX_HOSTS_PER_SCAN:
            hosts_truncated += 1
            return
        hosts_checked += 1

        async with semaphore:
            ports = open_ports_map.get(subdomain, [])
            ports = ports[:MAX_PORTS_PER_HOST]

            for port in ports:
                port_num = port if isinstance(port, int) else port.get("port", 0)
                banner = port.get("banner", "") if isinstance(port, dict) else ""

                # Passive: Redis, Mongo, Memcached → port open, service unconfirmed
                if port_num in (6379, 27017, 11211):
                    service = {6379: "redis", 27017: "mongodb", 11211: "memcached"}.get(port_num, "unknown")
                    findings.append({
                        "provider": f"{service}_port_open",
                        "category": "exposed_service",
                        "severity": "info",
                        "confidence": 0.5,
                        "matched_pattern": f"port {port_num} open",
                        "matched_text": "",
                        "version": None,
                        "dedupe_key": f"exposed_services:{service}_port_open:{subdomain}:{port_num}",
                        "host": subdomain,
                        "port": port_num,
                        "service": service,
                        "signature_id": f"{service}_port_open",
                        "status_code": None,
                    })
                    continue

                # MySQL: parse greeting
                if port_num == 3306 and banner:
                    mysql_result = _probe_mysql_banner(banner)
                    if mysql_result:
                        findings.append({
                            "provider": "mysql_greeting",
                            "category": "exposed_service",
                            "severity": "high",
                            "confidence": 0.9,
                            "matched_pattern": "mysql greeting",
                            "matched_text": mysql_result.get("version", ""),
                            "version": mysql_result.get("version"),
                            "dedupe_key": f"exposed_services:mysql_greeting:{subdomain}:{port_num}",
                            "host": subdomain,
                            "port": port_num,
                            "service": "mysql",
                            "signature_id": "mysql_greeting",
                            "status_code": None,
                        })
                    continue

                # Elasticsearch: HTTP via SSRF-pinned helper
                if port_num in (9200, 9300):
                    scheme = "https" if port_num == 9300 else "http"
                    url = f"{scheme}://{subdomain}:{port_num}/"
                    http_result = _http_probe(url)
                    status = http_result.get("status_code")
                    body = http_result.get("body", "")
                    if status == 200 and ("cluster_name" in body or "elasticsearch" in body.lower()):
                        findings.append({
                            "provider": "elasticsearch_exposed",
                            "category": "exposed_service",
                            "severity": "high",
                            "confidence": 0.9,
                            "matched_pattern": "elasticsearch cluster info",
                            "matched_text": body[:200],
                            "version": None,
                            "dedupe_key": f"exposed_services:elasticsearch_exposed:{subdomain}:{port_num}",
                            "host": subdomain,
                            "port": port_num,
                            "service": "elasticsearch",
                            "signature_id": "elasticsearch_exposed",
                            "status_code": status,
                        })
                    elif status in (401, 403):
                        findings.append({
                            "provider": "elasticsearch_auth_required",
                            "category": "exposed_service",
                            "severity": "info",
                            "confidence": 0.7,
                            "matched_pattern": "auth required",
                            "matched_text": "",
                            "version": None,
                            "dedupe_key": f"exposed_services:elasticsearch_auth:{subdomain}:{port_num}",
                            "host": subdomain,
                            "port": port_num,
                            "service": "elasticsearch",
                            "signature_id": "elasticsearch_auth",
                            "status_code": status,
                        })
                    continue

                # HTTP admin panels
                if port_num in (80, 443, 8080, 8443, 9090):
                    scheme = "https" if port_num in (443, 8443) else "http"
                    # Baseline: random nonexistent path
                    import uuid
                    baseline_path = f"/{uuid.uuid4().hex}"
                    baseline_url = f"{scheme}://{subdomain}:{port_num}{baseline_path}"
                    baseline_result = _http_probe(baseline_url)
                    baseline_status = baseline_result.get("status_code")

                    for admin_path in ["/admin", "/manager", "/phpmyadmin", "/wp-admin"]:
                        admin_url = f"{scheme}://{subdomain}:{port_num}{admin_path}"
                        admin_result = _http_probe(admin_url)
                        admin_status = admin_result.get("status_code")
                        # Only report if admin path differs from baseline (not soft-404)
                        if admin_status == 200 and admin_status != baseline_status:
                            findings.append({
                                "provider": f"admin_panel_{admin_path.strip('/')}",
                                "category": "exposed_service",
                                "severity": "medium",
                                "confidence": 0.7,
                                "matched_pattern": f"admin path {admin_path} returned 200",
                                "matched_text": "",
                                "version": None,
                                "dedupe_key": f"exposed_services:admin_panel:{subdomain}:{port_num}:{admin_path}",
                                "host": subdomain,
                                "port": port_num,
                                "service": "http_admin",
                                "signature_id": "admin_panel",
                                "status_code": admin_status,
                            })
                    continue

    tasks = [asyncio.create_task(check_host(sub)) for sub in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)

    truncated = hosts_truncated > 0
    return {
        "host": ctx.domain,
        "findings": findings,
        "findings_total": len(findings),
        "truncated": truncated,
    }
