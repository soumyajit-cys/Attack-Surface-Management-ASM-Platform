"""Plugin scanner modules wrapping the legacy ``services/scanner`` services.

Each module registers with the :class:`app.scanning.registry.ScannerRegistry`
via ``@scanner_module`` and consumes an immutable :class:`ScanContext`.
Modules only *collect* data; persistence stays in the pipeline so the registry
stays side-effect free and testable.
"""

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module

from services.scanner.header_scanner import analyze_headers
from services.scanner.port_scanner import scan_ports
from services.scanner.ssl_risk import assess_ssl_risk
from services.scanner.ssl_scanner import analyze_ssl


@scanner_module("port_scan", phase="port", order=1)
async def port_scan_module(ctx: ScanContext) -> dict:
    """Port scan the pinned IP (SSRF-safe: never DNS-resolves internally)."""
    ports = await scan_ports(ctx.pinned_ip)
    return {
        "host": ctx.domain,
        "ports": ports,
        "ports_total": len(ports),
        "ports_open": [p for p in ports if p.get("status") == "open"],
    }


@scanner_module("ssl_scan", phase="ssl", order=2)
async def ssl_scan_module(ctx: ScanContext) -> dict:
    """SSL/TLS assessment against the pinned IP."""
    ssl_data = await analyze_ssl(ctx.pinned_ip)
    assessment = assess_ssl_risk(ssl_data)
    return {
        "host": ctx.domain,
        "ssl": ssl_data,
        "risk_level": assessment["risk_level"],
        "findings": assessment.get("findings", []),
    }


@scanner_module("header_scan", phase="header", order=3)
async def header_scan_module(ctx: ScanContext) -> dict:
    """HTTP security-header analysis against the pinned IP."""
    issues = await analyze_headers(f"https://{ctx.domain}")
    return {
        "host": ctx.domain,
        "issues": issues,
        "issue_count": len(issues),
    }