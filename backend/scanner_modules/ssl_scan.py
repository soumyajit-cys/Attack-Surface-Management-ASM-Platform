"""SSL/TLS scanner module (registry phase ``ssl``)."""

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module

from services.scanner.ssl_risk import assess_ssl_risk
from services.scanner.ssl_scanner import analyze_ssl


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