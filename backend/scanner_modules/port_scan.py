"""Port-scan scanner module (registry phase ``port``)."""

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module

from services.scanner.port_scanner import scan_ports


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