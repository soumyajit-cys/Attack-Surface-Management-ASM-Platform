"""HTTP security-header scanner module (registry phase ``header``)."""

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module

from services.scanner.header_scanner import analyze_headers


@scanner_module("header_scan", phase="header", order=3)
async def header_scan_module(ctx: ScanContext) -> dict:
    """HTTP security-header analysis against the pinned IP."""
    issues = await analyze_headers(f"https://{ctx.domain}")
    return {
        "host": ctx.domain,
        "issues": issues,
        "issue_count": len(issues),
    }