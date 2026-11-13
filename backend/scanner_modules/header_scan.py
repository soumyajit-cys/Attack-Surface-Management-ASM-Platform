"""HTTP security-header scanner module (registry phase ``header``)."""

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module

from services.scanner.header_scanner import analyze_headers


# Headers safe to expose to downstream modules (no secrets).
_SAFE_HEADERS = frozenset({
    "server", "x-powered-by", "x-generator", "content-type",
})


def _sanitize_response(raw: dict | None) -> dict | None:
    """Strip sensitive headers and cap body size.

    Only an allowlist of non-sensitive headers is retained; Set-Cookie,
    Authorization, and all other headers are dropped.  The body is
    truncated to the configured cap.
    """
    if not raw:
        return None
    headers = {
        k: v for k, v in (raw.get("headers") or {}).items()
        if k.lower() in _SAFE_HEADERS
    }
    body = (raw.get("body") or "")[:65536]
    return {
        "status_code": raw.get("status_code"),
        "headers": headers,
        "body": body,
    }


@scanner_module("header_scan", phase="header", order=3)
async def header_scan_module(ctx: ScanContext) -> dict:
    """HTTP security-header analysis against the pinned IP."""
    issues, http_response = await analyze_headers(
        f"https://{ctx.domain}", capture_response=True
    )
    sanitized = _sanitize_response(http_response)
    return {
        "host": ctx.domain,
        "issues": issues,
        "issue_count": len(issues),
        "http_response": sanitized,
    }