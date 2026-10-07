"""Domain resolution with SSRF pin fallback.

The primary pipeline resolves DNS once and pins the IP in Redis via
``app.core.ssrf.pin_ip``.  This module provides a fallback that checks
the pin first before doing a fresh lookup, validated fail-closed.
"""

from utils.egress import resolve_validated_ips
from utils.logger import logger


async def resolve_domain(domain: str):
    # Try the pinned IP first (set by the scan submission path).
    try:
        from app.core.ssrf import pinned_resolve
        ip = pinned_resolve(domain)
        return {"domain": domain, "ip": ip, "pinned": True}
    except Exception:
        pass

    # Fallback to fresh DNS resolution. Blocked or unresolvable targets
    # yield no IP (callers fail the scan loudly instead of probing).
    try:
        ips = resolve_validated_ips(domain)
        return {"domain": domain, "ip": ips[0], "pinned": False}
    except Exception as exc:
        logger.warning("DNS resolution failed for %s: %s", domain, exc)
        return {"domain": domain, "ip": None, "pinned": False}
