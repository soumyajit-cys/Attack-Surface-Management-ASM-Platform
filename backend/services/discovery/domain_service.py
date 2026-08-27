"""Domain resolution with SSRF pin fallback.

The primary pipeline resolves DNS once and pins the IP in Redis via
``app.core.ssrf.pin_ip``.  This module provides a fallback that checks
the pin first before doing a fresh lookup.
"""

import socket

from utils.logger import logger


async def resolve_domain(domain: str):
    # Try the pinned IP first (set by the scan submission path).
    try:
        from app.core.ssrf import pinned_resolve
        ip = pinned_resolve(domain)
        return {"domain": domain, "ip": ip, "pinned": True}
    except Exception:
        pass

    # Fallback to fresh DNS resolution.
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip, "pinned": False}
    except Exception as exc:
        logger.warning("DNS resolution failed for %s: %s", domain, exc)
        return {"domain": domain, "ip": None, "pinned": False}
