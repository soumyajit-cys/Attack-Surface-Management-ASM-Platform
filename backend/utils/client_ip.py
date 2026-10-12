"""Single source for the client IP (Phase 1.5, task 1.5.2).

Used by the rate-limiter key, the audit log, and login lockout. ``TRUSTED_PROXIES``
holds comma-separated CIDRs (or bare IPs); default empty trusts nothing.
``X-Forwarded-For`` is honored ONLY when the immediate peer is trusted, and
even then the right-most *untrusted* hop wins (a trusted ingress appends the
peer it actually saw, so anything to its right is attacker-controlled only if
the peer itself is untrusted -- which is exactly when we ignore the header).
Unparsable entries/hops are ignored; with no usable header value the direct
peer is returned.
"""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger("sentinelasm")


def _parse_networks(raw: str | None) -> list:
    """Parse comma-separated CIDRs/bare IPs; drop invalid entries loudly."""
    networks = []
    for part in (raw or "").split(","):
        text = part.strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXIES entry: %r", text)
    return networks


def _trusted_proxies() -> list:
    from app.core.config import settings

    return _parse_networks(settings.trusted_proxies)


def _is_trusted(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def get_client_ip(request) -> str | None:
    """Best-effort client IP honoring proxy trust (see module docstring)."""
    peer = request.client.host if getattr(request, "client", None) else None
    if not peer:
        return None
    networks = _trusted_proxies()
    if not networks or not _is_trusted(peer, networks):
        return peer
    hops = []
    for part in (request.headers.get("x-forwarded-for") or "").split(","):
        text = part.strip()
        if not text:
            continue
        try:
            ipaddress.ip_address(text)
        except ValueError:
            continue
        hops.append(text)
    # Right-most untrusted hop; all-trusted chains resolve to the origin.
    for hop in reversed(hops):
        if not _is_trusted(hop, networks):
            return hop
    if hops:
        return hops[0]
    return peer
