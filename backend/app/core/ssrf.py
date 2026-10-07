"""DNS-resolve-and-pin: SSRF protection that spans the full scan lifecycle.

At scan submission the domain is resolved once and the IP is stored in Redis
with a short TTL. Every subsequent connection (port scan, SSL, HTTP headers)
calls ``pinned_resolve()`` which returns the pinned IP instead of doing a fresh
DNS lookup.  This closes the DNS-rebinding window that existed when each
scanner resolved independently.
"""

from __future__ import annotations

import socket
from typing import Optional

from utils.logger import logger
from utils.redis_client import get_redis
from utils.ssrf_guard import is_globally_routable_ip

_PIN_TTL_SECONDS = 600  # 10 minutes
_PIN_PREFIX = "ssrf:pin:"


class PinnedResolutionMissing(Exception):
    """Raised when a pinned IP is not found in Redis.

    This means either:
    - The pin expired (>10 min since submission), or
    - The scan was never submitted through the validated path.
    """

    def __init__(self, host: str) -> None:
        super().__init__(
            f"No pinned IP for {host!r}. Either the pin expired or the "
            "scan was not submitted through the validated path."
        )
        self.host = host


class PinnedIPMismatch(Exception):
    """Raised when a re-resolved IP differs from the pinned IP.

    This is the DNS-rebinding detection signal.
    """

    def __init__(self, host: str, pinned: str, actual: str) -> None:
        super().__init__(
            f"DNS rebind detected for {host!r}: pinned={pinned!r} actual={actual!r}"
        )
        self.host = host
        self.pinned = pinned
        self.actual = actual


def _pin_key(host: str) -> str:
    return f"{_PIN_PREFIX}{host}"


def pin_ip(host: str, ip: str) -> None:
    """Store the resolved IP for *host* in Redis with a short TTL.

    Called once at scan submission time after SSRF validation passes.
    """
    r = get_redis()
    r.set(_pin_key(host), ip, ex=_PIN_TTL_SECONDS)
    logger.debug("Pinned %s -> %s (TTL %ds)", host, ip, _PIN_TTL_SECONDS)


def pinned_resolve(host: str) -> str:
    """Return the pinned IP for *host*, or raise ``PinnedResolutionMissing``.

    Every scanner module must call this instead of ``socket.gethostbyname``.
    """
    r = get_redis()
    ip = r.get(_pin_key(host))
    if ip is None:
        raise PinnedResolutionMissing(host)
    return ip


def clear_pin(host: str) -> None:
    """Remove a pin (used in tests and on scan failure cleanup)."""
    get_redis().delete(_pin_key(host))


def is_valid_pin(host: str) -> bool:
    """Return True if a pin exists for *host*."""
    return get_redis().exists(_pin_key(host)) == 1


def validate_and_pin(domain: str) -> str:
    """Resolve *domain*, validate the IP is safe, and pin it.

    Validation uses the single shared validator
    (:func:`utils.ssrf_guard.is_globally_routable_ip`). Returns the pinned
    IP on success. Raises ``ValueError`` if the IP is not globally routable
    or resolution fails.
    """
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {domain!r}: {exc}") from exc

    if not is_globally_routable_ip(ip):
        raise ValueError(f"IP is not globally routable: {ip!r}")
    pin_ip(domain, ip)
    return ip


def assert_pin_consistent(host: str) -> str:
    """Re-resolve *host* and verify it matches the pinned IP.

    Returns the pinned IP if consistent.
    Raises ``PinnedIPMismatch`` if DNS has changed (rebinding detected).
    Raises ``PinnedResolutionMissing`` if no pin exists.
    """
    pinned = pinned_resolve(host)

    try:
        actual = socket.gethostbyname(host)
    except socket.gaierror:
        # DNS resolution failed -- this is fine, the original pin is still valid.
        return pinned

    if actual != pinned:
        raise PinnedIPMismatch(host, pinned, actual)

    return pinned
