"""Single egress helper for all outbound scanner connections (Phase 1, task 1.3).

Every connection to a scanned target goes through here:

- :func:`resolve_validated_ips` resolves once with ``getaddrinfo`` and
  validates **every** returned IP with :func:`is_globally_routable_ip`
  (fail-closed on any blocked address, on empty results, and on DNS errors).
- :func:`open_tcp_validated` connects to a validated IP. TLS callers pass
  their own verified context plus ``server_hostname`` so SNI and certificate
  hostname verification pin to the original name, not the IP.
- :func:`fetch_url_validated` rewrites the request URL to the validated IP,
  pins the ``Host`` header, and passes ``sni_hostname`` (honored by
  httpcore 1.x as the TLS ``server_hostname``) for https. Redirects are
  manual (max 3 hops), each hop re-resolved and re-validated. The HTTP
  client never resolves hostnames itself, closing DNS-rebinding TOCTOU.
- :func:`validate_webhook_url` enforces https, no userinfo, and an
  allowlisted port, then resolves + validates, for use at both webhook
  save time and send time.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from utils.ssrf_guard import is_globally_routable_ip

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_ALLOWED_WEBHOOK_PORTS = frozenset({443, 8443})


class EgressBlocked(ValueError):
    """Raised when a destination fails egress validation (fail-closed)."""


def resolve_validated_ips(host: str, port: int = 80) -> list[str]:
    """Resolve *host* once and return every IP, all globally routable.

    Raises :class:`EgressBlocked` when the host is empty, does not resolve,
    resolves to nothing, or ANY resolved IP is blocked. Callers connect to
    these IPs directly and must not resolve again.
    """
    if not host or not host.strip():
        raise EgressBlocked("Empty destination host")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise EgressBlocked(f"Host {host} does not resolve") from exc
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise EgressBlocked(f"Host {host} does not resolve")
    for ip in ips:
        if not is_globally_routable_ip(ip):
            raise EgressBlocked(f"Host {host} resolves to a blocked address")
    return ips


async def open_tcp_validated(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    ssl_context=None,
    server_hostname: str | None = None,
):
    """Open TCP to a validated IP for *host* (single resolution).

    Pass ``ssl_context`` (verified, ``check_hostname=True``) together with
    ``server_hostname`` for TLS so SNI and certificate verification pin to
    the original name. Returns ``(reader, writer)``.
    """
    ips = resolve_validated_ips(host, port)
    kwargs: dict = {}
    if ssl_context is not None:
        kwargs["ssl"] = ssl_context
    if server_hostname is not None:
        kwargs["server_hostname"] = server_hostname
    return await asyncio.wait_for(
        asyncio.open_connection(ips[0], port, **kwargs), timeout
    )


@dataclass
class FetchResult:
    """Small completed HTTP response."""

    status_code: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""


async def _read_capped(client_response, max_bytes: int) -> bytes | None:
    try:
        declared = int(client_response.headers.get("content-length", 0) or 0)
    except (TypeError, ValueError):
        declared = 0
    if declared > max_bytes:
        return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in client_response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def fetch_url_validated(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    timeout: float = 10.0,
    max_redirects: int = 3,
    max_bytes: int = 65536,
) -> FetchResult:
    """Fetch *url* through validated IPs with no client-side resolution trust.

    Raises :class:`EgressBlocked` for non-http(s) URLs, unresolvable or
    blocked destinations, redirect loops/scheme changes, and over-cap bodies.
    """
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        raise EgressBlocked("Only http(s) URLs may be fetched")
    host = parsed.hostname or ""
    base_headers = dict(headers or {})

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        scheme = parsed.scheme
        current_host = host
        current_target = parsed.path or "/"
        if parsed.query:
            current_target += f"?{parsed.query}"
        hops = 0
        while True:
            ips = resolve_validated_ips(current_host)
            port = _port_for(scheme, parsed)
            target_url = f"{scheme}://{ips[0]}:{port}{current_target}"
            req_headers = {**base_headers, "Host": current_host}
            extensions = {"sni_hostname": current_host} if scheme == "https" else {}
            async with client.stream(
                method, target_url, headers=req_headers, extensions=extensions
            ) as response:
                if response.status_code in REDIRECT_STATUSES:
                    if hops >= max_redirects:
                        raise EgressBlocked("Too many redirects")
                    location = response.headers.get("location")
                    if not location:
                        raise EgressBlocked("Redirect has no Location")
                    from urllib.parse import urljoin

                    nxt = urlparse(urljoin(target_url, location))
                    if nxt.scheme not in ("http", "https") or not nxt.hostname:
                        raise EgressBlocked("Redirect left http(s)")
                    scheme = nxt.scheme
                    current_host = nxt.hostname
                    current_target = nxt.path or "/"
                    if nxt.query:
                        current_target += f"?{nxt.query}"
                    parsed = nxt
                    hops += 1
                    continue
                body = await _read_capped(response, max_bytes)
                if body is None:
                    raise EgressBlocked(
                        f"Response exceeds {max_bytes} bytes"
                    )
                return FetchResult(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body,
                )


def _port_for(scheme: str, parsed) -> int:
    if parsed.port:
        return parsed.port
    return 443 if scheme == "https" else 80


def validate_webhook_url(
    url: str, *, allowed_ports: frozenset[int] = _ALLOWED_WEBHOOK_PORTS
) -> tuple[str, int, str]:
    """Validate a webhook URL at save time AND send time.

    Requires https, rejects userinfo and non-allowlisted ports, then
    resolves every IP and validates them. Returns ``(host, port, path)``.
    """
    parsed = urlparse(url or "")
    if parsed.scheme != "https":
        raise EgressBlocked("Webhook URL must use https")
    host = parsed.hostname or ""
    if not host:
        raise EgressBlocked("Webhook URL has no host")
    if parsed.username or parsed.password:
        raise EgressBlocked("Webhook URL must not contain userinfo")
    port = parsed.port or 443
    if port not in allowed_ports:
        raise EgressBlocked(f"Webhook port {port} is not allowed")
    resolve_validated_ips(host, port)
    return host, port, parsed.path or "/"
