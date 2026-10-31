"""Discovery provider protocol and shared helpers.

A :class:`DiscoveryProvider` is a read-only source of subdomain candidates for
a registered domain. Providers:

- never perform active probing (no connections to the target's ports);
- only return hosts that are the registered domain or a subdomain of it;
- normalize hostnames (lowercase, strip wildcards, IDNA/punycode, reject
  invalid labels or lengths);
- treat all external data as untrusted and never leak raw responses to logs.

The provider coordinator merges results across providers, dedupes, caps the
number of hosts per source per scan, and feeds new hosts into the change
detector.
"""

from __future__ import annotations

import idna
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

_MAX_LABEL_LEN = 63
_MAX_HOST_LEN = 253

# A DNS label: alphanumeric plus internal hyphens, not starting/ending with
# a hyphen.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ProviderError(Exception):
    """Raised when a provider fails. Callers treat this as non-fatal."""


@dataclass(frozen=True)
class DiscoveredHost:
    """One host observed by a discovery provider."""

    host: str
    source: str
    is_wildcard: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class ProviderResult:
    """Outcome of a single provider lookup."""

    provider: str
    hosts: list[DiscoveredHost] = field(default_factory=list)
    error: str | None = None
    cache_hit: bool = False
    hosts_returned: int = 0


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_host(raw_host: str) -> str | None:
    """Normalize a host observed from an untrusted source.

    Returns a canonical lowercase hostname, or ``None`` when the value is not
    a valid, scannable host. Wildcard prefixes (``*.``) are stripped and the
    caller is told via :func:`is_wildcard_host` semantics (the returned host
    has the prefix removed; the provider records the wildcard separately).

    Normalization:
      - strip whitespace and a trailing dot,
      - lowercase,
      - strip a leading ``*.`` wildcard marker,
      - IDNA/punycode-encode internationalized domain names,
      - reject empty hosts, invalid labels, labels over 63 chars, and hosts
        over 253 chars.
    """
    if not raw_host or not isinstance(raw_host, str):
        return None
    host = raw_host.strip().lower().rstrip(".")
    if not host:
        return None
    # Strip a leading wildcard marker. The host itself (e.g. "www.example.com")
    # is still a real candidate; the fact a wildcard cert covered it is
    # recorded separately by the provider.
    is_wildcard = host.startswith("*.")
    if is_wildcard:
        host = host[2:]
    if not host:
        return None
    try:
        # IDNA validation + punycode encoding for internationalized names.
        host = idna.encode(host).decode("ascii").lower()
    except idna.IDNAError:
        return None
    if len(host) > _MAX_HOST_LEN:
        return None
    labels = host.split(".")
    if len(labels) < 2:
        # Require at least one dot (a registrable domain, not a bare label).
        return None
    for label in labels:
        if not label or len(label) > _MAX_LABEL_LEN or not _LABEL_RE.match(label):
            return None
    return host


@runtime_checkable
class DiscoveryProvider(Protocol):
    """Read-only discovery provider protocol.

    Implementations must be side-effect free with respect to the target: no
    connections to the target's ports, no active probing. ``lookup`` returns
    candidate subdomains for *domain* (which is already the registered domain
    owned by the caller's organisation).
    """

    name: str
    """Human-readable provider name (also the metrics/label value)."""

    requires_key: bool = False
    """True when this provider needs an encrypted API key (optional providers
    such as Shodan/Censys/SecurityTrails). crt.sh does not require a key."""

    async def lookup(self, domain: str) -> ProviderResult:
        """Return discovered hosts for *domain*.

        Only hosts that are *domain* or a subdomain of it are returned.
        Provider failures are reported via ``ProviderResult.error`` rather
        than raised, so a broken provider never fails a scan.
        """
        ...  # pragma: no cover - protocol
