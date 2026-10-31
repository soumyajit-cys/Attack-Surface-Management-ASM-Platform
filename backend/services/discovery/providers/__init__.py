"""Discovery providers.

Discovery providers are pluggable, read-only sources of subdomain candidates.
Each provider implements the :class:`DiscoveryProvider` protocol and is
registered in the provider coordinator. Providers never perform active
probing: they only observe public data (certificate transparency logs, public
DNS, third-party intel feeds).

Optional key-based providers are disabled unless an organisation has stored an
encrypted API key in the ``enrichment_providers`` table; the key is never
returned by the API or logged.
"""

from .base import DiscoveredHost, DiscoveryProvider, ProviderError, ProviderResult

__all__ = [
    "DiscoveredHost",
    "DiscoveryProvider",
    "ProviderError",
    "ProviderResult",
]
