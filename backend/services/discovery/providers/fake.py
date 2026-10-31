"""Fake discovery provider for tests.

Returns a configurable, deterministic set of hosts with no network I/O.  Can
simulate cache hits, errors, wildcard coverage, and out-of-scope hosts.
"""

from __future__ import annotations

from typing import Optional

from services.discovery.providers.base import (
    DiscoveredHost,
    DiscoveryProvider,
    ProviderResult,
    now_utc,
)


class FakeProvider(DiscoveryProvider):
    name = "fake"
    requires_key = False

    def __init__(
        self,
        hosts: Optional[list[str]] = None,
        *,
        error: Optional[str] = None,
        cache_hit: bool = False,
        out_of_scope: Optional[list[str]] = None,
        wildcards: Optional[list[str]] = None,
    ) -> None:
        self._hosts = list(hosts or [])
        self._error = error
        self._cache_hit = cache_hit
        self._out_of_scope = list(out_of_scope or [])
        self._wildcards = list(wildcards or [])
        self.lookup_count = 0

    async def lookup(self, domain: str) -> ProviderResult:
        self.lookup_count += 1
        if self._error:
            return ProviderResult(
                provider=self.name, error=self._error, hosts_returned=0
            )
        now = now_utc()
        hosts: list[DiscoveredHost] = []
        for host in self._hosts:
            hosts.append(
                DiscoveredHost(
                    host=host,
                    source=self.name,
                    first_seen=now,
                    last_seen=now,
                )
            )
        for host in self._wildcards:
            hosts.append(
                DiscoveredHost(
                    host=host,
                    source=self.name,
                    is_wildcard=True,
                    first_seen=now,
                    last_seen=now,
                )
            )
        # Out-of-scope hosts are intentionally NOT returned by the provider
        # (providers filter to the registered domain).  They are recorded here
        # only so tests can assert a provider *rejected* them.
        return ProviderResult(
            provider=self.name,
            hosts=hosts,
            cache_hit=self._cache_hit,
            hosts_returned=len(hosts),
        )
