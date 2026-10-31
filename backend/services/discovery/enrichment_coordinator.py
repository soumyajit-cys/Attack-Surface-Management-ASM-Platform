"""Discovery provider coordinator.

Runs the enabled discovery providers for a registered domain, merges their
results, deduplicates hosts, caps hosts per source per scan, and reports
provider outcomes.  Provider failures are non-fatal: a broken provider is
recorded with an error state and the scan continues.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from metrics.prometheus import (
    DISCOVERY_CACHE_HITS_TOTAL,
    DISCOVERY_HOSTS_FOUND_TOTAL,
    DISCOVERY_REQUESTS_TOTAL,
    DISCOVERY_SUBDOMAINS_RETURNED_TOTAL,
)
from services.discovery.providers.base import (
    DiscoveryProvider,
    DiscoveredHost,
    ProviderResult,
)
from utils.logger import logger

logger = logging.getLogger("sentinelasm.discovery")


class DiscoveryCoordinator:
    """Orchestrates discovery providers for one domain."""

    def __init__(
        self,
        providers: Iterable[DiscoveryProvider],
        max_hosts_per_source_per_scan: int = 500,
    ) -> None:
        self._providers = list(providers)
        self._max_hosts_per_source_per_scan = max_hosts_per_source_per_scan

    async def discover(self, domain: str) -> tuple[list[DiscoveredHost], list[ProviderResult]]:
        """Run all providers for *domain*.

        Returns ``(hosts, results)`` where *hosts* is the merged, deduplicated,
        capped list of :class:`DiscoveredHost` and *results* is one
        :class:`ProviderResult` per provider (including failures).
        """
        if not self._providers:
            return [], []

        results = await asyncio.gather(
            *[provider.lookup(domain) for provider in self._providers],
            return_exceptions=True,
        )

        merged: dict[str, DiscoveredHost] = {}
        provider_results: list[ProviderResult] = []

        for provider, result in zip(self._providers, results):
            if isinstance(result, Exception):
                result = ProviderResult(
                    provider=provider.name,
                    error=f"provider_crashed: {type(result).__name__}",
                    hosts_returned=0,
                )
                logger.warning(
                    "Discovery provider %s crashed: %s", provider.name, result.error
                )
            provider_results.append(result)
            self._record_metrics(result)

            if result.error:
                continue
            for host in result.hosts:
                # Cap per source per scan (prevents DB flooding).
                if (
                    len(
                        [
                            h
                            for h in merged.values()
                            if h.source == host.source
                        ]
                    )
                    >= self._max_hosts_per_source_per_scan
                ):
                    continue
                key = host.host
                existing = merged.get(key)
                if existing is None:
                    merged[key] = host
                else:
                    # Keep the earliest first_seen and latest last_seen; merge
                    # wildcard flags.
                    merged[key] = DiscoveredHost(
                        host=existing.host,
                        source=existing.source,
                        is_wildcard=existing.is_wildcard or host.is_wildcard,
                        first_seen=min(
                            existing.first_seen or host.first_seen,
                            host.first_seen or existing.first_seen,
                        ),
                        last_seen=max(
                            existing.last_seen or host.last_seen,
                            host.last_seen or existing.last_seen,
                        ),
                    )

        hosts = sorted(merged.values(), key=lambda h: h.host)
        return hosts, provider_results

    def _record_metrics(self, result: ProviderResult) -> None:
        DISCOVERY_REQUESTS_TOTAL.labels(
            provider=result.provider, outcome="error" if result.error else "ok"
        ).inc()
        if result.cache_hit:
            DISCOVERY_CACHE_HITS_TOTAL.labels(provider=result.provider).inc()
        DISCOVERY_HOSTS_FOUND_TOTAL.labels(provider=result.provider).inc(
            len(result.hosts)
        )
        DISCOVERY_SUBDOMAINS_RETURNED_TOTAL.labels(provider=result.provider).inc(
            result.hosts_returned
        )
