"""Discovery provider metrics labels test (Phase 2.1, item 8).

Confirms that discovery provider metrics labels are only ``provider`` and
``outcome`` -- never a domain or hostname (observability must not leak scan
targets).
"""

from __future__ import annotations

from prometheus_client import REGISTRY


class TestDiscoveryMetricsLabels:
    def test_discovery_labels_are_provider_and_outcome_only(self):
        """Every discovery provider counter/histogram carries only the
        allowed label sets: provider (+ outcome for requests)."""
        expected = {
            "sentinelasm_discovery_provider_requests_total": {"provider", "outcome"},
            "sentinelasm_discovery_provider_hosts_found_total": {"provider"},
            "sentinelasm_discovery_provider_cache_hits_total": {"provider"},
            "sentinelasm_discovery_subdomains_returned_total": {"provider"},
        }
        found = {}
        for metric in REGISTRY.collect():
            name = metric.name
            if name in expected:
                label_names = {lab.name for lab in metric.samples[0].labels} if metric.samples else set()
                found[name] = label_names
        for name, allowed in expected.items():
            assert name in found, f"{name} not registered"
            assert found[name] == allowed, (
                f"{name} labels {found[name]} != expected {allowed}"
            )
