"""Discovery provider metrics labels test (Phase 2.1, item 8).

Confirms that discovery provider metrics labels are only ``provider`` and
``outcome`` -- never a domain or hostname (observability must not leak scan
targets).
"""

from __future__ import annotations

# Import the metrics module so all discovery counters are registered.
import metrics.prometheus  # noqa: F401
from prometheus_client import REGISTRY


class TestDiscoveryMetricsLabels:
    def test_discovery_labels_are_provider_and_outcome_only(self):
        """Every discovery provider counter carries only the allowed
        label sets: provider (+ outcome for requests). Domains/hostnames
        must never appear as labels (observability must not leak targets)."""
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
                label_names = set()
                for sample in metric.samples:
                    label_names.update(sample.labels.keys())
                found[name] = label_names
        for name, allowed in expected.items():
            assert name in found, f"{name} not registered"
            assert found[name] == allowed, (
                f"{name} labels {found[name]} != expected {allowed}"
            )
