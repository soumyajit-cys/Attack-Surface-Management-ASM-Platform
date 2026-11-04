"""Discovery provider metrics labels test (Phase 2.1, item 8).

Confirms that discovery provider metrics labels are only ``provider`` and
``outcome`` -- never a domain or hostname (observability must not leak scan
targets).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the backend root is on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Force-import the metrics module so all discovery counters are registered
# on the global Prometheus REGISTRY before we inspect them.
import importlib

importlib.import_module("metrics.prometheus")

from prometheus_client import REGISTRY

from metrics.prometheus import (
    DISCOVERY_CACHE_HITS_TOTAL,
    DISCOVERY_HOSTS_FOUND_TOTAL,
    DISCOVERY_REQUESTS_TOTAL,
    DISCOVERY_SUBDOMAINS_RETURNED_TOTAL,
)


class TestDiscoveryMetricsLabels:
    def test_discovery_labels_are_provider_and_outcome_only(self):
        """Every discovery provider counter carries only the allowed
        label sets: provider (+ outcome for requests). Domains/hostnames
        must never appear as labels (observability must not leak scan
        targets).

        Each metric is observed once so its declared labels appear in
        REGISTRY samples and can be inspected.
        """
        # Touch every metric so it has at least one sample with its labels.
        DISCOVERY_REQUESTS_TOTAL.labels(provider="crt_sh", outcome="ok").inc()
        DISCOVERY_HOSTS_FOUND_TOTAL.labels(provider="crt_sh").inc(1)
        DISCOVERY_CACHE_HITS_TOTAL.labels(provider="crt_sh").inc()
        DISCOVERY_SUBDOMAINS_RETURNED_TOTAL.labels(provider="crt_sh").inc(1)

        expected = {
            "sentinelasm_discovery_provider_requests": {"provider", "outcome"},
            "sentinelasm_discovery_provider_hosts_found": {"provider"},
            "sentinelasm_discovery_provider_cache_hits": {"provider"},
            "sentinelasm_discovery_subdomains_returned": {"provider"},
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
