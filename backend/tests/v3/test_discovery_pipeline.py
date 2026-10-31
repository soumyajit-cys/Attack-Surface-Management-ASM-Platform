"""Discovery pipeline tests (Phase 2 step 3).

Covers: discover_subdomains returns source/first_seen/last_seen, upsert
merges sources across concurrent scans, and scope gating prevents active
probing of unpinned/unverified targets.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from services.discovery.subdomain_service import discover_subdomains


# ── discover_subdomains: sources + timestamps ─────────────────────────────


class TestDiscoverSubdomains:
    @pytest.mark.asyncio
    async def test_returns_source_and_timestamps(self, monkeypatch):
        """crt.sh results carry source, first_seen, last_seen."""
        from services.discovery.providers.crt_sh import CrtShProvider

        # Patch the provider lookup to avoid network.
        async def fake_lookup(self, domain):
            from services.discovery.providers.base import (
                DiscoveredHost,
                ProviderResult,
            )
            now = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
            return ProviderResult(
                provider="crt_sh",
                hosts=[
                    DiscoveredHost(
                        host="www.example.com",
                        source="crt_sh",
                        first_seen=now,
                        last_seen=now,
                    )
                ],
                hosts_returned=1,
            )

        monkeypatch.setattr(CrtShProvider, "lookup", fake_lookup)

        results = await discover_subdomains("example.com")
        assert len(results) >= 1
        www = next((r for r in results if r["subdomain"] == "www.example.com"), None)
        assert www is not None, results
        assert "crt_sh" in www["sources"]
        assert www["first_seen"] is not None
        assert www["last_seen"] is not None

    @pytest.mark.asyncio
    async def test_out_of_scope_hosts_dropped(self, monkeypatch):
        """Only the registered domain and its subdomains are kept."""
        from services.discovery.providers.crt_sh import CrtShProvider

        async def fake_lookup(self, domain):
            from services.discovery.providers.base import (
                DiscoveredHost,
                ProviderResult,
            )
            now = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
            return ProviderResult(
                provider="crt_sh",
                hosts=[
                    DiscoveredHost(host="www.example.com", source="crt_sh", first_seen=now, last_seen=now),
                    DiscoveredHost(host="unrelated.com", source="crt_sh", first_seen=now, last_seen=now),
                ],
                hosts_returned=2,
            )

        monkeypatch.setattr(CrtShProvider, "lookup", fake_lookup)

        results = await discover_subdomains("example.com")
        hosts = {r["subdomain"] for r in results}
        assert "www.example.com" in hosts
        assert "unrelated.com" not in hosts


# ── upsert / merge sources ────────────────────────────────────────────────


class TestUpsertMerge:
    def test_upsert_merges_sources(self, db, org_factory):
        """Two scans of the same subdomain merge sources, keep earliest
        first_seen and latest last_seen."""
        from models.domain import Domain
        from models.subdomain import Subdomain
        from services.scanner.persistence import persist_discovery_results

        org, _ = org_factory("Upsert Org", "upuser", "upuser@example.com")
        from models.asset import Asset

        asset = Asset(organization_id=org.id, name="example.com")
        db.add(asset)
        db.flush()
        domain = Domain(organization_id=org.id, asset_id=asset.id, domain="example.com")
        db.add(domain)
        db.flush()
        db.commit()

        now1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        now2 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=timezone.utc)

        # First scan: crt.sh only.
        persist_discovery_results(
            db,
            org.id,
            "example.com",
            {
                "dns": [],
                "registrar": None,
                "asn": None,
                "subdomains": [
                    {
                        "subdomain": "www.example.com",
                        "source": "crt_sh",
                        "sources": ["crt_sh"],
                        "first_seen": now1.isoformat(),
                        "last_seen": now1.isoformat(),
                    }
                ],
            },
        )
        db.commit()

        # Second scan: dns_brute for same host.
        persist_discovery_results(
            db,
            org.id,
            "example.com",
            {
                "dns": [],
                "registrar": None,
                "asn": None,
                "subdomains": [
                    {
                        "subdomain": "www.example.com",
                        "source": "dns_brute",
                        "sources": ["dns_brute"],
                        "first_seen": now2.isoformat(),
                        "last_seen": now2.isoformat(),
                    }
                ],
            },
        )
        db.commit()

        row = (
            db.query(Subdomain)
            .filter(Subdomain.subdomain == "www.example.com")
            .one()
        )
        assert set(row.sources) == {"crt_sh", "dns_brute"}, row.sources
        assert row.first_seen == now1, row.first_seen
        assert row.last_seen == now2, row.last_seen
        assert row.source == "dns_brute"  # latest source wins the scalar column


# ── scope gating: active probing requires a pin ───────────────────────────


class TestScopeGating:
    def test_scan_targets_skips_unpinned(self, db, org_factory, monkeypatch):
        """Active probing is skipped for targets without a pinned IP
        (unverified domain scenario)."""
        import tasks.discovery_tasks as dt

        org, _ = org_factory("Gate Org", "gateuser", "gateuser@example.com")
        scan = SimpleNamespace(organization_id=org.id, id=1)
        persisted = {
            "subdomains": [
                SimpleNamespace(subdomain="www.example.com", id=1, ip_address=None)
            ],
        }

        calls = []

        def fake_run(ctx, modules):
            calls.append([m.phase for m in modules])
            return {}

        monkeypatch.setattr(dt, "_run_in_context", fake_run)
        monkeypatch.setattr(dt, "pinned_resolve", lambda host: (_ for _ in ()).throw(
            __import__("app.core.ssrf", fromlist=["PinnedResolutionMissing"]).PinnedResolutionMissing(host)
        ))

        summary = dt._scan_targets(
            db, scan, persisted, "example.com", None, "full"
        )

        assert calls == [], f"active probing must not run without pin: {calls}"
        assert summary["unpinned_skipped"] == ["www.example.com"]
        assert summary["ports_total"] == 0
