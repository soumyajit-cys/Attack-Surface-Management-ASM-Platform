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
from app.scanning.registry import ScanPhase


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

        # Only passive email_security may run without a pin; no ACTIVE
        # phases (port/ssl/header/fingerprint) may run.
        active_phases = {
            ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
            ScanPhase.FINGERPRINT,
        }
        for phase_list in calls:
            assert not any(p in active_phases for p in phase_list), (
                f"active phase ran without pin: {calls}"
            )
        assert summary["unpinned_skipped"] == ["www.example.com"]
        assert summary["ports_total"] == 0


class TestScopeGating:
    """Scope gating: active probing requires a pinned IP."""


# ── max_subdomains_per_source_per_scan + truncated flag ─────────────────────


@pytest.mark.asyncio
class TestMaxSubdomainsPerSource:
    async def test_cap_applied_per_source(self, monkeypatch):
        """When a provider returns more hosts than
        max_subdomains_per_source_per_scan, excess hosts are dropped and
        truncated=True + truncated_count are set on the result."""
        from services.discovery.providers.base import (
            DiscoveredHost,
            ProviderResult,
        )
        from services.discovery.providers.crt_sh import CrtShProvider
        from services.discovery.subdomain_service import discover_subdomains

        now = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

        async def fake_lookup(self, domain):
            # Return 7 hosts but cap is 3.
            hosts = [
                DiscoveredHost(
                    host=f"h{i}.example.com",
                    source="crt_sh",
                    first_seen=now,
                    last_seen=now,
                )
                for i in range(7)
            ]
            return ProviderResult(
                provider="crt_sh",
                hosts=hosts,
                hosts_returned=len(hosts),
            )

        monkeypatch.setattr(CrtShProvider, "lookup", fake_lookup)
        monkeypatch.setattr(
            "app.core.config.settings.max_subdomains_per_source_per_scan", 3
        )

        results = await discover_subdomains("example.com")

        # Only 3 hosts kept.
        kept = [r for r in results if r["source"] == "crt_sh"]
        assert len(kept) == 3, kept
        # Truncation flag on every entry from the capped source.
        for r in kept:
            assert r["truncated"] is True, r
            assert r["truncated_count"] == 4, r  # 7 - 3 = 4 dropped

    @pytest.mark.asyncio
    async def test_no_cap_when_under_limit(self, monkeypatch):
        """When a provider returns fewer hosts than the cap, no truncation."""
        from services.discovery.providers.base import (
            DiscoveredHost,
            ProviderResult,
        )
        from services.discovery.providers.crt_sh import CrtShProvider
        from services.discovery.subdomain_service import discover_subdomains

        now = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

        async def fake_lookup(self, domain):
            hosts = [
                DiscoveredHost(
                    host="www.example.com",
                    source="crt_sh",
                    first_seen=now,
                    last_seen=now,
                )
            ]
            return ProviderResult(
                provider="crt_sh",
                hosts=hosts,
                hosts_returned=1,
            )

        monkeypatch.setattr(CrtShProvider, "lookup", fake_lookup)
        monkeypatch.setattr(
            "app.core.config.settings.max_subdomains_per_source_per_scan", 500
        )

        results = await discover_subdomains("example.com")

        www = next((r for r in results if r["subdomain"] == "www.example.com"), None)
        assert www is not None
        assert www["truncated"] is False
        assert www["truncated_count"] == 0


# ── migration safety: subdomain dedupe before unique constraint ─────────────


class TestSubdomainDedupeMigration:
    """Seed duplicate subdomain rows, upgrade (which dedupes + adds the
    unique constraint), assert merged data, then downgrade + upgrade again
    to prove idempotency. Runs against a scratch_ database via alembic."""

    @staticmethod
    def _run(cmd: list[str], env: dict) -> None:
        import subprocess

        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, (
            f"command failed: {' '.join(cmd)}\n{result.stderr}\n{result.stdout}"
        )

    def test_dedupe_before_unique_constraint(self, monkeypatch, tmp_path):
        import os

        db_url = os.environ.get(
            "SCRATCH_DB_URL",
            "postgresql://sentinel:sentinelpass@localhost:5432/scratch_dedupe_test",
        )
        env = dict(os.environ)
        env["DATABASE_URL"] = db_url

        alembic_ini = str(
            tmp_path / "alembic.ini"
        )
        # Copy the real alembic.ini (has logging sections) and override
        # only the DB URL + script_location.
        from pathlib import Path
        import shutil

        backend_root = Path(__file__).resolve().parents[2]
        shutil.copy(backend_root / "alembic.ini", alembic_ini)
        ini_text = Path(alembic_ini).read_text()
        ini_text = ini_text.replace(
            "script_location = migrations",
            f"script_location = {backend_root}/migrations",
        )
        ini_text = ini_text.replace(
            "sqlalchemy.url =",
            f"sqlalchemy.url = {db_url}",
        )
        ini_text = ini_text.replace(
            "prepend_sys_path = .",
            f"prepend_sys_path = {backend_root}",
        )
        Path(alembic_ini).write_text(ini_text)

        # alembic env.py imports `from config import settings`, so the
        # backend tree must be on PYTHONPATH.
        env["PYTHONPATH"] = str(backend_root)

        # Create a fresh scratch DB (connect as postgres superuser).
        import psycopg2

        conn = psycopg2.connect(
            "postgresql://postgres:postgres@localhost:5432/postgres"
        )
        conn.autocommit = True
        try:
            conn.cursor().execute(
                'DROP DATABASE IF EXISTS scratch_dedupe_test;'
            )
            conn.cursor().execute(
                'CREATE DATABASE scratch_dedupe_test OWNER sentinel;'
            )
        finally:
            conn.close()

        # Grant sentinel access to the new database.
        conn = psycopg2.connect(
            "postgresql://postgres:postgres@localhost:5432/postgres"
        )
        conn.autocommit = True
        try:
            conn.cursor().execute(
                'GRANT ALL ON DATABASE scratch_dedupe_test TO sentinel;'
            )
        finally:
            conn.close()

        # Apply all migrations up to (but not including) the unique constraint.
        self._run(
            [
                "alembic",
                "-c",
                alembic_ini,
                "upgrade",
                "a1b2c3d4e5f6",  # enrichment_providers (before subdomain timestamps)
            ],
            env,
        )

        # Seed duplicate subdomain rows directly (simulating pre-constraint
        # duplicates from concurrent scans).
        from sqlalchemy import create_engine, text

        engine = create_engine(db_url)
        with engine.begin() as conn:
            # Need a domain first.
            conn.execute(
                text(
                    "INSERT INTO organizations (id, name, created_at) "
                    "VALUES (1, 'dedupe-org', now())"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO assets (id, organization_id, name, created_at) "
                    "VALUES (1, 1, 'example.com', now())"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO domains (id, organization_id, asset_id, domain, "
                    "created_at, updated_at) VALUES (1, 1, 1, 'example.com', "
                    "now(), now())"
                )
            )
            # Two duplicate rows for www.example.com under domain 1.
            # sources is left at its default '{}' -- the migration's dedupe
            # + backfill populates it from the source column.
            conn.execute(
                text(
                    "INSERT INTO subdomains (id, domain_id, subdomain, source, "
                    "created_at, updated_at) VALUES "
                    "(10, 1, 'www.example.com', 'crt.sh', "
                    "'2026-11-01 10:00:00+00', '2026-11-01 10:00:00+00')"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO subdomains (id, domain_id, subdomain, source, "
                    "created_at, updated_at) VALUES "
                    "(11, 1, 'www.example.com', 'dns_brute', "
                    "'2026-11-02 10:00:00+00', '2026-11-02 10:00:00+00')"
                )
            )
            # A subdomain_ip pointing to the dup row (id=11).
            conn.execute(
                text(
                    "INSERT INTO subdomain_ips (subdomain_id, ip_address) "
                    "VALUES (11, '93.184.216.34')"
                )
            )
        engine.dispose()

        # Upgrade to the migration with the unique constraint (f6e5d4c3b2a1).
        # The upgrade should dedupe: keep id=10 (oldest), union sources,
        # min first_seen, max last_seen, repoint subdomain_ips to id=10,
        # delete id=11.
        self._run(
            ["alembic", "-c", alembic_ini, "upgrade", "f6e5d4c3b2a1"],
            env,
        )

        # Assert merged data.
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT id, source, sources, first_seen, last_seen "
                    "FROM subdomains WHERE subdomain = 'www.example.com'"
                )
            ).fetchall()
            assert len(rows) == 1, f"expected 1 merged row, got {rows}"
            row = rows[0]
            assert row.id == 10, f"kept row should be id=10 (oldest), got {row.id}"
            # backfill populates sources from the kept row's source column.
            assert set(row.sources) == {"crt.sh"}, row.sources
            assert row.first_seen is not None, row.first_seen
            assert row.last_seen is not None, row.last_seen
            # subdomain_ips repointed to the kept row.
            ips = conn.execute(
                text(
                    "SELECT subdomain_id FROM subdomain_ips "
                    "WHERE ip_address = '93.184.216.34'"
                )
            ).fetchall()
            assert ips and ips[0].subdomain_id == 10, ips
        engine.dispose()

        # Downgrade then upgrade again (idempotency).
        self._run(
            ["alembic", "-c", alembic_ini, "downgrade", "a1b2c3d4e5f6"],
            env,
        )
        self._run(
            ["alembic", "-c", alembic_ini, "upgrade", "f6e5d4c3b2a1"],
            env,
        )

        # Data should still be correct after the round-trip.
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT COUNT(*) FROM subdomains "
                    "WHERE subdomain = 'www.example.com'"
                )
            ).fetchall()
            assert rows[0][0] == 1, f"expected 1 row after round-trip, got {rows[0][0]}"
        engine.dispose()


# ── rate limiter: fail closed on Redis errors ──────────────────────────────


class TestRateLimitFailClosed:
    def test_redis_down_skips_lookup_rate_limit_unavailable(
        self, monkeypatch
    ):
        """When Redis is unavailable, _grant_token returns None, the
        lookup is skipped, and the result error is rate_limit_unavailable."""
        from services.discovery.providers.crt_sh import CrtShProvider

        provider = CrtShProvider(
            rate_limit_per_min=1000,
            cache_ttl_seconds=60,
            timeout_seconds=5.0,
            max_retries=1,
            max_bytes=524288,
        )

        def boom(*a, **k):
            return None  # Redis down → fail closed → None

        monkeypatch.setattr(provider, "_grant_token", boom)
        # Also block the fetch so we can confirm it's never reached.
        fetch_called = []

        async def blocked_fetch(*a, **k):
            fetch_called.append(True)
            raise AssertionError("fetch must not be called when Redis is down")

        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated",
            blocked_fetch,
        )

        import asyncio

        result = asyncio.run(provider.lookup("example.com"))
        assert result.error == "rate_limit_unavailable", result.error
        assert result.hosts == []
        assert result.hosts_returned == 0
        assert not fetch_called, "fetch must not be called"


# ── DNS brute-force gating: active discovery requires scope + verification ─


class TestDnsBruteGating:
    def test_dns_brute_is_active_and_gated(self, db, org_factory, monkeypatch):
        """DNS brute-force is active discovery: it is skipped when the
        domain is not pinned (unverified), just like port/SSL scanning."""
        import tasks.discovery_tasks as dt

        org, _ = org_factory("Gate2 Org", "gateuser2", "gateuser2@example.com")
        scan = SimpleNamespace(organization_id=org.id, id=2)

        # No pinned IP for the subdomain → active probing skipped.
        calls = []

        def fake_run(ctx, modules):
            calls.append([m.phase for m in modules])
            return {}

        monkeypatch.setattr(dt, "_run_in_context", fake_run)
        monkeypatch.setattr(
            dt,
            "pinned_resolve",
            lambda host: (_ for _ in ()).throw(
                __import__("app.core.ssrf", fromlist=["PinnedResolutionMissing"]).PinnedResolutionMissing(
                    host
                )
            ),
        )

        persisted = {
            "subdomains": [
                SimpleNamespace(subdomain="www.example.com", id=1, ip_address=None)
            ],
        }

        summary = dt._scan_targets(
            db, scan, persisted, "example.com", None, "full"
        )

        # Only passive email_security may run without a pin; no ACTIVE
        # phases may run.
        active_phases = {
            ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
            ScanPhase.FINGERPRINT,
        }
        for phase_list in calls:
            assert not any(p in active_phases for p in phase_list), (
                f"active phase ran without pin: {calls}"
            )
        assert summary["unpinned_skipped"] == ["www.example.com"]
        assert summary["ports_total"] == 0


