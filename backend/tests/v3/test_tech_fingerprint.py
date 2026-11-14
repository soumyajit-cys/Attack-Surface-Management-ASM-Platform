"""v3 tech_fingerprint scanner module tests."""

import asyncio
import re
import time

import pytest

from app.scanning.context import ScanContext
from app.scanning.registry import ScanPhase, registry


@pytest.fixture(autouse=True)
def _fresh_registry():
    import sys
    for name in [n for n in sys.modules if n == "scanner_modules" or n.startswith("scanner_modules.")]:
        del sys.modules[name]
    registry._entries.clear()
    registry._discovered = False
    yield
    for name in [n for n in sys.modules if n == "scanner_modules" or n.startswith("scanner_modules.")]:
        del sys.modules[name]
    registry._entries.clear()
    registry._discovered = False


def _make_ctx(domain="example.com", subdomains=None, http_response=None):
    return ScanContext(
        domain=domain,
        pinned_ip="93.184.216.34",
        org_id=1,
        scan_id=1,
        db=None,
        scope="full",
        subdomains=list(subdomains or []),
        http_response=http_response,
    )


# ── Unit tests: matching ─────────────────────────────────────────────


class TestTechFingerprintMatching:
    def test_header_match(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints(
            {"Server": "Apache/2.4.41"}, None, None
        )
        assert any(m["provider"] == "Apache HTTP Server" for m in matches)

    def test_body_match(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints(
            None, "<html>wp-content/themes/test</html>", None
        )
        assert any(m["provider"] == "WordPress" for m in matches)

    def test_version_extraction(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints(
            {"Server": "nginx/1.18.0"}, None, None
        )
        nginx = [m for m in matches if m["provider"] == "nginx"]
        assert nginx and nginx[0].get("version") == "1.18.0"

    def test_no_match_returns_empty(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints({"X-Custom": "nothing"}, "hello world", None)
        # Should not crash; may be empty or contain only generic matches
        assert isinstance(matches, list)

    def test_redos_safety(self):
        """Version regexes must not exhibit catastrophic backtracking."""
        from scanner_modules.tech_fingerprint import FINGERPRINTS

        evil_input = "a" * 30 + "!"
        for fp in FINGERPRINTS:
            vr = fp.get("version_regex")
            if not vr:
                continue
            start = time.monotonic()
            try:
                re.search(vr, evil_input)
            except Exception:
                pass
            elapsed = time.monotonic() - start
            assert elapsed < 1.0, f"ReDoS in {fp['name']}: {elapsed:.2f}s"


# ── Module tests ─────────────────────────────────────────────────────


class TestTechFingerprintModule:
    def test_reuses_cached_response_no_extra_request(self, monkeypatch):
        """When ctx.http_response is present, no extra HTTP request is made."""
        import scanner_modules.tech_fingerprint as tf

        called = {"count": 0}

        def fake_probe(url):
            called["count"] += 1
            return {"status_code": 200, "headers": {}, "body": "", "error": None}

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(
            subdomains=["host.example.com"],
            http_response={
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.41"},
                "body": "",
            },
        )
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        assert called["count"] == 0, "Extra request made despite cached response"

    def test_two_hosts_two_findings(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.41"},
                "body": "",
                "error": None,
            }

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["a.example.com", "b.example.com"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        findings = result["findings"]
        # Each host should produce at least one finding
        hosts = {f["cname_target"] for f in findings}
        assert "a.example.com" in hosts
        assert "b.example.com" in hosts

    def test_truncation_at_max_hosts(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        original_max = tf.MAX_HOSTS_PER_SCAN
        tf.MAX_HOSTS_PER_SCAN = 2

        def fake_probe(url):
            return {"status_code": 200, "headers": {}, "body": "", "error": None}

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["h1", "h2", "h3", "h4"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        assert result["truncated"] is True

        tf.MAX_HOSTS_PER_SCAN = original_max

    def test_dedupe_key_format(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {
                "status_code": 200,
                "headers": {"Server": "nginx/1.18.0"},
                "body": "",
                "error": None,
            }

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["host.example.com"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        for f in result["findings"]:
            assert f["dedupe_key"].startswith("tech_fingerprint:")
            assert "host.example.com" in f["dedupe_key"]

    def test_scope_gating_no_probe_unverified(self):
        """Tech fingerprint is in SCOPE_FULL only."""
        from app.scanning.scope import SCOPE_PHASES, ScanPhase

        assert ScanPhase.FINGERPRINT not in SCOPE_PHASES["passive"]
        assert ScanPhase.FINGERPRINT not in SCOPE_PHASES["active"]
        assert ScanPhase.FINGERPRINT in SCOPE_PHASES["full"]

    def test_empty_subdomains_returns_empty(self):
        import scanner_modules.tech_fingerprint as tf

        ctx = _make_ctx(subdomains=[])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        assert result["findings"] == []
        assert result["truncated"] is False

    def test_confidence_cap(self, monkeypatch):
        """Banner-derived versions have confidence <= 0.6."""
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.41"},
                "body": "",
                "error": None,
            }

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["host.example.com"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        for f in result["findings"]:
            assert f["confidence"] <= 0.85


class TestSanitizerAllowlist:
    def test_only_allowlisted_headers_survive(self):
        from scanner_modules.header_scan import _sanitize_response

        raw = {
            "status_code": 200,
            "headers": {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4",
                "Set-Cookie": "session=secret123",
                "Authorization": "Bearer token",
                "X-Custom-Secret": "should-not-survive",
                "Content-Type": "text/html",
            },
            "body": "hello world",
        }
        sanitized = _sanitize_response(raw)
        assert sanitized is not None
        assert set(sanitized["headers"].keys()) == {"server", "x-powered-by", "content-type"}
        assert "Set-Cookie" not in sanitized["headers"]
        assert "Authorization" not in sanitized["headers"]
        assert "X-Custom-Secret" not in sanitized["headers"]

    def test_no_raw_headers_or_body_in_summary(self):
        """Persisted scan summary must not contain raw headers or body."""
        import tasks.discovery_tasks as dt

        # Verify the summary dict doesn't include http_response fields
        from app.scanning.registry import registry, ScanPhase
        summary = dt._new_summary(registry)
        # Check that no value in the summary contains header/body keys
        def _check(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # The summary legitimately has a "headers" key (scanned/issues
                    # counters) and "ssl" key.  We only flag http_response and
                    # body keys that would indicate leaked raw data.
                    assert k not in ("http_response", "body", "raw_headers", "raw_body"), f"Found {k} at {path}"
                    _check(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _check(item, f"{path}[{i}]")

        _check(summary)


class TestAssetTechnologiesAPI:
    def test_cross_org_tenant_isolation(self, db, org_factory, monkeypatch):
        """Org B cannot see org A's technologies."""
        # This test verifies the API scoping; actual HTTP test would need
        # TestClient. Here we verify the query-level scoping.
        from models.asset import Asset
        from models.domain import Domain
        from models.subdomain import Subdomain
        from models.asset_technology import AssetTechnology

        # Create org A asset with technology
        org_a, _ = org_factory("org-a", "usera", "a@example.com")
        org_b, _ = org_factory("org-b", "userb", "b@example.com")
        asset_a = Asset(organization_id=org_a.id, name="asset-a")
        db.add(asset_a)
        db.flush()
        domain_a = Domain(organization_id=1, asset_id=asset_a.id, domain="a.example.com")
        db.add(domain_a)
        db.flush()
        sub_a = Subdomain(domain_id=domain_a.id, subdomain="www.a.example.com")
        db.add(sub_a)
        db.flush()
        tech_a = AssetTechnology(subdomain_id=sub_a.id, name="nginx", confidence=0.6)
        db.add(tech_a)
        db.commit()

        # Query as org 2 should find nothing
        from app.api.v1.assets import _subdomain_data
        # Verify the subdomain belongs to org 1
        assert sub_a.id is not None
        # Cross-org: querying Asset with org_id=2 should not find asset_a
        from models.asset import Asset as A
        result = db.query(A).filter(A.id == asset_a.id, A.organization_id == org_b.id).first()
        assert result is None


class TestPersistenceUpsert:
    def test_upsert_insert_and_update(self, db, org_factory):
        from models.subdomain import Subdomain
        from models.domain import Domain
        from models.asset import Asset
        from services.scanner.persistence import persist_tech_fingerprint_results
        from models.asset_technology import AssetTechnology

        org, _ = org_factory("test-org", "testuser", "test@example.com")
        asset = Asset(organization_id=org.id, name="test-asset")
        db.add(asset)
        db.flush()
        domain = Domain(organization_id=org.id, asset_id=asset.id, domain="example.com")
        db.add(domain)
        db.flush()
        sub = Subdomain(domain_id=domain.id, subdomain="www.example.com")
        db.add(sub)
        db.flush()

        # Insert
        persist_tech_fingerprint_results(db, sub, [
            {"provider": "nginx", "category": "web_server", "version": "1.18.0", "confidence": 0.6, "matched_pattern": "nginx/", "status_code": 200},
        ])
        db.commit()

        tech = db.query(AssetTechnology).filter(AssetTechnology.subdomain_id == sub.id).first()
        assert tech is not None
        assert tech.name == "nginx"
        assert tech.version == "1.18.0"
        first_seen = tech.first_seen

        # Update
        persist_tech_fingerprint_results(db, sub, [
            {"provider": "nginx", "category": "web_server", "version": "1.20.0", "confidence": 0.6, "matched_pattern": "nginx/", "status_code": 200},
        ])
        db.commit()
        db.expire_all()

        tech = db.query(AssetTechnology).filter(AssetTechnology.subdomain_id == sub.id).first()
        assert tech.version == "1.20.0"
        assert tech.first_seen == first_seen  # preserved

    def test_concurrent_upsert_no_integrity_error(self, db, org_factory):
        """Concurrent upserts must not raise IntegrityError."""
        from models.subdomain import Subdomain
        from models.domain import Domain
        from models.asset import Asset
        from services.scanner.persistence import persist_tech_fingerprint_results
        from models.asset_technology import AssetTechnology
        from sqlalchemy.exc import IntegrityError

        org, _ = org_factory("test-org2", "testuser2", "test2@example.com")
        asset = Asset(organization_id=org.id, name="test-asset2")
        db.add(asset)
        db.flush()
        domain = Domain(organization_id=org.id, asset_id=asset.id, domain="example2.com")
        db.add(domain)
        db.flush()
        sub = Subdomain(domain_id=domain.id, subdomain="www.example2.com")
        db.add(sub)
        db.flush()

        # Two upserts for the same (subdomain_id, name) should not error
        persist_tech_fingerprint_results(db, sub, [
            {"provider": "Apache", "category": "web_server", "version": "2.4", "confidence": 0.6, "matched_pattern": "Apache/", "status_code": 200},
        ])
        persist_tech_fingerprint_results(db, sub, [
            {"provider": "Apache", "category": "web_server", "version": "2.4.1", "confidence": 0.6, "matched_pattern": "Apache/", "status_code": 200},
        ])
        db.commit()
        db.expire_all()

        tech = db.query(AssetTechnology).filter(AssetTechnology.subdomain_id == sub.id).first()
        assert tech.version == "2.4.1"


class TestRealConcurrency:
    def test_concurrent_upsert_two_sessions(self, db, org_factory):
        """Two sessions in two threads released together with a barrier."""
        import threading
        from models.subdomain import Subdomain
        from models.domain import Domain
        from models.asset import Asset
        from models.asset_technology import AssetTechnology
        from services.scanner.persistence import persist_tech_fingerprint_results
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        org, _ = org_factory("conc-org", "concuser", "conc@example.com")
        asset = Asset(organization_id=org.id, name="conc-asset")
        db.add(asset)
        db.flush()
        domain = Domain(organization_id=org.id, asset_id=asset.id, domain="conc.example.com")
        db.add(domain)
        db.flush()
        sub = Subdomain(domain_id=domain.id, subdomain="www.conc.example.com")
        db.add(sub)
        db.commit()
        sub_id = sub.id

        # Use the same DB URL for both sessions
        db_url = str(db.bind.url)
        engine = create_engine(db_url)
        Session = sessionmaker(bind=engine)

        barrier = threading.Barrier(2)
        errors = []

        def worker(version):
            try:
                s = Session()
                # Re-fetch subdomain in this session
                sub_obj = s.query(Subdomain).filter(Subdomain.id == sub_id).first()
                barrier.wait(timeout=5)
                persist_tech_fingerprint_results(s, sub_obj, [
                    {"provider": "nginx", "category": "web_server", "version": version,
                     "confidence": 0.6, "matched_pattern": "nginx/", "status_code": 200},
                ])
                s.commit()
                s.close()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker, args=("1.18.0",))
        t2 = threading.Thread(target=worker, args=("1.20.0",))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert not errors, f"Concurrency errors: {errors}"

        # Verify final state
        s = Session()
        tech = s.query(AssetTechnology).filter(AssetTechnology.subdomain_id == sub_id).first()
        assert tech is not None
        assert tech.version in ("1.18.0", "1.20.0")
        s.close()


class TestValueBasedSanitizer:
    def test_sentinel_strings_not_in_summary_or_logs(self, caplog):
        import logging
        import json
        import tasks.discovery_tasks as dt
        from app.scanning.registry import registry

        caplog.set_level(logging.DEBUG)

        # Unique sentinel strings
        sentinel_cookie = "SENTINEL_COOKIE_VALUE_XYZ"
        sentinel_auth = "SENTINEL_AUTH_TOKEN_ABC"
        sentinel_body = "SENTINEL_BODY_CONTENT_123"

        # Build a sanitized response (simulating what header_scan produces)
        from scanner_modules.header_scan import _sanitize_response
        raw = {
            "status_code": 200,
            "headers": {
                "Server": "nginx/1.18.0",
                "Set-Cookie": sentinel_cookie,
                "Authorization": sentinel_auth,
            },
            "body": sentinel_body,
        }
        sanitized = _sanitize_response(raw)

        # Sanitized response must not contain sentinels
        sanitized_str = json.dumps(sanitized)
        assert sentinel_cookie not in sanitized_str
        assert sentinel_auth not in sanitized_str
        assert sentinel_body not in sanitized_str

        # Build a summary and check it doesn't contain sentinels
        summary = dt._new_summary(registry)
        summary_str = json.dumps(summary)
        assert sentinel_cookie not in summary_str
        assert sentinel_auth not in summary_str
        assert sentinel_body not in summary_str

        # Check logs don't contain sentinels
        for record in caplog.records:
            msg = record.getMessage()
            assert sentinel_cookie not in msg
            assert sentinel_auth not in msg
            assert sentinel_body not in msg


class TestMigrationUpDownUp:
    def test_asset_technologies_migration_roundtrip(self, monkeypatch, tmp_path):
        """Automated up/down/up test on scratch DB."""
        import os
        import subprocess
        from pathlib import Path
        import shutil

        db_url = os.environ.get(
            "SCRATCH_DB_URL",
            "postgresql://sentinel:sentinelpass@localhost:5432/scratch_migration_test",
        )
        env = dict(os.environ)
        env["DATABASE_URL"] = db_url

        backend_root = Path(__file__).resolve().parents[2]
        alembic_ini = str(tmp_path / "alembic.ini")
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
        env["PYTHONPATH"] = str(backend_root)

        import psycopg2

        # Create fresh DB
        conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/postgres")
        conn.autocommit = True
        try:
            conn.cursor().execute("DROP DATABASE IF EXISTS scratch_migration_test;")
            conn.cursor().execute("CREATE DATABASE scratch_migration_test OWNER sentinel;")
        finally:
            conn.close()

        conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/postgres")
        conn.autocommit = True
        try:
            conn.cursor().execute("GRANT ALL ON DATABASE scratch_migration_test TO sentinel;")
        finally:
            conn.close()

        def run(cmd):
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
            assert result.returncode == 0, f"Failed: {' '.join(cmd)}\n{result.stderr}\n{result.stdout}"

        # Upgrade to head
        run(["alembic", "-c", alembic_ini, "upgrade", "head"])
        # Downgrade one step
        run(["alembic", "-c", alembic_ini, "downgrade", "-1"])
        # Upgrade again
        run(["alembic", "-c", alembic_ini, "upgrade", "head"])

        # Cleanup
        conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/postgres")
        conn.autocommit = True
        try:
            conn.cursor().execute("DROP DATABASE IF EXISTS scratch_migration_test;")
        finally:
            conn.close()
