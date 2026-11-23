"""Migration data tests for Phase 4a findings schema."""

import hashlib
import os
import subprocess
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

import psycopg2
import pytest

from tests.db_guard import assert_safe_test_db


class TestFindingsMigrationData:
    @staticmethod
    def _run(cmd, env):
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
        assert result.returncode == 0, f"Failed: {' '.join(cmd)}\n{result.stderr}\n{result.stdout}"

    def test_migration_data(self, monkeypatch, tmp_path):
        admin_url = os.environ.get("TEST_ADMIN_DATABASE_URL")
        if not admin_url:
            pytest.fail("TEST_ADMIN_DATABASE_URL is not set")

        app_url = os.environ.get("DATABASE_URL")
        if not app_url:
            pytest.fail("DATABASE_URL is not set")

        # Parse admin URL
        admin_parsed = urlparse(admin_url)
        admin_host = admin_parsed.hostname or "127.0.0.1"
        admin_port = admin_parsed.port or 5432
        admin_user = admin_parsed.username or "postgres"
        admin_password = admin_parsed.password or ""
        admin_dbname = admin_parsed.path.lstrip("/") or "postgres"

        # Parse app URL
        app_parsed = urlparse(app_url)
        app_host = app_parsed.hostname or "127.0.0.1"
        app_port = app_parsed.port or 5432
        app_user = app_parsed.username or "sentinel"
        app_password = app_parsed.password or ""
        app_dbname = app_parsed.path.lstrip("/") or "scratch_check"

        # Scratch DB name
        scratch_db_name = "scratch_migration_data_test"
        assert scratch_db_name.startswith("scratch_")
        assert_safe_test_db(f"postgresql://{app_user}:{app_password}@{app_host}:{app_port}/{scratch_db_name}")

        # Build admin connection string (use IP literal)
        admin_conn_str = f"postgresql://{admin_user}:{admin_password}@{admin_host}:{admin_port}/{admin_dbname}"
        app_conn_str = f"postgresql://{app_user}:{app_password}@{app_host}:{app_port}/{scratch_db_name}"

        env = dict(os.environ)
        env["DATABASE_URL"] = app_conn_str

        backend_root = Path(__file__).resolve().parents[2]
        alembic_ini = str(tmp_path / "alembic.ini")
        shutil.copy(backend_root / "alembic.ini", alembic_ini)
        ini_text = Path(alembic_ini).read_text()
        ini_text = ini_text.replace("script_location = migrations", f"script_location = {backend_root}/migrations")
        ini_text = ini_text.replace("sqlalchemy.url =", f"sqlalchemy.url = {app_conn_str}")
        ini_text = ini_text.replace("prepend_sys_path = .", f"prepend_sys_path = {backend_root}")
        Path(alembic_ini).write_text(ini_text)
        env["PYTHONPATH"] = str(backend_root)

        # Create fresh DB with retry
        for attempt in range(10):
            try:
                conn = psycopg2.connect(admin_conn_str)
                conn.autocommit = True
                try:
                    cur = conn.cursor()
                    cur.execute(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{scratch_db_name}' AND pid <> pg_backend_pid();")
                    cur.execute(f"DROP DATABASE IF EXISTS {scratch_db_name};")
                    cur.execute(f"CREATE DATABASE {scratch_db_name} OWNER {app_user};")
                finally:
                    conn.close()
                break
            except Exception:
                pass
        else:
            raise RuntimeError(f"Could not create {scratch_db_name}")

        # Grant access
        conn = psycopg2.connect(admin_conn_str)
        conn.autocommit = True
        try:
            conn.cursor().execute(f"GRANT ALL ON DATABASE {scratch_db_name} TO {app_user};")
        finally:
            conn.close()

        # Upgrade to revision before e7f8a9b0c1d2
        self._run([sys.executable, "-m", "alembic", "-c", alembic_ini, "upgrade", "b2c3d4e5f6a7"], env)

        # Seed data
        import sqlalchemy as sa
        from sqlalchemy import create_engine, text
        engine = create_engine(app_conn_str)
        with engine.begin() as c:
            c.execute(text("INSERT INTO organizations (id, name, require_2fa) VALUES (1, 'org', false)"))
            c.execute(text("INSERT INTO assets (id, organization_id, name, criticality, exposure) VALUES (1, 1, 'asset', 'dev', 'internet')"))
            c.execute(text("INSERT INTO domains (id, organization_id, asset_id, domain) VALUES (1, 1, 1, 'a.com')"))
            c.execute(text("INSERT INTO domains (id, organization_id, asset_id, domain) VALUES (2, 1, 1, 'b.com')"))
            # Duplicate group: 3 rows
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, description, created_at, updated_at) VALUES (1, 1, 1, 'Dup', 'low', 'oldest', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, description, created_at, updated_at) VALUES (2, 1, 1, 'Dup', 'medium', 'mid', '2026-01-02', '2026-01-02')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, description, created_at, updated_at) VALUES (3, 1, 1, 'Dup', 'high', 'newest desc', '2026-01-03', '2026-01-03')"))
            # Two domains with old-style email keys
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, description, dedupe_key, created_at, updated_at) VALUES (4, 1, 1, 'SPF', 'low', 'a.com spf', 'email_security:spf_missing', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, description, dedupe_key, created_at, updated_at) VALUES (5, 1, 1, 'SPF', 'low', 'b.com spf with _dmarc.a.com decoy', 'email_security:spf_missing', '2026-01-01', '2026-01-01')"))
            # One row per prefix
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, dedupe_key, created_at, updated_at) VALUES (6, 1, 1, 'T', 'low', 'email_security:x:y.com', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, dedupe_key, created_at, updated_at) VALUES (7, 1, 1, 'T', 'low', 'subdomain_takeover:GitHub Pages:h', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, dedupe_key, created_at, updated_at) VALUES (8, 1, 1, 'T', 'low', 'tech_fingerprint:WordPress:h', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, dedupe_key, created_at, updated_at) VALUES (9, 1, 1, 'T', 'low', 'exposed_services:redis_port_open:h:6379', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, dedupe_key, created_at, updated_at) VALUES (10, 1, 1, 'T', 'low', 'exposed_services:admin_panel:h:80:/admin', '2026-01-01', '2026-01-01')"))
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, dedupe_key, created_at, updated_at) VALUES (11, 1, 1, 'T', 'low', 'ssl_expired:h', '2026-01-01', '2026-01-01')"))
            # Legacy row with no key
            c.execute(text("INSERT INTO findings (id, organization_id, asset_id, title, severity, created_at, updated_at) VALUES (12, 1, 1, 'Legacy Title', 'low', '2026-01-01', '2026-01-01')"))

        # Upgrade to head
        self._run([sys.executable, "-m", "alembic", "-c", alembic_ini, "upgrade", "head"], env)

        # Assertions
        with engine.connect() as c:
            # Duplicate group merged
            rows = c.execute(text("SELECT id, severity, description, first_seen_at FROM findings WHERE title = 'Dup'")).fetchall()
            assert len(rows) == 1, f"Expected 1 dup row, got {len(rows)}"
            assert rows[0][1] == "high"
            assert rows[0][2] == "newest desc"
            assert str(rows[0][3]).startswith("2026-01-01")

            # a.com and b.com remain separate
            a_row = c.execute(text("SELECT dedupe_key FROM findings WHERE description LIKE '%a.com spf%'")).fetchone()
            b_row = c.execute(text("SELECT dedupe_key FROM findings WHERE description LIKE '%b.com spf%'")).fetchone()
            assert a_row is not None and "a.com" in a_row[0]
            assert b_row is not None and "b.com" in b_row[0]

            # source_module/target_host per prefix
            def check_prefix(key, expected_module, expected_host):
                r = c.execute(text(f"SELECT source_module, target_host FROM findings WHERE dedupe_key = '{key}'")).fetchone()
                if r:
                    assert r[0] == expected_module, f"{key}: expected {expected_module}, got {r[0]}"
                    assert r[1] == expected_host, f"{key}: expected {expected_host}, got {r[1]}"

            check_prefix("email_security:x:y.com", "email_security", "y.com")
            check_prefix("subdomain_takeover:GitHub Pages:h", "subdomain_takeover", "h")
            check_prefix("tech_fingerprint:WordPress:h", "tech_fingerprint", "h")
            check_prefix("exposed_services:redis_port_open:h:6379", "exposed_services", "h")
            check_prefix("exposed_services:admin_panel:h:80:/admin", "exposed_services", "h")
            check_prefix("ssl_expired:h", "ssl_scan", "h")

            # Legacy row
            legacy = c.execute(text("SELECT source_module, dedupe_key FROM findings WHERE title = 'Legacy Title'")).fetchone()
            assert legacy[0] is None
            expected_key = "legacy:" + hashlib.md5(b"Legacy Title").hexdigest()
            assert legacy[1] == expected_key

            # sla_alerted_at set for all pre-existing
            rows = c.execute(text("SELECT sla_alerted_at FROM findings")).fetchall()
            for r in rows:
                assert r[0] is not None

            # due_date set per severity
            rows = c.execute(text("SELECT severity, due_date FROM findings WHERE title = 'Dup'")).fetchone()
            assert rows[1] is not None

        # Downgrade + upgrade
        self._run([sys.executable, "-m", "alembic", "-c", alembic_ini, "downgrade", "-1"], env)
        self._run([sys.executable, "-m", "alembic", "-c", alembic_ini, "upgrade", "head"], env)

        # Cleanup
        conn = psycopg2.connect(admin_conn_str)
        conn.autocommit = True
        try:
            for _ in range(10):
                try:
                    conn.cursor().execute(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{scratch_db_name}' AND pid <> pg_backend_pid();")
                    conn.cursor().execute(f"DROP DATABASE IF EXISTS {scratch_db_name};")
                    break
                except Exception:
                    pass
        finally:
            conn.close()
