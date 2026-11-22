"""Phase 4a tests: findings schema, upsert helper, migration."""

import hashlib
import re

import pytest


class TestGrepNoDirectFindingInserts:
    def test_no_finding_outside_allowed(self):
        """Fail if Finding( appears outside models/, upsert.py, tests, and alert builders."""
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[2]
        allowed = {
            "models/finding.py",
            "services/findings/upsert.py",
        }
        # Also allow alerting_service.py:421 and api/v1/alerting.py:385
        allowed_alert = {
            "services/alerts/alerting_service.py",
            "app/api/v1/alerting.py",
        }
        violations = []
        for py in root.rglob("*.py"):
            rel = str(py.relative_to(root))
            if "tests" in rel or "__pycache__" in rel:
                continue
            if rel in allowed or rel in allowed_alert:
                continue
            text = py.read_text()
            if "Finding(" in text:
                violations.append(rel)
        assert not violations, f"Direct Finding( outside allowed files: {violations}"


class TestUpsertHelper:
    def test_insert(self, db, org_factory):
        from services.findings.upsert import upsert_finding
        from models.finding import Finding
        from models.asset import Asset

        org, _ = org_factory("ins-org", "insuser", "ins@example.com")
        asset = Asset(organization_id=org.id, name="ins-asset")
        db.add(asset)
        db.flush()

        f, created = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:key1", title="Test", severity="high")
        db.commit()
        assert f is not None
        assert f.title == "Test"
        assert f.severity == "high"
        assert created is True

    def test_update_preserves_workflow_state(self, db, org_factory):
        from services.findings.upsert import upsert_finding
        from models.finding import Finding

        org, _ = org_factory("wf-org", "wfuser", "wf@example.com")
        asset = None
        from models.asset import Asset
        asset = Asset(organization_id=org.id, name="wf-asset")
        db.add(asset)
        db.flush()

        f1, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:wf", title="WF", severity="high", status="open")
        db.commit()
        # Set workflow state
        f1.status = "accepted_risk"
        f1.assigned_to = None
        db.commit()

        # Upsert again (scan-driven update)
        f2, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:wf", title="WF", severity="medium")
        db.commit()
        db.expire_all()
        f3 = db.query(Finding).filter(Finding.id == f2.id).first()
        assert f3.status == "accepted_risk"  # preserved
        assert f3.severity == "medium"  # updated

    def test_partial_fields_dont_null(self, db, org_factory):
        from services.findings.upsert import upsert_finding
        from models.finding import Finding

        org, _ = org_factory("pf-org", "pfuser", "pf@example.com")
        from models.asset import Asset
        asset = Asset(organization_id=org.id, name="pf-asset")
        db.add(asset)
        db.flush()

        upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:pf", title="PF", severity="high", description="desc1")
        db.commit()

        # Update only severity, description should be preserved
        upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:pf", severity="medium")
        db.commit()
        db.expire_all()

        f = db.query(Finding).filter(Finding.dedupe_key == "test:pf").first()
        assert f.severity == "medium"
        assert f.description == "desc1"  # not nulled

    def test_empty_update_set(self, db, org_factory):
        from services.findings.upsert import upsert_finding
        from models.finding import Finding

        org, _ = org_factory("eu-org", "euuser", "eu@example.com")
        from models.asset import Asset
        asset = Asset(organization_id=org.id, name="eu-asset")
        db.add(asset)
        db.flush()

        f1, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:eu", title="EU", severity="high")
        db.commit()
        orig_updated = f1.updated_at

        # Empty update (no fields) should not error
        f2, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:eu")
        db.commit()
        assert f2 is not None

    def test_last_seen_updated(self, db, org_factory):
        from services.findings.upsert import upsert_finding
        from models.finding import Finding
        from datetime import datetime, timezone

        org, _ = org_factory("ls-org", "lsuser", "ls@example.com")
        from models.asset import Asset
        asset = Asset(organization_id=org.id, name="ls-asset")
        db.add(asset)
        db.flush()

        f1, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:ls", title="LS", severity="high")
        db.commit()
        first_last_seen = f1.last_seen_at

        f2, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:ls", title="LS", severity="high")
        db.commit()
        db.expire_all()
        f3 = db.query(Finding).filter(Finding.dedupe_key == "test:ls").first()
        assert f3.last_seen_at >= first_last_seen

    def test_fresh_instance(self, db, org_factory):
        from services.findings.upsert import upsert_finding

        org, _ = org_factory("fi-org", "fiuser", "fi@example.com")
        from models.asset import Asset
        asset = Asset(organization_id=org.id, name="fi-asset")
        db.add(asset)
        db.flush()

        f, _ = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:fi", title="FI", severity="high")
        assert f is not None
        assert f.id is not None

    def test_concurrency(self, db, org_factory):
        import threading
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from models.asset import Asset
        from services.findings.upsert import upsert_finding

        org, _ = org_factory("cc-org", "ccuser", "cc@example.com")
        asset = Asset(organization_id=org.id, name="cc-asset")
        db.add(asset)
        db.commit()
        asset_id = asset.id
        org_id = org.id

        db_url = __import__("os").environ.get("DATABASE_URL", str(db.bind.url))
        engine = create_engine(db_url)
        Session = sessionmaker(bind=engine)
        barrier = threading.Barrier(2)
        errors = []

        def worker():
            try:
                s = Session()
                barrier.wait(timeout=5)
                upsert_finding(s, org_id=org_id, asset_id=asset_id, dedupe_key="test:cc", title="CC", severity="high")
                s.commit()
                s.close()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert not errors, f"Errors: {errors}"


class TestLegacyDedupeKey:
    def test_legacy_key_format(self):
        from services.findings.upsert import legacy_dedupe_key
        key = legacy_dedupe_key("Open Port 80")
        assert key.startswith("legacy:")
        assert len(key) == len("legacy:") + 32


class TestMigrationSchema:
    def test_tables_exist(self, db):
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        tables = inspector.get_table_names()
        assert "finding_events" in tables
        assert "org_sla_config" in tables
        assert "scan_module_runs" in tables

    def test_findings_columns(self, db):
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        cols = {c["name"] for c in inspector.get_columns("findings")}
        for col in ("source_module", "target_host", "first_seen_at", "last_seen_at",
                    "version", "status", "assigned_to", "due_date", "suppression_reason",
                    "suppressed_by", "suppressed_until", "sla_alerted_at"):
            assert col in cols, f"Missing column: {col}"

    def test_unique_index_exists(self, db):
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        indexes = {i["name"] for i in inspector.get_indexes("findings")}
        assert "uq_findings_org_asset_dedupe" in indexes

    def test_fk_exists(self, db):
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        fks = inspector.get_foreign_keys("findings")
        fk_names = {fk["name"] for fk in fks}
        assert "fk_findings_assigned_to" in fk_names or any("assigned_to" in str(fk) for fk in fks)


class TestMigrationUpDownUp:
    def test_migration_roundtrip(self, monkeypatch, tmp_path):
        import os
        import sys
        import subprocess
        import shutil
        from pathlib import Path

        db_url = "postgresql://sentinel:sentinelpass@localhost:5432/scratch_migration_test"
        env = dict(os.environ)
        env["DATABASE_URL"] = db_url

        backend_root = Path(__file__).resolve().parents[2]
        alembic_ini = str(tmp_path / "alembic.ini")
        shutil.copy(backend_root / "alembic.ini", alembic_ini)
        ini_text = Path(alembic_ini).read_text()
        ini_text = ini_text.replace("script_location = migrations", f"script_location = {backend_root}/migrations")
        ini_text = ini_text.replace("sqlalchemy.url =", f"sqlalchemy.url = {db_url}")
        ini_text = ini_text.replace("prepend_sys_path = .", f"prepend_sys_path = {backend_root}")
        Path(alembic_ini).write_text(ini_text)
        env["PYTHONPATH"] = str(backend_root)

        import psycopg2
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
        run([sys.executable, "-m", "alembic", "-c", alembic_ini, "upgrade", "head"])
        # Downgrade one step
        run([sys.executable, "-m", "alembic", "-c", alembic_ini, "downgrade", "-1"])
        # Upgrade again
        run([sys.executable, "-m", "alembic", "-c", alembic_ini, "upgrade", "head"])

        # Cleanup
        conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/postgres")
        conn.autocommit = True
        try:
            conn.cursor().execute("DROP DATABASE IF EXISTS scratch_migration_test;")
        finally:
            conn.close()


class TestUpsertDbError:
    def test_db_error_propagates_no_rollback(self, db, org_factory):
        """A DB error propagates and does not roll back unrelated rows staged in the same session."""
        from services.findings.upsert import upsert_finding
        from models.finding import Finding
        from models.asset import Asset
        import pytest

        org, _ = org_factory("dbe-org", "dbeuser", "dbe@example.com")
        asset = Asset(organization_id=org.id, name="dbe-asset")
        db.add(asset)
        db.flush()

        # Stage an unrelated row
        unrelated = Finding(
            organization_id=org.id,
            asset_id=asset.id,
            dedupe_key="unrelated:key",
            title="Unrelated",
            severity="low",
            first_seen_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        db.add(unrelated)
        db.flush()

        # Trigger a failing upsert using a savepoint so the transaction isn't aborted
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            with db.begin_nested():
                upsert_finding(db, org_id=org.id, asset_id=99999, dedupe_key="fail:key", title="Fail", severity="high")

        # The unrelated row should still be staged (not rolled back)
        db.expire_all()
        count = db.query(Finding).filter(Finding.dedupe_key == "unrelated:key").count()
        assert count == 1, "Unrelated staged row was rolled back"

    def test_cve_ids_roundtrip(self, db, org_factory):
        """cve_ids round-trips as a list."""
        from services.findings.upsert import upsert_finding
        from models.asset import Asset

        org, _ = org_factory("cve-org", "cveuser", "cve@example.com")
        asset = Asset(organization_id=org.id, name="cve-asset")
        db.add(asset)
        db.flush()

        cve_list = ["CVE-2024-0001", "CVE-2024-0002"]
        f, created = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:cve", title="CVE Test", severity="high", cve_ids=cve_list)
        db.commit()
        db.expire_all()

        f2 = db.query(__import__("models.finding", fromlist=["Finding"]).Finding).filter(
            __import__("models.finding", fromlist=["Finding"]).Finding.dedupe_key == "test:cve"
        ).first()
        assert f2.cve_ids == cve_list

        # Update with different list
        new_list = ["CVE-2024-0003"]
        upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:cve", title="CVE Test", severity="high", cve_ids=new_list)
        db.commit()
        db.expire_all()

        f3 = db.query(__import__("models.finding", fromlist=["Finding"]).Finding).filter(
            __import__("models.finding", fromlist=["Finding"]).Finding.dedupe_key == "test:cve"
        ).first()
        assert f3.cve_ids == new_list

    def test_created_flag(self, db, org_factory):
        """created is True on insert, False on conflict."""
        from services.findings.upsert import upsert_finding
        from models.asset import Asset

        org, _ = org_factory("cf-org", "cfuser", "cf@example.com")
        asset = Asset(organization_id=org.id, name="cf-asset")
        db.add(asset)
        db.flush()

        f1, created1 = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:cf", title="CF", severity="high")
        db.commit()
        assert created1 is True

        f2, created2 = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:cf", title="CF", severity="high")
        db.commit()
        assert created2 is False

    def test_empty_update_set(self, db, org_factory):
        """Empty update_set path: second call returns created=False."""
        from services.findings.upsert import upsert_finding
        from models.asset import Asset

        org, _ = org_factory("eu-org2", "euuser2", "eu2@example.com")
        asset = Asset(organization_id=org.id, name="eu-asset2")
        db.add(asset)
        db.flush()

        upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:eu2", title="EU2", severity="high")
        db.commit()

        # Call with no updatable fields
        f, created = upsert_finding(db, org_id=org.id, asset_id=asset.id, dedupe_key="test:eu2")
        db.commit()
        assert created is False
        assert f is not None

    def test_concurrency_20x(self, db, org_factory):
        """Two threads, barrier, same key, 20 times: exactly one created=True each."""
        import threading
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from models.asset import Asset
        from services.findings.upsert import upsert_finding
        import os

        org, _ = org_factory("conc-org2", "concuser2", "conc2@example.com")
        asset = Asset(organization_id=org.id, name="conc-asset2")
        db.add(asset)
        db.commit()
        org_id = org.id
        asset_id = asset.id

        db_url = os.environ.get("DATABASE_URL", str(db.bind.url))
        engine = create_engine(db_url)
        Session = sessionmaker(bind=engine)

        for i in range(20):
            barrier = threading.Barrier(2)
            results = []
            errors = []

            def worker(barrier=barrier, i=i, results=results, errors=errors):
                try:
                    s = Session()
                    barrier.wait(timeout=5)
                    f, created = upsert_finding(s, org_id=org_id, asset_id=asset_id, dedupe_key=f"test:conc20:{i}", title="CC", severity="high")
                    s.commit()
                    results.append(created)
                    s.close()
                except Exception as e:
                    errors.append(e)

            t1 = threading.Thread(target=worker)
            t2 = threading.Thread(target=worker)
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)

            assert not errors, f"Errors: {errors}"
            assert sum(results) == 1, f"Expected exactly one created=True, got {results}"

        # Verify exactly one row per key
        s = Session()
        count = s.query(__import__("models.finding", fromlist=["Finding"]).Finding).filter(
            __import__("models.finding", fromlist=["Finding"]).Finding.dedupe_key.like("test:conc20:%")
        ).count()
        assert count == 20
        s.close()
