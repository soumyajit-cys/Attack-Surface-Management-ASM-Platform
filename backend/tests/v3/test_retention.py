"""Retention purge (Phase 2.2, item 2).

A Celery-beat task purges age-expired ``alerts``, ``audit_logs``,
``scan_history``, and surplus ``asset_snapshots`` (newest-50 per asset) in
bounded batches, with a dry-run mode, per-table Settings, and plain logging
(no audit rows about itself). These tests pin the age boundaries, per-org
safety, batch limit, idempotence, snapshot protection, the beat entry, and
the Settings drift surface. They run against the suite's scratch database.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from config import settings

NOW = datetime.now(timezone.utc)


def _old(days: float):
    return NOW - timedelta(days=days + 1)


def _fresh(days: float):
    return NOW - timedelta(days=max(days - 1, 0))


@pytest.fixture()
def two_orgs(db, org_factory):
    org_a, user_a = org_factory("retention-a", "retention-a", "a@retention.test")
    org_b, user_b = org_factory("retention-b", "retention-b", "b@retention.test")
    return org_a, org_b


def _add_alerts(db, org_id, n, created_at):
    from models.alert import Alert

    for i in range(n):
        db.add(Alert(organization_id=org_id, asset_id=_asset(db, org_id).id,
                     title=f"alert-{i}", severity="high",
                     message="[fixture]", created_at=created_at))
    db.commit()


def _asset(db, org_id):
    # One asset per org, created on the fly (idempotent enough for fixtures).
    from models.asset import Asset

    asset = db.query(Asset).filter(Asset.organization_id == org_id).first()
    if asset is None:
        asset = Asset(organization_id=org_id, name=f"asset-{org_id}",
                      criticality="dev", exposure="internet")
        db.add(asset)
        db.commit()
    return asset


def _table_counts(db):
    from models.alert import Alert
    from models.asset_snapshot import AssetSnapshot
    from models.audit_log import AuditLog
    from models.scan_history import ScanHistory

    return {
        "alerts": db.query(Alert).count(),
        "audit_logs": db.query(AuditLog).count(),
        "scan_history": db.query(ScanHistory).count(),
        "asset_snapshots": db.query(AssetSnapshot).count(),
    }


def _grid_rows(db, orgs, *, old_days, fresh_days):
    """One old + one fresh row per table per org."""
    from models.alert import Alert
    from models.asset_snapshot import AssetSnapshot
    from models.audit_log import AuditLog
    from models.scan_history import ScanHistory

    for org in orgs:
        asset = _asset(db, org.id)
        db.add(Alert(organization_id=org.id, asset_id=asset.id, title="old",
                     severity="high", message="[fixture]",
                     created_at=_old(old_days)))
        db.add(Alert(organization_id=org.id, asset_id=asset.id, title="fresh",
                     severity="high", message="[fixture]",
                     created_at=_fresh(fresh_days)))
        db.add(AuditLog(organization_id=org.id, actor="test", action="a",
                        details="d", created_at=_old(old_days)))
        db.add(AuditLog(organization_id=org.id, actor="test", action="a",
                        details="d", created_at=_fresh(fresh_days)))
        db.add(ScanHistory(organization_id=org.id, asset_id=asset.id,
                           target="old.example", status="completed",
                           started_at=_old(old_days)))
        db.add(ScanHistory(organization_id=org.id, asset_id=asset.id,
                           target="fresh.example", status="completed",
                           started_at=_fresh(fresh_days)))
        db.add(AssetSnapshot(asset_id=asset.id, snapshot={},
                             created_at=_old(old_days)))
        db.add(AssetSnapshot(asset_id=asset.id, snapshot={},
                             created_at=_fresh(fresh_days)))
    db.commit()


def _purge(db, **kwargs):
    from tasks.retention_tasks import purge_expired_records

    kwargs.setdefault("now", NOW)
    return purge_expired_records(db, **kwargs)


# ── Settings surface ──────────────────────────────────────────────────────────

def test_retention_settings_defaults():
    assert settings.retention_alert_days == 90
    assert settings.retention_scan_history_days == 180
    assert settings.retention_audit_log_days == 365
    assert settings.retention_snapshot_keep_newest == 50
    assert settings.retention_batch_limit >= 1


def test_retention_settings_documented():
    """Settings fields honour convention: README + .env.example drift tests."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    readme = root / "README.md"
    env_example = root / ".env.example"
    for field in ["RETENTION_ALERT_DAYS", "RETENTION_SCAN_HISTORY_DAYS",
                  "RETENTION_AUDIT_LOG_DAYS", "RETENTION_SNAPSHOT_KEEP_NEWEST",
                  "RETENTION_BATCH_LIMIT"]:
        assert field in readme.read_text(), f"README missing {field}"
        assert field in env_example.read_text(), f".env.example missing {field}"
        assert field in (root / "backend" / ".env.example").read_text(), (
            f"backend/.env.example missing {field}"
        )


# ── Core behaviour ────────────────────────────────────────────────────────────

def test_purge_age_boundaries(db, two_orgs):
    """Rows strictly older than the cutoff go; boundary-adjacent rows stay."""
    org_a, org_b = two_orgs
    _grid_rows(db, [org_a, org_b], old_days=90, fresh_days=90)
    before = _table_counts(db)
    assert before["alerts"] == 4  # 2 orgs x (old + fresh)

    result = _purge(db)

    assert result["alerts"] == 2, "only the two 90d+-old alerts are deleted"
    after = _table_counts(db)
    assert after["alerts"] == 2
    from models.alert import Alert

    titles = {a.title for a in db.query(Alert).all()}
    assert titles == {"fresh"}


def test_purge_per_table_ages_differ(db, two_orgs):
    """scan_history's 180 d window does not swallow fresh 90 d-old rows."""
    org_a, org_b = two_orgs
    _scan_history_grid(db, [org_a, org_b], old_days=90, fresh_days=90)
    result = _purge(db)
    assert result["scan_history"] == 0
    assert result["alerts"] == 0  # 90 d is the alerts cutoff — none older here
    from models.scan_history import ScanHistory

    assert db.query(ScanHistory).count() == 4  # 2 orgs x 2 rows, all kept


def _scan_history_grid(db, orgs, *, old_days, fresh_days):
    from models.scan_history import ScanHistory

    for org in orgs:
        asset = _asset(db, org.id)
        db.add(ScanHistory(organization_id=org.id, asset_id=asset.id,
                           target="old.example", status="completed",
                           started_at=_old(old_days)))
        db.add(ScanHistory(organization_id=org.id, asset_id=asset.id,
                           target="fresh.example", status="completed",
                           started_at=_fresh(fresh_days)))
    db.commit()


def test_purge_per_org_safety(db, two_orgs):
    """Org B's fresh rows never die because org A's rows aged out."""
    from models.alert import Alert
    from models.scan_history import ScanHistory

    org_a, org_b = two_orgs
    # Org A: rows older than every window (365 d+). Org B: created NOW —
    # no window can touch them.
    asset_a = _asset(db, org_a.id)
    asset_b = _asset(db, org_b.id)
    db.add(Alert(organization_id=org_a.id, asset_id=asset_a.id, title="old-A",
                 severity="high", message="[fixture]",
                 created_at=_old(400)))
    db.add(ScanHistory(organization_id=org_a.id, asset_id=asset_a.id,
                       target="old.example", status="completed",
                       started_at=_old(400)))
    db.add(Alert(organization_id=org_b.id, asset_id=asset_b.id, title="fresh-B",
                 severity="high", message="[fixture]", created_at=NOW))
    db.add(ScanHistory(organization_id=org_b.id, asset_id=asset_b.id,
                       target="fresh.example", status="completed",
                       started_at=NOW))
    db.commit()

    result = _purge(db)

    # Both orgs' aged rows go (global, age-driven) — fresh ones never.
    assert result["alerts"] == 1 and result["scan_history"] == 1
    titles = {a.title for a in db.query(Alert).all()}
    assert titles == {"fresh-B"}
    targets = {t for (t,) in db.query(ScanHistory.target).all()}
    assert targets == {"fresh.example"}


def test_purge_batch_limit_and_idempotence(db, two_orgs):
    from models.alert import Alert

    org_a, org_b = two_orgs
    # 10 old alerts; batch limit 3 → three runs, then a no-op fourth run.
    for i in range(10):
        db.add(Alert(organization_id=org_a.id, asset_id=_asset(db, org_a.id).id,
                     title=f"old-{i}", severity="high", message="[fixture]",
                     created_at=_old(91)))
    db.commit()

    first = _purge(db, limit=3)
    assert first["alerts"] == 3
    second = _purge(db, limit=3)
    assert second["alerts"] == 3
    third = _purge(db, limit=3)
    assert third["alerts"] == 3
    assert db.query(Alert).count() == 1
    fourth = _purge(db, limit=3)
    assert fourth["alerts"] == 1
    fifth = _purge(db, limit=3)
    assert fifth["alerts"] == 0, "idempotent: nothing left to purge"
    assert db.query(Alert).count() == 0


def test_purge_dry_run_deletes_nothing(db, two_orgs):
    from models.alert import Alert

    org_a, _ = two_orgs
    db.add(Alert(organization_id=org_a.id, asset_id=_asset(db, org_a.id).id,
                 title="ancient", severity="high", message="[fixture]",
                 created_at=_old(91)))
    db.commit()

    result = _purge(db, dry_run=True, limit=5)

    assert result["alerts"] == 1, "dry-run reports what WOULD be deleted"
    assert result["dry_run"] is True
    assert db.query(Alert).count() == 1, "dry-run must not delete"
    result = _purge(db, limit=5)
    assert result["alerts"] == 1 and result["dry_run"] is False
    assert db.query(Alert).count() == 0


# ── Snapshot protection ───────────────────────────────────────────────────────

def test_snapshots_keep_newest_per_asset(db, two_orgs):
    from models.asset_snapshot import AssetSnapshot

    org_a, org_b = two_orgs
    asset_a = _asset(db, org_a.id)
    asset_b = _asset(db, org_b.id)
    ids_a = []
    for i in range(6):
        snap = AssetSnapshot(asset_id=asset_a.id, snapshot={"i": i},
                             created_at=NOW - timedelta(hours=6 - i))
        db.add(snap)
        ids_a.append(snap)
    db.flush()
    ids_b = []
    for i in range(3):
        snap = AssetSnapshot(asset_id=asset_b.id, snapshot={"i": i},
                             created_at=NOW - timedelta(hours=9 - i))
        db.add(snap)
        ids_b.append(snap)
    db.commit()
    kept_expected = set(ids_a[3:])   # newest 3 snapshots of asset A
    kept_ids = {s.id for s in kept_expected}

    result = _purge(db, snapshot_keep_newest=3, limit=100)

    assert result["asset_snapshots"] == 3, "asset A had 6, keep 3 → 3 deleted"
    remaining = {s.id for s in db.query(AssetSnapshot).filter(
        AssetSnapshot.asset_id == asset_a.id).all()}
    assert remaining == kept_ids, "newest 3 of asset A survive"
    assert db.query(AssetSnapshot).filter(
        AssetSnapshot.asset_id == asset_b.id).count() == 3, (
        "asset B (3 snapshots) is untouched: per-asset accounting, not global"
    )


def test_snapshots_newest_never_deleted(db, two_orgs):
    from models.asset_snapshot import AssetSnapshot

    org_a, _ = two_orgs
    asset_a = _asset(db, org_a.id)
    snaps = []
    for i in range(8):
        s = AssetSnapshot(asset_id=asset_a.id, snapshot={"i": i},
                          created_at=NOW - timedelta(days=8 - i))
        db.add(s)
        snaps.append(s)
    db.commit()

    result = _purge(db, snapshot_keep_newest=2, limit=100)

    assert result["asset_snapshots"] == 6
    remaining = [s.id for s in db.query(AssetSnapshot).filter(
        AssetSnapshot.asset_id == asset_a.id).all()]
    assert snaps[-1].id in remaining, "the NEWEST snapshot must never die"
    assert snaps[-2].id in remaining


def test_purge_never_writes_audit_rows(db, two_orgs):
    from models.audit_log import AuditLog

    org_a, org_b = two_orgs
    fresh_grid(db, [org_a, org_b], days=1)
    before = db.query(AuditLog).count()
    _purge(db)
    after = db.query(AuditLog).count()
    assert after == before, "the purge must not audit-log itself"


def fresh_grid(db, orgs, *, days):
    _grid_rows(db, orgs, old_days=days, fresh_days=days)


# ── Referenced-row safety + wiring ────────────────────────────────────────────

def test_purge_targets_have_no_inbound_foreign_keys():
    """If another table ever references a purge target, the purge would
    violate 'never delete a referenced row' — fail loudly at test time."""
    from models import Base

    targets = {"alerts", "audit_logs", "scan_history", "asset_snapshots"}
    for table in Base.metadata.sorted_tables:
        for fk in table.foreign_keys:
            target_table = fk.column.table.name
            assert target_table not in targets, (
                f"{table.name}.{fk.parent.name} references purge target "
                f"{target_table!r}; update tasks/retention_tasks.py before "
                "adding the dependency"
            )


def test_beat_schedule_entry_registered():
    from workers.celery_app import celery

    entry = celery.conf.beat_schedule.get("purge-expired-rows")
    assert entry is not None, "beat schedule must include purge-expired-rows"
    assert entry["task"] == "tasks.retention.purge_expired_rows"
    assert "tasks.retention_tasks" in celery.conf.include
    assert celery.conf.task_routes.get("tasks.retention.*") == {"queue": "celery"}
