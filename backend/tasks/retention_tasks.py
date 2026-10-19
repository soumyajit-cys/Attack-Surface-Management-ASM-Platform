"""Retention purge (Phase 2.2).

``tasks.retention.purge_expired_rows`` (beat: daily, queue ``celery``)
deletes age-expired rows from four tables in bounded batches so retention
never stalls a worker tick:

====================  ==========================================
``alerts``            older than ``retention_alert_days``
``scan_history``      older than ``retention_scan_history_days``
``audit_logs``        older than ``retention_audit_log_days``
``asset_snapshots``   surplus beyond the newest
                      ``retention_snapshot_keep_newest`` per asset
====================  ==========================================

Guarantees (tested in ``tests/v3/test_retention.py``):

- **Age boundaries**: ``created_at``/``started_at`` strictly older than the
  cutoff go; anything at/inside the cutoff stays.
- **Per-org safety**: deletion is purely age-driven and global; a purge of
  one organisation's aged rows never touches another org's rows (fresh ones
  are outside the cutoff by definition).
- **Batch limit**: at most ``retention_batch_limit`` rows per table per run
  (0 = unlimited); a repeat beat tick converges — idempotent.
- **Snapshots**: the newest snapshot per asset is never deleted (rank > N
  deletes only surplus rows; N is clamped to >= 1).
- **Referenced rows**: no other table holds a foreign key to the purge
  targets; ``test_purge_targets_have_no_inbound_foreign_keys`` fails the
  suite if that ever changes and the purge must be re-sequenced first.
- **Dry run**: ``dry_run=True`` reports per-table counts of what *would* be
  deleted without deleting.
- **Logging**: one structured INFO line per run with per-table counts. The
  purge never writes audit-log rows about itself.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from models import Alert, AssetSnapshot, AuditLog, ScanHistory
from utils.database import SessionLocal
from utils.logger import logger
from workers.celery_app import celery

_AGE_RULES: tuple[tuple[str, type, str, str], ...] = (
    # (result_key, model, timestamp column, Settings window name)
    ("alerts", Alert, "created_at", "retention_alert_days"),
    ("scan_history", ScanHistory, "started_at", "retention_scan_history_days"),
    ("audit_logs", AuditLog, "created_at", "retention_audit_log_days"),
)


def _purge_age_table(
    db: Session,
    model: type,
    column: str,
    cutoff: datetime,
    limit: int,
    dry_run: bool,
) -> int:
    """Delete at most ``limit`` rows older than ``cutoff`` (oldest first)."""
    ts_col = getattr(model, column)
    id_rows = (
        db.query(model.id)
        .filter(ts_col < cutoff)
        .order_by(ts_col)
        .limit(limit)
        .all()
    )
    ids = [row[0] for row in id_rows]
    if not ids or dry_run:
        return len(ids)
    db.execute(delete(model).where(model.id.in_(ids)))
    return len(ids)


def _purge_surplus_snapshots(
    db: Session,
    keep_newest: int,
    limit: int,
    dry_run: bool,
) -> int:
    """Delete surplus snapshots: newest ``keep_newest`` per asset survive.

    Row numbers rank per asset newest-first (ties broken by id); only
    ``rn > keep_newest`` rows are eligible, so rank 1 (the newest) is
    structurally undeletable. ``keep_newest`` is clamped to >= 1.
    """
    keep = max(keep_newest, 1)
    rank_desc = AssetSnapshot.created_at.desc()
    id_desc = AssetSnapshot.id.desc()
    rank = (
        func.row_number()
        .over(partition_by=AssetSnapshot.asset_id,
              order_by=[rank_desc, id_desc])
        .label("rn")
    )
    ranked = db.query(AssetSnapshot.id.label("id"), rank).subquery()
    surplus = (
        db.query(ranked.c.id)
        .filter(ranked.c.rn > keep)
        .order_by(ranked.c.id)
        .limit(limit)
        .all()
    )
    ids = [row[0] for row in surplus]
    if not ids or dry_run:
        return len(ids)
    db.execute(delete(AssetSnapshot).where(AssetSnapshot.id.in_(ids)))
    return len(ids)


def purge_expired_records(
    db: Session,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
    limit: int | None = None,
    snapshot_keep_newest: int | None = None,
) -> dict[str, Any]:
    """One retention pass over all four tables. Returns per-table counts.

    ``now``/``limit``/``snapshot_keep_newest`` are injectable for tests;
    production callers rely on Settings (90/180/365 d, newest-50, 1000).
    """
    from app.core.config import settings as app_settings

    now = now or datetime.now(timezone.utc)
    if limit is None:
        limit = app_settings.retention_batch_size
    if snapshot_keep_newest is None:
        snapshot_keep_newest = app_settings.retention_snapshot_keep_newest

    counts: dict[str, Any] = {}
    for key, model, column, window_setting in _AGE_RULES:
        days = getattr(app_settings, window_setting)
        cutoff = now - timedelta(days=days)
        counts[key] = _purge_age_table(db, model, column, cutoff, limit, dry_run)

    counts["asset_snapshots"] = _purge_surplus_snapshots(
        db, snapshot_keep_newest, limit, dry_run
    )
    counts["dry_run"] = dry_run

    if not dry_run:
        db.commit()
    else:
        db.rollback()
    # Bulk DELETE bypasses the identity map; expire it so no later ORM read
    # trips over a deleted-but-still-referenced instance.
    db.expire_all()

    logger.info(
        "retention purge complete (dry_run=%s): "
        "alerts=%s scan_history=%s audit_logs=%s asset_snapshots=%s",
        dry_run,
        counts["alerts"],
        counts["scan_history"],
        counts["audit_logs"],
        counts["asset_snapshots"],
    )
    return counts


@celery.task(name="tasks.retention.purge_expired_rows")
def purge_expired_rows(dry_run: bool = False) -> dict[str, Any]:
    """Beat entry (daily): one bounded batch per table.

    Repeated ticks converge: ``retention_batch_limit`` rows per table per
    day is far above normal ingest for a single-host deployment, and the
    next tick simply continues where this one stopped.
    """
    db = SessionLocal()
    try:
        return purge_expired_records(db, dry_run=dry_run)
    finally:
        db.close()
