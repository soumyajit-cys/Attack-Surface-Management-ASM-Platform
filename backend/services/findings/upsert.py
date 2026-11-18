"""Single upsert helper for Finding persistence.

All writers (discovery_tasks, cve_tasks, etc.) MUST use this helper
instead of direct Finding() inserts.
"""

from __future__ import annotations

import hashlib
from typing import Any
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from models.finding import Finding


def upsert_finding(
    db: Session,
    org_id: int,
    asset_id: int,
    dedupe_key: str,
    **fields: Any,
) -> tuple[Finding, bool]:
    """Insert or update a finding by (org_id, asset_id, dedupe_key).

    Returns (finding, created) where created is True if a new row was
    inserted, False if an existing row was updated.

    Uses a pre-query to check existence, then INSERT ... ON CONFLICT.
    The created flag is determined by whether the row existed before
    the upsert (equivalent to xmax = 0 for newly inserted rows).
    """
    now = datetime.now(timezone.utc)

    # Check if row exists before upsert (for created flag).
    existing = db.execute(
        text(
            "SELECT id FROM findings "
            "WHERE organization_id = :org AND asset_id = :asset AND dedupe_key = :dk"
        ),
        {"org": org_id, "asset": asset_id, "dk": dedupe_key},
    ).fetchone()
    was_created = existing is None

    # Build insert values.
    values: dict[str, Any] = {
        "organization_id": org_id,
        "asset_id": asset_id,
        "dedupe_key": dedupe_key,
        "title": fields.get("title", ""),
        "severity": fields.get("severity", "info"),
        "category": fields.get("category", "general"),
        "first_seen_at": fields.get("first_seen_at", now),
        "last_seen_at": fields.get("last_seen_at", now),
        "last_seen_scan_id": fields.get("last_seen_scan_id"),
        "updated_at": now,
    }
    for key in ("description", "recommendation", "confidence", "source_module", "target_host", "cve_ids", "cvss_score"):
        if fields.get(key) is not None:
            values[key] = fields[key]

    # On conflict: update only provided (non-None) fields.
    update_set = {}
    for key in ("title", "severity", "category", "description", "recommendation", "confidence", "source_module", "target_host", "cve_ids", "cvss_score"):
        if fields.get(key) is not None:
            update_set[key] = fields[key]
    update_set["last_seen_at"] = fields.get("last_seen_at", now)
    if fields.get("last_seen_scan_id") is not None:
        update_set["last_seen_scan_id"] = fields["last_seen_scan_id"]
    update_set["updated_at"] = now

    stmt = pg_insert(Finding).values(**values)
    if update_set:
        stmt = stmt.on_conflict_do_update(
            index_elements=["organization_id", "asset_id", "dedupe_key"],
            set_=update_set,
        )
    else:
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["organization_id", "asset_id", "dedupe_key"],
        )
    db.execute(stmt)
    db.flush()

    finding = (
        db.query(Finding)
        .filter(
            Finding.organization_id == org_id,
            Finding.asset_id == asset_id,
            Finding.dedupe_key == dedupe_key,
        )
        .first()
    )
    if finding is not None:
        db.refresh(finding)
    return finding, was_created


def legacy_dedupe_key(title: str) -> str:
    """Generate a dedupe key for legacy title-keyed findings."""
    return f"legacy:{hashlib.md5(title.encode()).hexdigest()}"
PYEOF
echo "Done"