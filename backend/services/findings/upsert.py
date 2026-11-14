"""Single upsert helper for Finding persistence.

All writers (discovery_tasks, cve_tasks, etc.) MUST use this helper
instead of direct Finding() inserts.
"""

from __future__ import annotations

import hashlib
from typing import Any
from datetime import datetime, timezone

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from models.finding import Finding


def upsert_finding(
    db: Session,
    org_id: int,
    asset_id: int,
    dedupe_key: str,
    **fields: Any,
) -> Finding:
    """Insert or update a finding by (org_id, asset_id, dedupe_key).

    On insert: sets all provided fields + first_seen_at = now.
    On conflict: updates ONLY fields that are explicitly provided (non-None).
    Never overwrites existing values with NULL. Never touches workflow
    fields (status, assigned_to, due_date, suppression_*) unless explicitly
    passed (4b will add reopen logic).

    Returns a fresh instance from the DB.
    """
    now = datetime.now(timezone.utc)

    # Build insert values (only non-None optional fields).
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
    }
    for key in ("description", "recommendation", "confidence", "source_module", "target_host", "cve_ids", "cvss_score"):
        if fields.get(key) is not None:
            values[key] = fields[key]

    stmt = insert(Finding).values(**values)
    # On conflict, update only provided (non-None) fields.
    update_set = {}
    for key in ("title", "severity", "category", "description", "recommendation", "confidence", "source_module", "target_host", "cve_ids", "cvss_score"):
        if fields.get(key) is not None:
            update_set[key] = fields[key]
    if fields.get("last_seen_at") is not None:
        update_set["last_seen_at"] = fields["last_seen_at"]
    if fields.get("last_seen_scan_id") is not None:
        update_set["last_seen_scan_id"] = fields["last_seen_scan_id"]

    if update_set:
        stmt = stmt.on_conflict_do_update(
            index_elements=["organization_id", "asset_id", "dedupe_key"],
            set_=update_set,
        )
    db.execute(stmt)
    db.flush()

    # Fetch fresh instance.
    finding = (
        db.query(Finding)
        .filter(
            Finding.organization_id == org_id,
            Finding.asset_id == asset_id,
            Finding.dedupe_key == dedupe_key,
        )
        .first()
    )
    # Refresh to get latest DB state.
    if finding is not None:
        db.refresh(finding)
    return finding


def legacy_dedupe_key(title: str) -> str:
    """Generate a dedupe key for legacy title-keyed findings."""
    return f"legacy:{hashlib.md5(title.encode()).hexdigest()}"
PYEOF
echo "Done"