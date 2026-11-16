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
) -> tuple[Finding, bool]:
    """Insert or update a finding by (org_id, asset_id, dedupe_key).

    On insert: sets all provided fields + first_seen_at = now.
    On conflict: updates ONLY fields that are explicitly provided (non-None).
    Never overwrites existing values with NULL. Never touches workflow
    fields (status, assigned_to, due_date, suppression_*) unless explicitly
    passed. Sets last_seen_at = now and last_seen_scan_id on every sighting.
    Sets updated_at on conflict. Returns a fresh instance.
    """
    now = datetime.now(timezone.utc)

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
    # Always update last_seen on every sighting.
    update_set["last_seen_at"] = fields.get("last_seen_at", now)
    if fields.get("last_seen_scan_id") is not None:
        update_set["last_seen_scan_id"] = fields["last_seen_scan_id"]
    update_set["updated_at"] = now

    stmt = insert(Finding).values(**values)
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
    if finding is not None:
        db.refresh(finding)
    return finding


def legacy_dedupe_key(title: str) -> str:
    """Generate a dedupe key for legacy title-keyed findings."""
    return f"legacy:{hashlib.md5(title.encode()).hexdigest()}"
