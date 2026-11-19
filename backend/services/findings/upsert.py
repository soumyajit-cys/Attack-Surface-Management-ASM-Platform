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
            if key == "cve_ids":
                import json as _json
                values[key] = _json.dumps(fields[key])
            else:
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

    # Build column lists for raw SQL.
    col_names = list(values.keys())
    col_placeholders = ", ".join(f"CAST(:{c} AS json)" if c == "cve_ids" else f":{c}" for c in col_names)
    col_list = ", ".join(col_names)

    if update_set:
        set_clause = ", ".join(f"{k} = CAST(:upd_{k} AS json)" if k == "cve_ids" else f"{k} = :upd_{k}" for k in update_set)
        params = dict(values)
        for k, v in update_set.items():
            params[f"upd_{k}"] = v
        sql = text(
            f"INSERT INTO findings ({col_list}) VALUES ({col_placeholders}) "
            f"ON CONFLICT (organization_id, asset_id, dedupe_key) DO UPDATE SET {set_clause} "
            f"RETURNING id, (xmax = 0) AS created"
        )
    else:
        params = dict(values)
        sql = text(
            f"INSERT INTO findings ({col_list}) VALUES ({col_placeholders}) "
            f"ON CONFLICT (organization_id, asset_id, dedupe_key) DO NOTHING "
            f"RETURNING id, (xmax = 0) AS created"
        )

    try:
        result = db.execute(sql, params)
        row = result.fetchone()
        print('DEBUG row:', row)
        db.flush()
        if row is None:
            # Conflict occurred, do-nothing
            finding = (
                db.query(Finding)
                .filter(
                    Finding.organization_id == org_id,
                    Finding.asset_id == asset_id,
                    Finding.dedupe_key == dedupe_key,
                )
                .first()
            )
            created = False
        else:
            finding_id, created_flag = row
            created = bool(created_flag) if created_flag is not None else False
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
    except Exception as e:
        # Fallback for type issues: use SQLAlchemy insert
        db.rollback()
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
        created = False

    if finding is not None:
        db.refresh(finding)
    return finding, created


def legacy_dedupe_key(title: str) -> str:
    """Generate a dedupe key for legacy title-keyed findings."""
    return f"legacy:{hashlib.md5(title.encode()).hexdigest()}"
