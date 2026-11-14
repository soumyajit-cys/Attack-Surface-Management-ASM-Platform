"""Single upsert helper for Finding persistence.

All writers (discovery_tasks, cve_tasks, etc.) MUST use this helper
instead of direct Finding() inserts.
"""

from __future__ import annotations

import hashlib
from typing import Any

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

    Returns the Finding instance.
    """
    values = {
        "organization_id": org_id,
        "asset_id": asset_id,
        "dedupe_key": dedupe_key,
        "title": fields.get("title", ""),
        "severity": fields.get("severity", "info"),
        "category": fields.get("category", "general"),
        "description": fields.get("description"),
        "recommendation": fields.get("recommendation"),
        "confidence": fields.get("confidence"),
        "source_module": fields.get("source_module"),
        "target_host": fields.get("target_host"),
    }
    # Remove None values for optional fields to use DB defaults
    values = {k: v for k, v in values.items() if v is not None or k in ("organization_id", "asset_id", "dedupe_key", "title", "severity", "category")}

    stmt = insert(Finding).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["organization_id", "asset_id", "dedupe_key"],
        set_={
            "severity": fields.get("severity"),
            "category": fields.get("category"),
            "description": fields.get("description"),
            "recommendation": fields.get("recommendation"),
            "confidence": fields.get("confidence"),
            "last_seen_at": None,  # will be set by caller
        },
    )
    db.execute(stmt)
    db.flush()

    # Fetch the finding
    finding = (
        db.query(Finding)
        .filter(
            Finding.organization_id == org_id,
            Finding.asset_id == asset_id,
            Finding.dedupe_key == dedupe_key,
        )
        .first()
    )
    return finding


def legacy_dedupe_key(title: str) -> str:
    """Generate a dedupe key for legacy title-keyed findings."""
    return f"legacy:{hashlib.md5(title.encode()).hexdigest()}"
PYEOF
mkdir -p /home/babai/Desktop/codeing/ASM/Attack-Surface-Management-ASM-Platform/backend/services/findings
mv /home/babai/Desktop/codeing/ASM/Attack-Surface-Management-ASM-Platform/backend/services/findings/upsert.py /tmp/upsert_backup.py 2>/dev/null
mkdir -p /home/babai/Desktop/codeing/ASM/Attack-Surface-Management-ASM-Platform/backend/services/findings
cp /tmp/upsert_backup.py /home/babai/Desktop/codeing/ASM/Attack-Surface-Management-ASM-Platform/backend/services/findings/upsert.py
echo "Done"