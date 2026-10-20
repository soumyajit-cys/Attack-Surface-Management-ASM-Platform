"""``/api/v1/audit-logs`` — the org's audit trail viewer (ORG_MANAGE only).

Org-scoped by construction (every query filters on the caller's own
organization_id), paginated with a hard page-size cap, and filterable by
action / actor / since / until / ip — all through parameterized SQLAlchemy
comparisons; nothing is interpolated into SQL. Secret-looking ``details``
keys are scrubbed server-side before serialization, and filter values are
validated and length-bounded.
"""

import ipaddress
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_permissions_dep
from app.core.permissions import Permission
from app.db.session import get_db
from models.audit_log import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])

_ORG_MANAGE_DEP = require_permissions_dep(Permission.ORG_MANAGE)

MAX_PAGE_SIZE = 100

# details keys scrubbed from every response row (case-insensitive): audit
# writers never put secrets in details, but the crawl of history is not
# guaranteed — the VIEWER guarantees no secret names are ever returned.
_SECRET_DETAIL_KEYS = frozenset({
    "password", "secret", "token", "api_key", "apikey", "authorization",
    "totp_secret", "recovery_code", "cookie", "webhook_secret",
})


def _scrub_details(raw: str | None) -> dict:
    """Parse the details JSON and drop secret-named keys (never returns them)."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        key: value
        for key, value in parsed.items()
        if key.lower() not in _SECRET_DETAIL_KEYS
    }


@router.get("")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=MAX_PAGE_SIZE),
    action: str | None = Query(None, max_length=64),
    actor: str | None = Query(None, max_length=200),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    ip: str | None = Query(None, max_length=64),
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_MANAGE_DEP),
):
    """This org's audit trail, newest first.

    Raises 400 for invalid filters (bad IP literal, since after until);
    FastAPI itself rejects malformed datetimes and out-of-bounds pagination.
    """
    if since is not None and until is not None and since > until:
        raise HTTPException(
            status_code=400, detail="since must not be after until")

    canonical_ip: str | None = None
    if ip:
        try:
            canonical_ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            raise HTTPException(
                status_code=400, detail="ip filter must be an IP literal")

    # Parameterized only: every filter is a bound SQLAlchemy comparison
    # (no string building), backed by the migration-e5f6a7b8c9d1 indexes
    # (organization_id, created_at) / action / ip_address.
    query = db.query(AuditLog).filter(
        AuditLog.organization_id == principal.organization_id)
    if action is not None:
        query = query.filter(AuditLog.action == action)
    if actor is not None:
        query = query.filter(AuditLog.actor == actor)
    if since is not None:
        query = query.filter(AuditLog.created_at >= since)
    if until is not None:
        query = query.filter(AuditLog.created_at <= until)
    if canonical_ip is not None:
        query = query.filter(AuditLog.ip_address == canonical_ip)

    total = query.count()
    rows = (
        query
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    # count() ran with a plain func.count() over the same index-friendly filters.
    assert total is not None

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": row.id,
                "actor": row.actor,
                "action": row.action,
                "details": _scrub_details(row.details),
                "ip_address": row.ip_address,
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }
