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

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_permissions_dep
from app.core.errors import BadRequestError
from app.core.permissions import Permission
from app.db.session import get_db
from models.audit_log import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])

_ORG_MANAGE_DEP = require_permissions_dep(Permission.ORG_MANAGE)

MAX_PAGE_SIZE = 100

# Substring patterns, case-insensitive, scrubbed from ``details`` keys at
# every nesting level (nested dicts and lists included). A key whose name
# matches ANY pattern is dropped before serialization; the audit VIEWER
# guarantees no secret-looking material is ever returned even if a writer
# slips. Bare "key"/"ip"/"email" are deliberately NOT patterns (identifiers,
# not credentials).
_SCRUB_PATTERNS: tuple[str, ...] = (
    "password", "passcode",          # password material and its sibling
    "otp", "totp",                   # second factors and their seeds
    "secret", "token", "credential", "authorization", "cookie",
    "api_key", "apikey",             # API credentials
    "recovery_code",                 # single-use 2FA codes
    "webhook", "url",                # webhook/callback targets are credentials here
    "private",                       # private keys / private material
)

# Per-action allowlist (see _allowed_for_action): reviewed fields whose
# BOOLEAN/STATE value is the point of the event. One entry so far:
# the 2FA lifecycle events carry the totp_enabled flag so the audit
# trail can answer "was 2FA on when this happened?".
_ACTION_KEY_ALLOWLIST: dict[str, frozenset[str]] = {
    "auth.2fa": frozenset({"totp_enabled"}),
}


def _allowed_for_action(action: str | None) -> frozenset[str]:
    """Per-action allowlist — keys that stay VISIBLE for that action family.

    A key earns its place here only when a reviewed boolean/counter IS the
    point of the event (the secret material itself still never passes —
    the deny patterns are checked first). "family" entries match the
    action exactly or by prefix with a ``.``/``_`` separator, e.g.
    ``auth.2fa`` covers ``auth.2fa_enabled``, ``auth.2fa_reset``,
    ``auth.2fa_codes_regenerated``.
    """
    if not action:
        return frozenset()
    allowed: set[str] = set()
    for family, keys in _ACTION_KEY_ALLOWLIST.items():
        if action == family \
                or action.startswith((family + ".", family + "_")):
            allowed.update(keys)
    return frozenset(allowed)
    return frozenset(allowed)


def _matches_deny(key: str) -> bool:
    folded = key.casefold()
    return any(pattern in folded for pattern in _SCRUB_PATTERNS)


def _scrub_sensitive(value: object, allowed: frozenset[str] = frozenset()) -> object:
    """Recursively drop secret-named keys from parsed details.

    Keys in ``allowed`` for this action family survive even when their
    name trips a deny pattern.
    """
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, item in value.items():
            foldable = isinstance(key, str)
            if foldable and _matches_deny(key) and key.casefold() not in allowed:
                continue
            result[key] = _scrub_sensitive(item, allowed)
        return result
    if isinstance(value, list):
        return [_scrub_sensitive(item, allowed) for item in value]
    return value


def _scrub_details(raw: str | None, action: str | None = None) -> dict:
    """Parse the details JSON and drop secret-named keys (never returns them)."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    allowed = _allowed_for_action(action)
    scrubbed = _scrub_sensitive(parsed, allowed)
    return scrubbed if isinstance(scrubbed, dict) else {}


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
        raise BadRequestError("since must not be after until")

    canonical_ip: str | None = None
    if ip:
        try:
            canonical_ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            raise BadRequestError("ip filter must be an IP literal")

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

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": row.id,
                "actor": row.actor,
                "action": row.action,
                "details": _scrub_details(row.details, row.action),
                "ip_address": row.ip_address,
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }
