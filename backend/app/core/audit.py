"""Audit logging for sensitive actions.

Writes rows to the existing ``audit_logs`` table. Callers are responsible for
committing the session (audit rows participate in the request's transaction so
an action and its audit entry succeed or fail together).
"""

import json
import logging
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from models.audit_log import AuditLog

logger = logging.getLogger("sentinelasm.audit")


def client_ip(request: Request | None) -> str | None:
    """Best-effort client IP. Delegates to the single source of truth
    (:func:`utils.client_ip.get_client_ip`) so audit, rate limiting, and
    lockout agree. Only trusts X-Forwarded-For behind TRUSTED_PROXIES."""
    if request is None:
        return None
    from utils.client_ip import get_client_ip

    return get_client_ip(request)


def record_audit(
    db: Session,
    *,
    organization_id: int,
    actor: str,
    action: str,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Persist an audit event. Flushes but does not commit."""
    entry = AuditLog(
        organization_id=organization_id,
        actor=actor,
        action=action,
        details=json.dumps(details or {}, default=str),
    )
    db.add(entry)
    db.flush()

    logger.info(
        "audit",
        extra={
            "action": action,
            "actor": actor,
            "organization_id": organization_id,
            "ip": client_ip(request),
        },
    )
    return entry
