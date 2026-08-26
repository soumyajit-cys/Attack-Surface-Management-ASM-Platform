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
    """Best-effort client IP. Only trusts X-Forwarded-For when a single hop."""
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first_hop = forwarded.split(",")[0].strip()
        if first_hop:
            return first_hop
    return request.client.host if request.client else None


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
