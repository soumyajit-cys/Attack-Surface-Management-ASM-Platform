"""``/api/v1/scans`` -- scan orchestration.

Replaces the legacy ``/scan`` routes with:
- error envelope (``app.core.errors``),
- permission checks via ``require_permissions_dep``,
- SSRF pin-on-submit (resolve + pin once, scanners reuse the pin).
"""

import re

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from models.scan_history import ScanHistory
from schemas.scan import ScanRequest

from app.core.audit import record_audit
from app.core.errors import BadRequestError, NotFoundError
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db
from tasks.discovery_tasks import run_discovery
from utils.rate_limiter import limiter
from utils.ssrf_guard import (
    generate_ownership_challenge,
    validate_scan_target,
    verify_domain_ownership,
)

router = APIRouter(prefix="/scans", tags=["scans"])

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,63}$",
    re.IGNORECASE,
)

_SCAN_DEP = require_permissions_dep(Permission.SCAN_CREATE)
_READ_SCAN_DEP = require_permissions_dep(Permission.SCAN_READ)


def _validated_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    if not DOMAIN_RE.match(domain):
        raise BadRequestError("Invalid domain name", code="invalid_domain")
    return domain


@router.post("", status_code=202)
@limiter.limit("5/minute")
async def start_scan(
    request: Request,
    data: ScanRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_SCAN_DEP),
):
    domain = _validated_domain(data.domain)

    from services.discovery.domain_service import resolve_domain
    resolved = await resolve_domain(domain)
    resolved_ip = resolved.get("ip")

    allowed, reason = validate_scan_target(domain, resolved_ip)
    if not allowed:
        raise BadRequestError(
            f"Scan target not allowed: {reason}",
            code="scan_target_not_allowed",
        )

    scan = ScanHistory(
        organization_id=principal.organization_id,
        target=domain,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    run_discovery.delay(scan_id=scan.id)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan.started",
        details={"target": domain},
        request=request,
    )
    db.commit()

    return {
        "scan_id": scan.id,
        "target": domain,
        "status": "pending",
        "resolved_ip": resolved_ip,
    }


@router.post("/verify-ownership")
@limiter.limit("10/minute")
async def request_ownership_verification(
    request: Request,
    data: ScanRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_SCAN_DEP),
):
    domain = _validated_domain(data.domain)
    token, expected_value = generate_ownership_challenge(domain)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan.ownership_challenge",
        details={"domain": domain},
        request=request,
    )
    db.commit()

    return {
        "domain": domain,
        "challenge_token": token,
        "txt_record_name": f"_sentinelasm-challenge.{domain}",
        "expected_txt_value": expected_value,
        "instructions": (
            f"Add a TXT record at _sentinelasm-challenge.{domain} "
            f"with value: {expected_value}"
        ),
    }


@router.get("/verify-ownership/check")
@limiter.limit("20/minute")
async def check_ownership_verification(
    request: Request,
    domain: str,
    token: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_SCAN_DEP),
):
    domain = _validated_domain(domain)
    verified, message = await verify_domain_ownership(domain, token)

    if not verified:
        raise BadRequestError(
            message,
            code="ownership_unverified",
        )

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan.ownership_verified",
        details={"domain": domain},
        request=request,
    )
    db.commit()

    return {
        "verified": True,
        "message": message,
        "domain": domain,
    }


@router.get("/{scan_id}")
async def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_SCAN_DEP),
):
    scan = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.id == scan_id,
            ScanHistory.organization_id == principal.organization_id,
        )
        .first()
    )
    if scan is None:
        raise NotFoundError("Scan not found", code="scan_not_found")

    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "error": scan.error,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }