"""``/api/v1/scans`` -- scan orchestration.

Replaces the legacy ``/scan`` routes with:
- error envelope (``app.core.errors``),
- permission checks via ``require_permissions_dep``,
- SSRF pin-on-submit (resolve + pin once, scanners reuse the pin).
"""

import re

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from models.scan_history import ScanHistory
from schemas.scan import ScanRequest

from app.core.audit import record_audit
from app.core.config import settings
from app.core.errors import BadRequestError, ForbiddenError, NotFoundError
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db
from services.verification import verification_service as verification
from tasks.discovery_tasks import run_discovery
from utils.rate_limiter import limiter
from utils.ssrf_guard import validate_scan_target

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

    if settings.require_domain_verification:
        from utils.logger import logger

        ok, mode_or_reason, covering = verification.is_scan_allowed(
            db, principal.organization_id, domain
        )
        if not ok:
            raise ForbiddenError(
                f"Scan blocked: {mode_or_reason}",
                code="domain_not_verified",
            )
        if mode_or_reason == verification.STATUS_GRANDFATHERED and covering is not None:
            logger.warning(
                "Manual scan of grandfathered domain %s (verify before %s)",
                covering.domain, covering.expires_at,
            )
            verification.record_grace_notice(
                db, principal.organization_id, None, covering
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
    method = (data.method or verification.METHOD_DNS_TXT).strip().lower()
    if method not in verification.METHODS:
        raise BadRequestError(
            f"Unknown verification method: {method}",
            code="invalid_verification_method",
        )
    try:
        row = verification.initiate_verification(
            db, principal.organization_id, domain, method
        )
    except ValueError as exc:
        raise BadRequestError(str(exc), code="verification_not_allowed")

    expected = verification.challenge_value(row.token)
    if method == verification.METHOD_DNS_TXT:
        record_name: str | None = f"_sentinelasm-challenge.{domain}"
        expected_txt: str | None = expected
        file_path: str | None = None
        file_content: str | None = None
        instructions = (
            f"Add a TXT record at _sentinelasm-challenge.{domain} "
            f"with value: {expected}"
        )
    else:
        record_name = None
        expected_txt = None
        file_path = verification.http_file_path(row.token)
        file_content = expected
        instructions = (
            f"Serve the exact text '{expected}' at "
            f"https://{domain}{file_path} (plain HTTP is also accepted)"
        )

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan.ownership_challenge",
        details={"domain": domain, "method": method},
        request=request,
    )
    db.commit()

    return {
        "domain": domain,
        "method": method,
        "status": row.status,
        "challenge_token": row.token,
        "txt_record_name": record_name,
        "expected_txt_value": expected_txt,
        "file_path": file_path,
        "file_content": file_content,
        "instructions": instructions,
    }


@router.get("/verify-ownership/check")
@limiter.limit("20/minute")
async def check_ownership_verification(
    request: Request,
    domain: str,
    token: str | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_SCAN_DEP),
):
    from models.verified_domain import VerifiedDomain

    domain = _validated_domain(domain)
    row = (
        db.query(VerifiedDomain)
        .filter(
            VerifiedDomain.organization_id == principal.organization_id,
            VerifiedDomain.domain == domain,
        )
        .first()
    )
    if row is None:
        raise NotFoundError(
            "No verification challenge for this domain",
            code="verification_not_found",
        )
    if token is not None and token != row.token:
        raise BadRequestError(
            "Challenge token does not match the issued challenge",
            code="verification_failed",
        )

    ok, message = await verification.check_row(db, row)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan.ownership_verified" if ok else "scan.ownership_failed",
        details={"domain": domain, "method": row.method},
        request=request,
    )
    db.commit()

    if not ok:
        raise BadRequestError(
            message,
            code="verification_failed",
        )

    return {
        "verified": True,
        "message": message,
        "domain": domain,
        "method": row.method,
    }


@router.get("/verified-domains")
async def list_verified_domains(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_SCAN_DEP),
):
    """This org's domain verification rows (statuses drive UI badges)."""
    from models.verified_domain import VerifiedDomain

    rows = (
        db.query(VerifiedDomain)
        .filter(VerifiedDomain.organization_id == principal.organization_id)
        .order_by(VerifiedDomain.domain)
        .all()
    )
    return {
        "items": [
            {
                "domain": r.domain,
                "method": r.method,
                "status": r.status,
                "verified_at": r.verified_at,
                "expires_at": r.expires_at,
                "last_checked_at": r.last_checked_at,
            }
            for r in rows
        ]
    }


@router.get("")
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_SCAN_DEP),
):
    query = db.query(ScanHistory).filter(
        ScanHistory.organization_id == principal.organization_id
    )
    if status:
        query = query.filter(ScanHistory.status == status)

    total = query.count()
    items = (
        query.order_by(ScanHistory.id.desc())
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
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "error": s.error,
                "asset_id": s.asset_id,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "updated_at": s.updated_at,
            }
            for s in items
        ],
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