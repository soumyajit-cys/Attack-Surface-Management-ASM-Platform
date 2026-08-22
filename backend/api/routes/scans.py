import re
import asyncio

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from auth.roles import require_roles, ROLE_ADMIN, ROLE_ANALYST
from models.scan_history import ScanHistory
from models.user import User
from schemas.scan import ScanRequest
from tasks.discovery_tasks import run_discovery
from utils.database import get_db
from utils.ssrf_guard import (
    validate_scan_target,
    verify_domain_ownership,
    generate_ownership_challenge,
)

router = APIRouter(
    prefix="/scan",
    tags=["scan"],
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,63}$",
    re.IGNORECASE,
)


@router.post("/", status_code=202)
async def start_scan(
    data: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(
        require_roles(ROLE_ADMIN, ROLE_ANALYST)
    ),
):
    domain = data.domain.strip().lower()
    if not DOMAIN_RE.match(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain name",
        )

    from services.discovery.domain_service import resolve_domain
    resolved = await resolve_domain(domain)
    resolved_ip = resolved.get("ip")

    allowed, reason = validate_scan_target(domain, resolved_ip)
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Scan target not allowed: {reason}",
        )

    scan = ScanHistory(
        organization_id=user.organization_id,
        target=domain,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(run_discovery.delay, scan_id=scan.id)

    return {
        "scan_id": scan.id,
        "target": domain,
        "status": "pending",
        "resolved_ip": resolved_ip,
    }


@router.post("/verify-ownership")
async def request_ownership_verification(
    data: ScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = data.domain.strip().lower()
    if not DOMAIN_RE.match(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain name",
        )

    token, expected_value = generate_ownership_challenge(domain)

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


@router.post("/verify-ownership/check")
async def check_ownership_verification(
    data: ScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = data.domain.strip().lower()
    if not DOMAIN_RE.match(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain name",
        )

    token = data.domain  # using domain field to pass token in this case
    # In practice, this would come from a separate field or query param
    # For simplicity, we'll use a query param approach

    raise HTTPException(
        status_code=501,
        detail="Use query parameter ?token=... with GET /scan/verify-ownership/check?domain=...&token=...",
    )


@router.get("/verify-ownership/check")
async def check_ownership_verification_get(
    domain: str,
    token: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    domain = domain.strip().lower()
    if not DOMAIN_RE.match(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain name",
        )

    verified, message = await verify_domain_ownership(domain, token)

    if verified:
        return {
            "verified": True,
            "message": message,
            "domain": domain,
        }
    else:
        raise HTTPException(
            status_code=400,
            detail=message,
        )


@router.get("/{scan_id}")
async def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.id == scan_id,
            ScanHistory.organization_id == user.organization_id,
        )
        .first()
    )
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "error": scan.error,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }