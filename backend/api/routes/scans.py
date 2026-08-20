import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from auth.roles import require_roles, ROLE_ADMIN, ROLE_ANALYST
from models.scan_history import ScanHistory
from models.user import User
from schemas.scan import ScanRequest
from tasks.discovery_tasks import run_discovery
from utils.database import get_db

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

    scan = ScanHistory(
        organization_id=user.organization_id,
        target=domain,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    run_discovery.delay(scan_id=scan.id)

    return {
        "scan_id": scan.id,
        "target": domain,
        "status": "pending",
    }


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