from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from models.asset import Asset
from models.finding import Finding
from models.user import User
from utils.database import get_db

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


@router.get("/")
async def get_dashboard(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = user.organization_id

    total_assets = db.query(Asset).filter(
        Asset.organization_id == org_id
    ).count()

    total_findings = db.query(Finding).filter(
        Finding.organization_id == org_id
    ).count()

    by_severity = dict(
        db.query(
            Finding.severity,
            func.count(Finding.id),
        )
        .filter(Finding.organization_id == org_id)
        .group_by(Finding.severity)
        .all()
    )

    return {
        "assets": total_assets,
        "findings": total_findings,
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "medium": by_severity.get("medium", 0),
        "low": by_severity.get("low", 0),
        "info": by_severity.get("info", 0),
    }