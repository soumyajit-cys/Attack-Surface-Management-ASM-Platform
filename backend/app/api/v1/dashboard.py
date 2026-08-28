"""``/api/v1/dashboard`` -- organization summary counts."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.asset import Asset
from models.finding import Finding
from models.scan_history import ScanHistory

from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_READ_DEP = require_permissions_dep(Permission.FINDING_READ)


@router.get("")
async def get_dashboard(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_DEP),
):
    org_id = principal.organization_id

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

    scans_total = db.query(ScanHistory).filter(
        ScanHistory.organization_id == org_id
    ).count()

    scans_completed = db.query(ScanHistory).filter(
        ScanHistory.organization_id == org_id,
        ScanHistory.status == "completed",
    ).count()

    from models.risk_score import RiskScore
    avg_risk = db.query(func.avg(RiskScore.score)).join(
        Asset, Asset.id == RiskScore.asset_id
    ).filter(Asset.organization_id == org_id).scalar()

    return {
        "assets": total_assets,
        "findings": total_findings,
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "medium": by_severity.get("medium", 0),
        "low": by_severity.get("low", 0),
        "info": by_severity.get("info", 0),
        "scans_total": scans_total,
        "scans_completed": scans_completed,
        "avg_risk_score": float(avg_risk) if avg_risk else 0.0,
    }