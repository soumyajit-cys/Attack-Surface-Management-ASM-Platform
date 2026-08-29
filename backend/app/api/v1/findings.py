"""``/api/v1/findings`` -- findings listener with pagination + filtering."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from models.finding import Finding

from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/findings", tags=["findings"])

_FINDINGS_DEP = require_permissions_dep(Permission.FINDING_READ)


@router.get("")
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    category: str | None = None,
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_FINDINGS_DEP),
):
    query = db.query(Finding).filter(
        Finding.organization_id == principal.organization_id
    )

    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)
    if asset_id:
        query = query.filter(Finding.asset_id == asset_id)

    total = query.count()

    items = (
        query.order_by(Finding.created_at.desc())
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
                "id": f.id,
                "asset_id": f.asset_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "recommendation": f.recommendation,
                "created_at": f.created_at,
                "asset_name": _asset_name(db, f.asset_id, principal.organization_id),
            }
            for f in items
        ],
    }


def _asset_name(db: Session, asset_id: int, org_id: int) -> str | None:
    from models.asset import Asset

    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.organization_id == org_id,
    ).first()
    return asset.name if asset else None


@router.get("/{finding_id}")
async def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_FINDINGS_DEP),
):
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.organization_id == principal.organization_id,
    ).first()
    if not finding:
        from app.core.errors import NotFoundError

        raise NotFoundError("Finding not found", code="finding_not_found")

    return {
        "id": finding.id,
        "asset_id": finding.asset_id,
        "asset_name": _asset_name(db, finding.asset_id, principal.organization_id),
        "organization_id": finding.organization_id,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "created_at": finding.created_at,
        "updated_at": finding.updated_at,
    }