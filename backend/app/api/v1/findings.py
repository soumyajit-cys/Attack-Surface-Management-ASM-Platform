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
            }
            for f in items
        ],
    }