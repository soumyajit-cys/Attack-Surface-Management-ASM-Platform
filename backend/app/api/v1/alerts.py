"""``/api/v1/alerts`` -- first-class asset-change events.

Surfaces the change-detection alerts persisted by
``services.history.change_detector.persist_alerts`` (new subdomain,
opened/closed port, changed certificate, new/resolved finding) so the
dashboard "Recent Changes" panel and operators can track them per
organisation. All queries are organisation-scoped like every other route.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from models.alert import Alert
from models.asset import Asset

from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/alerts", tags=["alerts"])

_ALERTS_DEP = require_permissions_dep(Permission.FINDING_READ)


def _asset_name(db: Session, asset_id: int | None, org_id: int) -> str | None:
    if asset_id is None:
        return None
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.organization_id == org_id,
    ).first()
    return asset.name if asset else None


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERTS_DEP),
):
    query = db.query(Alert).filter(
        Alert.organization_id == principal.organization_id
    )

    if severity:
        query = query.filter(Alert.severity == severity)
    if asset_id:
        query = query.filter(Alert.asset_id == asset_id)

    total = query.count()

    items = (
        query.order_by(Alert.created_at.desc())
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
                "id": a.id,
                "asset_id": a.asset_id,
                "asset_name": _asset_name(db, a.asset_id, principal.organization_id),
                "title": a.title,
                "severity": a.severity,
                "message": a.message,
                "read": bool(a.read),
                "created_at": a.created_at,
            }
            for a in items
        ],
    }
