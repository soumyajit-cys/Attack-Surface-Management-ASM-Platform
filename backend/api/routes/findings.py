from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from models.finding import Finding
from models.user import User
from utils.database import get_db

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
)


@router.get("/")
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Finding).filter(
        Finding.organization_id == user.organization_id
    )

    if severity:
        query = query.filter(Finding.severity == severity)

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