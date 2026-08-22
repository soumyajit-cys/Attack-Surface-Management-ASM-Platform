from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from auth.roles import ROLE_ADMIN, require_roles
from models import ScanPolicy, ScanHistory, Asset, ScanScope, ScanFrequency
from schemas.scan_policy import ScanPolicyCreate, ScanPolicyUpdate, ScanPolicyResponse
from tasks.discovery_tasks import run_discovery
from utils.database import get_db

router = APIRouter(
    prefix="/scan-policies",
    tags=["scan-policies"],
)


@router.post("/", response_model=ScanPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_policy(
    data: ScanPolicyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    asset = db.query(Asset).filter(
        Asset.id == data.asset_id,
        Asset.organization_id == user.organization_id,
    ).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    try:
        freq = ScanFrequency(data.frequency)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid frequency",
        )

    try:
        scope = ScanScope(data.scope)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scope",
        )

    policy = ScanPolicy(
        organization_id=user.organization_id,
        asset_id=data.asset_id,
        name=data.name,
        frequency=freq,
        cron_expression=data.cron_expression,
        scope=scope,
        created_by=user.id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy


@router.get("/", response_model=list[ScanPolicyResponse])
async def list_scan_policies(
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(ScanPolicy).filter(
        ScanPolicy.organization_id == user.organization_id
    )
    if asset_id:
        query = query.filter(ScanPolicy.asset_id == asset_id)

    policies = query.order_by(ScanPolicy.created_at.desc()).all()
    return policies


@router.get("/{policy_id}", response_model=ScanPolicyResponse)
async def get_scan_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == user.organization_id,
    ).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan policy not found",
        )
    return policy


@router.patch("/{policy_id}", response_model=ScanPolicyResponse)
async def update_scan_policy(
    policy_id: int,
    data: ScanPolicyUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == user.organization_id,
    ).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan policy not found",
        )

    if data.name is not None:
        policy.name = data.name
    if data.frequency is not None:
        try:
            policy.frequency = ScanFrequency(data.frequency)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid frequency",
            )
    if data.cron_expression is not None:
        policy.cron_expression = data.cron_expression
    if data.scope is not None:
        try:
            policy.scope = ScanScope(data.scope)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid scope",
            )
    if data.is_active is not None:
        policy.is_active = data.is_active

    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(policy)

    return policy


@router.delete("/{policy_id}")
async def delete_scan_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == user.organization_id,
    ).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan policy not found",
        )

    db.delete(policy)
    db.commit()

    return {"message": "Scan policy deleted"}


@router.post("/{policy_id}/run-now")
async def run_scan_policy_now(
    policy_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == user.organization_id,
    ).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan policy not found",
        )

    if not policy.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan policy is not active",
        )

    asset = db.query(Asset).filter(Asset.id == policy.asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    scan = ScanHistory(
        organization_id=user.organization_id,
        asset_id=asset.id,
        target=asset.name,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    run_discovery.delay(scan_id=scan.id)

    policy.last_run_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "scan_id": scan.id,
        "target": asset.name,
        "status": "pending",
    }