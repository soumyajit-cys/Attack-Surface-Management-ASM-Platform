"""``/api/v1/scan-policies`` -- scheduled scanning.

On create (and on frequency/cron changes) the ``next_run_at`` is computed so
the Celery Beat scheduler (``tasks.scheduler_tasks.process_due_scan_policies``)
can dispatch scans without the API knowing anything about cron.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from models import Asset, ScanFrequency, ScanPolicy, ScanScope
from schemas.scan_policy import (
    ScanPolicyCreate,
    ScanPolicyResponse,
    ScanPolicyUpdate,
)
from tasks.scheduler_tasks import compute_next_run

from app.core.audit import record_audit
from app.core.errors import BadRequestError, NotFoundError
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/scan-policies", tags=["scan-policies"])

_POLICY_MANAGE_DEP = require_permissions_dep(Permission.POLICY_MANAGE)
_READ_DEP = require_permissions_dep(Permission.SCAN_READ)


def _next_run(policy: ScanPolicy, now: datetime) -> datetime:
    return compute_next_run(policy.frequency, policy.cron_expression, now)


@router.post("", response_model=ScanPolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_policy(
    request: Request,
    data: ScanPolicyCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_POLICY_MANAGE_DEP),
):
    asset = db.query(Asset).filter(
        Asset.id == data.asset_id,
        Asset.organization_id == principal.organization_id,
    ).first()
    if not asset:
        raise NotFoundError("Asset not found", code="asset_not_found")

    try:
        freq = ScanFrequency(data.frequency)
        scope = ScanScope(data.scope)
    except ValueError:
        raise BadRequestError("Invalid frequency or scope", code="invalid_scan_policy")

    now = datetime.now(timezone.utc)
    policy = ScanPolicy(
        organization_id=principal.organization_id,
        asset_id=data.asset_id,
        name=data.name,
        frequency=freq,
        cron_expression=data.cron_expression,
        scope=scope,
        created_by=principal.user.id,
        next_run_at=_next_run_policy(freq, data.cron_expression, now),
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan_policy.created",
        details={"policy_id": policy.id, "name": policy.name},
        request=request,
    )
    db.commit()

    return policy


def _next_run_policy(freq: ScanFrequency, cron: str | None, now: datetime) -> datetime:
    if freq == ScanFrequency.CUSTOM_CRON and not cron:
        raise BadRequestError(
            "cron_expression is required for custom_cron frequency",
            code="cron_expression_required",
        )
    return compute_next_run(freq, cron, now)


@router.get("", response_model=list[ScanPolicyResponse])
async def list_scan_policies(
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_DEP),
):
    query = db.query(ScanPolicy).filter(
        ScanPolicy.organization_id == principal.organization_id
    )
    if asset_id:
        query = query.filter(ScanPolicy.asset_id == asset_id)

    return query.order_by(ScanPolicy.created_at.desc()).all()


@router.get("/{policy_id}", response_model=ScanPolicyResponse)
async def get_scan_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_DEP),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == principal.organization_id,
    ).first()
    if not policy:
        raise NotFoundError("Scan policy not found", code="scan_policy_not_found")
    return policy


@router.patch("/{policy_id}", response_model=ScanPolicyResponse)
async def update_scan_policy(
    policy_id: int,
    data: ScanPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_POLICY_MANAGE_DEP),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == principal.organization_id,
    ).first()
    if not policy:
        raise NotFoundError("Scan policy not found", code="scan_policy_not_found")

    try:
        if data.frequency is not None:
            policy.frequency = ScanFrequency(data.frequency)
    except ValueError:
        raise BadRequestError("Invalid frequency", code="invalid_frequency")

    try:
        if data.scope is not None:
            policy.scope = ScanScope(data.scope)
    except ValueError:
        raise BadRequestError("Invalid scope", code="invalid_scope")

    if data.name is not None:
        policy.name = data.name
    if data.cron_expression is not None:
        policy.cron_expression = data.cron_expression
    if data.is_active is not None:
        policy.is_active = data.is_active

    if policy.frequency == ScanFrequency.CUSTOM_CRON and not policy.cron_expression:
        raise BadRequestError(
            "cron_expression is required for custom_cron frequency",
            code="cron_expression_required",
        )

    policy.next_run_at = _next_run(policy, datetime.now(timezone.utc))
    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(policy)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan_policy.updated",
        details={"policy_id": policy_id},
        request=request,
    )
    db.commit()

    return policy


@router.delete("/{policy_id}")
async def delete_scan_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_POLICY_MANAGE_DEP),
):
    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == principal.organization_id,
    ).first()
    if not policy:
        raise NotFoundError("Scan policy not found", code="scan_policy_not_found")

    db.delete(policy)
    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan_policy.deleted",
        details={"policy_id": policy_id},
        request=request,
    )
    db.commit()

    return {"message": "Scan policy deleted"}


@router.post("/{policy_id}/run-now")
async def run_scan_policy_now(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_POLICY_MANAGE_DEP),
):
    from models.scan_history import ScanHistory

    policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == policy_id,
        ScanPolicy.organization_id == principal.organization_id,
    ).first()
    if not policy:
        raise NotFoundError("Scan policy not found", code="scan_policy_not_found")
    if not policy.is_active:
        raise BadRequestError(
            "Scan policy is not active", code="scan_policy_inactive"
        )

    asset = db.query(Asset).filter(Asset.id == policy.asset_id).first()
    if not asset:
        raise NotFoundError("Asset not found", code="asset_not_found")

    scan = ScanHistory(
        organization_id=principal.organization_id,
        asset_id=asset.id,
        target=asset.name,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from tasks.discovery_tasks import run_discovery
    run_discovery.delay(scan_id=scan.id)

    policy.last_run_at = datetime.now(timezone.utc)
    policy.next_run_at = _next_run(policy, datetime.now(timezone.utc))
    db.commit()

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="scan_policy.run_now",
        details={"policy_id": policy_id, "scan_id": scan.id},
        request=request,
    )
    db.commit()

    return {
        "scan_id": scan.id,
        "target": asset.name,
        "status": "pending",
    }