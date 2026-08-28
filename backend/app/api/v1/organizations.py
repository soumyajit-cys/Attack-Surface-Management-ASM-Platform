"""``/api/v1/organizations`` -- org profile, invitations, API keys."""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from models import APIKey, Invitation, InvitationStatus, Organization
from schemas.organization import (
    APIKeyCreate,
    APIKeyUpdate,
    InvitationAccept,
    InvitationCreate,
    InvitationResponse,
    OrganizationResponse,
)

from app.core.audit import record_audit
from app.core.errors import ConflictError, NotFoundError
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/organizations", tags=["organizations"])

_ORG_ADMIN_DEP = require_permissions_dep(Permission.ORG_MANAGE)


def _org_response(db: Session, org) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "created_at": org.created_at,
        "updated_at": org.updated_at,
    }


@router.get("/me", response_model=OrganizationResponse)
async def get_my_organization(
    db: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
):
    org = db.query(Organization).filter(
        Organization.id == principal.organization_id
    ).first()
    if not org:
        raise NotFoundError(
            "Organization not found", code="organization_not_found"
        )
    return org


@router.post("/invitations", response_model=InvitationResponse, status_code=status.HTTP_201_CREATED)
async def create_invitation(
    request: Request,
    data: InvitationCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    from models.user import User

    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise ConflictError(
            "User with this email already exists",
            code="email_taken",
        )

    existing_invitation = db.query(Invitation).filter(
        Invitation.organization_id == principal.organization_id,
        Invitation.email == data.email,
        Invitation.status == InvitationStatus.PENDING,
    ).first()
    if existing_invitation:
        raise ConflictError(
            "Pending invitation already exists for this email",
            code="invitation_pending",
        )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    invitation = Invitation(
        organization_id=principal.organization_id,
        email=data.email,
        role=data.role,
        token=token,
        status=InvitationStatus.PENDING,
        invited_by=principal.user.id,
        expires_at=expires_at,
    )
    db.add(invitation)
    db.commit()
    db.refresh(invitation)

    from app.core.config import settings
    from services.alerts.email_service import send_email

    accept_url = f"{settings.frontend_url}/accept-invitation?token={token}"
    send_email(
        data.email,
        f"Invitation to join {principal.user.organization.name} on SentinelASM",
        f"You have been invited to join {principal.user.organization.name} as {data.role}.\n"
        f"Accept here: {accept_url}\n"
        f"This invitation expires in 7 days.",
    )

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="org.invite",
        details={"email": data.email, "role": data.role},
        request=request,
    )
    db.commit()

    return invitation


@router.get("/invitations", response_model=list[InvitationResponse])
async def list_invitations(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    invitations = db.query(Invitation).filter(
        Invitation.organization_id == principal.organization_id
    ).order_by(Invitation.created_at.desc()).all()
    return invitations


@router.post("/invitations/{invitation_id}/revoke")
async def revoke_invitation(
    invitation_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    invitation = db.query(Invitation).filter(
        Invitation.id == invitation_id,
        Invitation.organization_id == principal.organization_id,
    ).first()
    if not invitation:
        raise NotFoundError(
            "Invitation not found", code="invitation_not_found"
        )

    invitation.status = InvitationStatus.REVOKED
    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="org.invite_revoked",
        details={"invitation_id": invitation_id},
        request=request,
    )
    db.commit()

    return {"message": "Invitation revoked"}


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: APIKeyCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    full_key, key_hash = APIKey.generate_key()
    expires_at = None
    if data.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_days)

    api_key = APIKey(
        organization_id=principal.organization_id,
        name=data.name,
        key_hash=key_hash,
        key_prefix=full_key.split("_")[0],
        scopes=data.scopes,
        expires_at=expires_at,
        created_by=principal.user.id,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return {
        "id": api_key.id,
        "organization_id": api_key.organization_id,
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "scopes": api_key.scopes,
        "is_active": api_key.is_active,
        "last_used_at": api_key.last_used_at,
        "expires_at": api_key.expires_at,
        "created_by": api_key.created_by,
        "created_at": api_key.created_at,
        "key": full_key,
    }


@router.get("/api-keys")
async def list_api_keys(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    keys = db.query(APIKey).filter(
        APIKey.organization_id == principal.organization_id
    ).order_by(APIKey.created_at.desc()).all()
    return [
        {
            "id": k.id,
            "organization_id": k.organization_id,
            "name": k.name,
            "key_prefix": k.key_prefix,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "last_used_at": k.last_used_at,
            "expires_at": k.expires_at,
            "created_by": k.created_by,
            "created_at": k.created_at,
        }
        for k in keys
    ]


@router.patch("/api-keys/{key_id}")
async def update_api_key(
    key_id: int,
    data: APIKeyUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.organization_id == principal.organization_id,
    ).first()
    if not api_key:
        raise NotFoundError("API key not found", code="api_key_not_found")

    if data.name is not None:
        api_key.name = data.name
    if data.scopes is not None:
        api_key.scopes = data.scopes
    if data.is_active is not None:
        api_key.is_active = data.is_active

    api_key.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "API key updated"}


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ORG_ADMIN_DEP),
):
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.organization_id == principal.organization_id,
    ).first()
    if not api_key:
        raise NotFoundError("API key not found", code="api_key_not_found")

    db.delete(api_key)
    db.commit()

    return {"message": "API key deleted"}