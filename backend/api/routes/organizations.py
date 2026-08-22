import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from auth.roles import ROLE_ADMIN, require_roles
from models import Invitation, InvitationStatus, APIKey, Organization, User
from schemas.organization import (
    APIKeyCreate,
    APIKeyUpdate,
    InvitationAccept,
    InvitationCreate,
    OrganizationCreate,
)
from utils.database import get_db

router = APIRouter(
    prefix="/organizations",
    tags=["organizations"],
)


@router.post("/", response_model=OrganizationCreate, status_code=status.HTTP_201_CREATED)
async def create_organization(
    data: OrganizationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    existing = db.query(Organization).filter(
        Organization.name == data.name
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization name already taken",
        )

    org = Organization(name=data.name)
    db.add(org)
    db.flush()

    user.organization_id = org.id
    user.role = ROLE_ADMIN
    db.commit()
    db.refresh(org)

    return org


@router.get("/me", response_model=OrganizationCreate)
async def get_my_organization(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return org


@router.post("/invitations", response_model=InvitationCreate, status_code=status.HTTP_201_CREATED)
async def create_invitation(
    data: InvitationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    existing_invitation = db.query(Invitation).filter(
        Invitation.organization_id == user.organization_id,
        Invitation.email == data.email,
        Invitation.status == InvitationStatus.PENDING,
    ).first()
    if existing_invitation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Pending invitation already exists for this email",
        )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    invitation = Invitation(
        organization_id=user.organization_id,
        email=data.email,
        role=data.role,
        token=token,
        status=InvitationStatus.PENDING,
        invited_by=user.id,
        expires_at=expires_at,
    )
    db.add(invitation)
    db.commit()
    db.refresh(invitation)

    from services.alerts.email_service import send_email
    from config import settings

    accept_url = f"{settings.frontend_url}/accept-invitation?token={token}"
    send_email(
        data.email,
        f"Invitation to join {user.organization.name} on SentinelASM",
        f"You have been invited to join {user.organization.name} as {data.role}.\n"
        f"Accept here: {accept_url}\n"
        f"This invitation expires in 7 days.",
    )

    return invitation


@router.get("/invitations", response_model=list[InvitationCreate])
async def list_invitations(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    invitations = db.query(Invitation).filter(
        Invitation.organization_id == user.organization_id
    ).order_by(Invitation.created_at.desc()).all()
    return invitations


@router.post("/invitations/{token}/accept", response_model=dict)
async def accept_invitation(
    token: str,
    data: InvitationAccept,
    db: Session = Depends(get_db),
):
    invitation = db.query(Invitation).filter(
        Invitation.token == token,
        Invitation.status == InvitationStatus.PENDING,
    ).first()
    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired invitation token",
        )

    if invitation.expires_at < datetime.now(timezone.utc):
        invitation.status = InvitationStatus.EXPIRED
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Invitation has expired",
        )

    existing_user = db.query(User).filter(User.username == data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    existing_email = db.query(User).filter(User.email == invitation.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    from auth.security import hash_password

    user = User(
        organization_id=invitation.organization_id,
        username=data.username,
        email=invitation.email,
        password_hash=hash_password(data.password),
        role=invitation.role,
    )
    db.add(user)

    invitation.status = InvitationStatus.ACCEPTED
    invitation.accepted_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Invitation accepted, account created"}


@router.post("/invitations/{invitation_id}/revoke")
async def revoke_invitation(
    invitation_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    invitation = db.query(Invitation).filter(
        Invitation.id == invitation_id,
        Invitation.organization_id == user.organization_id,
    ).first()
    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    invitation.status = InvitationStatus.REVOKED
    db.commit()

    return {"message": "Invitation revoked"}


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: APIKeyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    full_key, key_hash = APIKey.generate_key()
    expires_at = None
    if data.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_days)

    api_key = APIKey(
        organization_id=user.organization_id,
        name=data.name,
        key_hash=key_hash,
        key_prefix=full_key.split("_")[0],
        scopes=data.scopes,
        expires_at=expires_at,
        created_by=user.id,
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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    keys = db.query(APIKey).filter(
        APIKey.organization_id == user.organization_id
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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.organization_id == user.organization_id,
    ).first()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.organization_id == user.organization_id,
    ).first()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    db.delete(api_key)
    db.commit()

    return {"message": "API key deleted"}