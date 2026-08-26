"""``/api/v1/auth`` -- authentication endpoints.

Parity with the legacy ``/auth`` routes plus:
- consistent error envelope (see ``app.core.errors``),
- audit logging of register / login / refresh / logout / reset events,
- ``/me`` returns the organization name and effective permissions
  (fixes the frontend's empty-org-name bug at the source).
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import jwt as token_service
from auth.roles import ROLE_ADMIN
from auth.security import hash_password, verify_password
from auth.token_store import token_store
from models.user import User
from models.organization import Organization
from schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
)

from app.core.audit import client_ip, record_audit
from app.core.config import settings
from app.core.errors import BadRequestError, ConflictError, UnauthenticatedError
from app.core.permissions import permissions_for_role
from app.db.session import get_db
from app.api.deps import current_principal, Principal
from app.schemas.auth import MessageOut, TokenBundle, UserOut
from utils.rate_limiter import limiter
from services.alerts.email_service import send_email

router = APIRouter(prefix="/auth", tags=["auth"])


def _user_out(user: User, organization_name: str | None = None) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=organization_name,
        permissions=sorted(p.value for p in permissions_for_role(user.role)),
    )


def _issue_tokens(db: Session, user: User) -> TokenBundle:
    org = db.get(Organization, user.organization_id)
    access = token_service.create_access_token(user.id)
    refresh = token_service.create_refresh_token(user.id)
    token_store.store_refresh(refresh, user.id)
    return TokenBundle(
        access_token=access,
        refresh_token=refresh,
        user=_user_out(user, organization_name=org.name if org else None),
    )


@router.post("/register", response_model=TokenBundle, status_code=status.HTTP_201_CREATED)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def register(
    request: Request,
    data: RegisterRequest,
    db: Session = Depends(get_db),
) -> TokenBundle:
    from sqlalchemy.orm import exc as orm_exc

    existing = (
        db.query(User).filter(User.username == data.username).first()
    )
    if existing is not None:
        raise ConflictError("Username already taken", code="username_taken")

    existing = db.query(User).filter(User.email == data.email).first()
    if existing is not None:
        raise ConflictError("Email already registered", code="email_taken")

    org = Organization(name=data.organization)
    db.add(org)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ConflictError(
            "Organization name already taken", code="organization_taken"
        )

    user = User(
        organization_id=org.id,
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=ROLE_ADMIN,
    )
    db.add(user)
    try:
        db.flush()
    except (IntegrityError, orm_exc.FlushError):
        db.rollback()
        raise ConflictError("Account could not be created", code="registration_failed")

    record_audit(
        db,
        organization_id=org.id,
        actor=user.username,
        action="auth.register",
        details={"email": data.email},
        request=request,
    )
    db.commit()
    db.refresh(user)

    return _issue_tokens(db, user)


@router.post("/login", response_model=TokenBundle)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenBundle:
    user: User | None = (
        db.query(User).filter(User.username == data.username).first()
    )

    if user is None or not verify_password(data.password, user.password_hash):
        if user is not None:
            record_audit(
                db,
                organization_id=user.organization_id,
                actor=user.username,
                action="auth.login_failed",
                details={"ip": client_ip(request)},
                request=request,
            )
            db.commit()
        raise UnauthenticatedError("Invalid credentials")

    if not user.is_active:
        raise BadRequestError("Account is disabled", code="account_disabled")

    bundle = _issue_tokens(db, user)
    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.login",
        details={"ip": client_ip(request)},
        request=request,
    )
    db.commit()
    return bundle


@router.post("/refresh", response_model=TokenBundle)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def refresh(
    request: Request,
    data: RefreshRequest,
    db: Session = Depends(get_db),
) -> TokenBundle:
    payload = token_service.decode_token(data.refresh_token)
    if not payload or payload.get("type") != token_service.REFRESH:
        raise UnauthenticatedError("Invalid refresh token")

    user_id = int(payload["sub"])
    if not token_store.refresh_valid(data.refresh_token, user_id):
        raise UnauthenticatedError("Refresh token expired or revoked")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise UnauthenticatedError("User not found or inactive")

    access = token_service.create_access_token(user.id)
    new_refresh = token_service.create_refresh_token(user.id)
    token_store.rotate(data.refresh_token, new_refresh, user.id)

    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.refresh",
        request=request,
    )
    db.commit()

    return _issue_tokens(db, user)


@router.post("/logout", response_model=MessageOut)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def logout(
    request: Request,
    data: LogoutRequest,
    db: Session = Depends(get_db),
) -> MessageOut:
    payload = token_service.decode_token(data.refresh_token)
    if payload:
        token_store.revoke(data.refresh_token)
        user = db.get(User, int(payload["sub"]))
        if user is not None:
            record_audit(
                db,
                organization_id=user.organization_id,
                actor=user.username,
                action="auth.logout",
                request=request,
            )
            db.commit()

    if data.access_token:
        access_payload = token_service.decode_token(data.access_token)
        if access_payload:
            token_store.revoke(data.access_token)

    return MessageOut(message="logged out")


@router.post("/forgot-password", response_model=MessageOut)
@limiter.limit("3/minute")
async def forgot_password(
    request: Request,
    data: ForgotPasswordRequest,
    db: Session = Depends(get_db),
) -> MessageOut:
    user: User | None = db.query(User).filter(User.email == data.email).first()
    generic = MessageOut(message="If that email exists, a reset link was sent")

    if user is None or not user.is_active:
        return generic

    token = token_service.create_password_reset_token(user.id)
    link = f"{settings.frontend_url}/reset-password?token={token}"

    send_email(
        user.email,
        "SentinelASM password reset",
        f"Reset your password here: {link}\n"
        "This link expires in 30 minutes.",
    )

    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.forgot_password",
        request=request,
    )
    db.commit()
    return generic


@router.post("/reset-password", response_model=MessageOut)
@limiter.limit("3/minute")
async def reset_password(
    request: Request,
    data: ResetPasswordRequest,
    db: Session = Depends(get_db),
) -> MessageOut:
    payload = token_service.decode_token(data.token)
    if not payload or payload.get("type") != token_service.PASSWORD_RESET:
        raise BadRequestError("Invalid or expired reset token", code="invalid_reset_token")

    if token_store.reset_used(data.token):
        raise BadRequestError("Reset token already used", code="reset_token_used")

    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise BadRequestError("Invalid reset token", code="invalid_reset_token")

    user.password_hash = hash_password(data.new_password)
    token_store.mark_reset_used(data.token)
    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.reset_password",
        request=request,
    )
    db.commit()

    return MessageOut(message="Password updated")


@router.get("/me", response_model=UserOut)
async def me(principal: Principal = Depends(current_principal)) -> UserOut:
    user = principal.user
    org = None
    if principal.via != "api_key":
        org = None  # filled below via db-free path when needed
    # Organization name is fetched lazily through the user's relationship to
    # avoid a second dependency in the common JWT case.
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=user.organization.name if user.organization else None,
        permissions=sorted(p.value for p in principal.permissions),
    )
