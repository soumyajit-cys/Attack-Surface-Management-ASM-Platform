from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import jwt as token_service
from auth.dependencies import get_current_user
from auth.security import hash_password, verify_password
from auth.token_store import token_store
from auth.roles import ROLE_ADMIN
from config import settings
from models.organization import Organization
from models.user import User
from repositories.user_repository import UserRepository
from schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from services.alerts.email_service import send_email
from utils.database import get_db
from utils.rate_limiter import limiter

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


def _issue_tokens(db: Session, user: User) -> TokenResponse:
    access = token_service.create_access_token(user.id)
    refresh = token_service.create_refresh_token(user.id)
    token_store.store_refresh(refresh, user.id)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(
    request: Request,
    data: RegisterRequest,
    db: Session = Depends(get_db),
):
    repo = UserRepository(db)

    if repo.get_by_username(data.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    if repo.get_by_email(data.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    org = Organization(name=data.organization)
    db.add(org)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization name already taken",
        )

    user = User(
        organization_id=org.id,
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=ROLE_ADMIN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return _issue_tokens(db, user)


@router.post("/login")
async def login(
    data: LoginRequest,
    db: Session = Depends(get_db),
):
    repo = UserRepository(db)
    user = repo.get_by_username(data.username)

    if user is None or not verify_password(
        data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return _issue_tokens(db, user)


@router.post("/refresh")
async def refresh(
    data: RefreshRequest,
    db: Session = Depends(get_db),
):
    payload = token_service.decode_token(data.refresh_token)
    if (
        not payload
        or payload.get("type") != token_service.REFRESH
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = int(payload["sub"])

    if not token_store.refresh_valid(data.refresh_token, user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired or revoked",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access = token_service.create_access_token(user.id)
    new_refresh = token_service.create_refresh_token(user.id)
    token_store.rotate(data.refresh_token, new_refresh, user.id)

    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
    )


@router.post("/logout")
async def logout(
    data: LogoutRequest,
    db: Session = Depends(get_db),
):
    payload = token_service.decode_token(data.refresh_token)
    if payload:
        token_store.revoke(data.refresh_token)

    if data.access_token:
        access_payload = token_service.decode_token(data.access_token)
        if access_payload:
            token_store.revoke(data.access_token)

    return {"message": "logged out"}


@router.post("/forgot-password")
async def forgot_password(
    data: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    repo = UserRepository(db)
    user = repo.get_by_email(data.email)

    if user is None or not user.is_active:
        return {"message": "If that email exists, a reset link was sent"}

    token = token_service.create_password_reset_token(user.id)
    link = f"{settings.frontend_url}/reset-password?token={token}"

    send_email(
        user.email,
        "SentinelASM password reset",
        f"Reset your password here: {link}\n"
        "This link expires in 30 minutes.",
    )

    return {"message": "If that email exists, a reset link was sent"}


@router.post("/reset-password")
async def reset_password(
    data: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    payload = token_service.decode_token(data.token)
    if (
        not payload
        or payload.get("type") != token_service.PASSWORD_RESET
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    if token_store.reset_used(data.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token already used",
        )

    user = db.query(User).filter(
        User.id == int(payload["sub"])
    ).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token",
        )

    user.password_hash = hash_password(data.new_password)
    token_store.mark_reset_used(data.token)
    db.commit()

    return {"message": "Password updated"}


@router.get("/me")
async def me(
    user: User = Depends(get_current_user),
):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
    }