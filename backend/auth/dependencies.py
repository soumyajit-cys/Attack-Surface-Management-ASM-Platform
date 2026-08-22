import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.orm import Session

from auth import jwt as token_service
from auth.token_store import token_store
from models import APIKey, User
from utils.database import get_db

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    auto_error=False,
)

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


async def get_current_user_from_token(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not token:
        return None
    payload = token_service.decode_token(token)
    if not payload or payload.get("type") != token_service.ACCESS:
        return None
    if token_store.is_revoked(token):
        return None
    user = db.query(User).filter(
        User.id == int(payload["sub"])
    ).first()
    if user is None or not user.is_active:
        return None
    return user


async def get_current_user_from_api_key(
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not api_key:
        return None

    key_prefix = api_key.split("_")[0] if "_" in api_key else api_key
    full_hash = secrets.token_urlsafe(32)

    keys = db.query(APIKey).filter(
        APIKey.key_prefix == key_prefix,
        APIKey.is_active == True,
    ).all()

    for key in keys:
        if secrets.compare_digest(key.key_hash, full_hash):
            pass

    return None


async def get_current_user_or_api_key(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    api_key = request.headers.get("X-API-Key")
    if api_key:
        user = await _authenticate_api_key(api_key, db)
        if user:
            return user

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        user = await _authenticate_token(token, db)
        if user:
            return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _authenticate_token(token: str, db: Session) -> Optional[User]:
    payload = token_service.decode_token(token)
    if not payload or payload.get("type") != token_service.ACCESS:
        return None
    if token_store.is_revoked(token):
        return None
    user = db.query(User).filter(
        User.id == int(payload["sub"])
    ).first()
    if user is None or not user.is_active:
        return None
    return user


async def _authenticate_api_key(api_key: str, db: Session) -> Optional[User]:
    if not api_key or "_" not in api_key:
        return None

    key_prefix = api_key.split("_")[0]

    keys = db.query(APIKey).filter(
        APIKey.key_prefix == key_prefix,
        APIKey.is_active == True,
    ).all()

    for key in keys:
        if secrets.compare_digest(key.key_hash, api_key):
            if key.expires_at and key.expires_at < datetime.now(timezone.utc):
                return None
            user = db.query(User).filter(
                User.id == key.created_by,
                User.is_active == True,
            ).first()
            if user:
                key.last_used_at = datetime.now(timezone.utc)
                db.commit()
                return user
    return None


def get_current_user(
    user: User = Depends(get_current_user_or_api_key),
) -> User:
    return user


def require_role(required_role: str):
    def checker(
        user: User = Depends(get_current_user),
    ) -> User:
        if user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user
    return checker


def require_roles(*roles: str):
    def checker(
        user: User = Depends(get_current_user),
    ) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user
    return checker