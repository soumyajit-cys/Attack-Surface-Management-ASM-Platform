"""Authentication principals and permission dependencies for v1 routes.

A :class:`Principal` is the authenticated caller: the backing ``User`` plus
*how* they authenticated (JWT bearer vs API key) and their effective
permission set. API-key scopes are finally **enforced**: effective
permissions are the intersection of the owning user's role permissions and
the key's coarse scope grants.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from auth import jwt as token_service
from auth import stepup as stepup_store
from auth.stepup import StepupUnavailable
from auth.token_store import token_store
from models import APIKey, User

from app.core.errors import UnauthenticatedError
from app.core.permissions import (
    Permission,
    effective_permissions,
    require_permissions as enforce_permissions,
)
from app.db.session import get_db

AuthMethod = Literal["jwt", "api_key"]


@dataclass(frozen=True)
class Principal:

    user: User
    via: AuthMethod
    permissions: frozenset[Permission]

    @property
    def organization_id(self) -> int:
        return self.user.organization_id

    @property
    def is_api_key(self) -> bool:
        return self.via == "api_key"


def _load_user(db: Session, user_id: int) -> User | None:
    return (
        db.query(User)
        .filter(User.id == user_id, User.is_active.is_(True))
        .first()
    )


def authenticate_bearer(token: str, db: Session) -> Principal | None:
    payload = token_service.decode_token(token)
    if not payload or payload.get("type") != token_service.ACCESS:
        return None
    if token_store.is_revoked(token):
        return None
    user = _load_user(db, int(payload["sub"]))
    if user is None:
        return None
    return Principal(
        user=user,
        via="jwt",
        permissions=effective_permissions(user.role),
    )


def authenticate_api_key(raw_key: str, db: Session) -> Principal | None:
    import hashlib

    if not raw_key or "_" not in raw_key:
        return None

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key: APIKey | None = (
        db.query(APIKey)
        .filter(APIKey.key_hash == key_hash, APIKey.is_active.is_(True))
        .first()
    )
    if key is None:
        return None
    if key.expires_at and key.expires_at < datetime.now(timezone.utc):
        return None

    user = _load_user(db, key.created_by)
    if user is None or user.organization_id != key.organization_id:
        return None

    key.last_used_at = datetime.now(timezone.utc)
    db.commit()

    return Principal(
        user=user,
        via="api_key",
        permissions=effective_permissions(user.role, key.scopes),
    )


def get_principal(request: Request, db: Session) -> Principal:
    api_key = request.headers.get("X-API-Key")
    if api_key:
        principal = authenticate_api_key(api_key, db)
        if principal:
            return principal

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        principal = authenticate_bearer(auth_header[7:], db)
        if principal:
            return principal

    raise UnauthenticatedError()


def current_principal(
    request: Request,
    db: Session = Depends(get_db),
) -> Principal:
    """FastAPI dependency: any authenticated principal (JWT or API key)."""
    return get_principal(request, db)


def principal_or_enroll(
    request: Request,
    db: Session = Depends(get_db),
) -> Principal:
    """Like :func:`current_principal`, but additionally accepts a restricted
    ``scope="enroll_2fa"`` token (Phase 1.5.4).

    Used ONLY by the 2FA enrollment endpoints and ``GET /auth/me`` so users
    forced into enrollment by ``require_2fa`` can complete it. Every other
    route keeps ``current_principal``, which rejects restricted tokens
    because their type is neither access nor a valid API key.
    """
    try:
        return get_principal(request, db)
    except UnauthenticatedError:
        pass
    auth_header = request.headers.get("Authorization") or ""
    if not auth_header.startswith("Bearer "):
        raise UnauthenticatedError()
    payload = token_service.decode_token(auth_header[7:])
    if (not payload or payload.get("type") != token_service.RESTRICTED
            or payload.get("scope") != "enroll_2fa"):
        raise UnauthenticatedError()
    user = _load_user(db, int(payload["sub"]))
    if user is None:
        raise UnauthenticatedError()
    return Principal(
        user=user,
        via="jwt",
        permissions=effective_permissions(user.role),
    )


def require_permissions_dep(*needed: Permission):
    """Dependency factory: authenticate then enforce permissions."""

    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        enforce_permissions(principal.permissions, *needed)
        return principal

    return dependency


def _bearer_access_jti(request: Request) -> str | None:
    """jti of the presenting JWT access token (None for API keys etc.)."""
    auth_header = request.headers.get("Authorization") or ""
    if not auth_header.startswith("Bearer "):
        return None
    payload = token_service.decode_token(auth_header[7:])
    if not payload or payload.get("type") != token_service.ACCESS:
        return None
    return payload.get("jti")


def require_step_up_dep():
    """Dependency factory: require a live step-up marker.

    Sensitive org-admin write routes stack this AFTER
    ``require_permissions_dep`` (permission failures win presentation
    order). The marker is a server-side Redis entry keyed by user id +
    presenting access jti with a 300 s TTL, planted only by
    ``POST /auth/step-up``; each successful use is audited, never
    revealing credentials. Redis loss fails closed.
    """

    def dependency(
        request: Request,
        principal: Principal = Depends(current_principal),
        db: Session = Depends(get_db),
    ) -> None:
        from app.core.audit import client_ip, record_audit
        from app.core.errors import ForbiddenError, ServiceUnavailableError

        if principal.is_api_key:
            # A marker must belong to a user session; API keys cannot
            # step up at all (answer like the other step-up route).
            raise ForbiddenError(
                "Step-up re-authentication requires a user session",
                code="step_up_required",
            )
        jti = _bearer_access_jti(request)
        try:
            ok = stepup_store.active(principal.user.id, jti)
        except StepupUnavailable:
            raise ServiceUnavailableError(
                "Step-up verification temporarily unavailable",
                code="auth_unavailable",
            )
        if not ok:
            raise ForbiddenError(
                "Step-up re-authentication required",
                code="step_up_required",
            )
        record_audit(
            db,
            organization_id=principal.organization_id,
            actor=principal.user.username,
            action="auth.stepup_used",
            details={"ip": client_ip(request), "route": request.url.path},
            request=request,
        )
        db.commit()

    return dependency
