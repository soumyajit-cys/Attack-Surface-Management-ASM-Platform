"""``/api/v1/auth`` -- authentication endpoints.

Parity with the legacy ``/auth`` routes plus:
- consistent error envelope (see ``app.core.errors``),
- audit logging of register / login / refresh / logout / reset events,
- ``/me`` returns the organization name and effective permissions
  (fixes the frontend's empty-org-name bug at the source).
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, exc as orm_exc
from datetime import datetime, timezone

from auth import jwt as token_service
from auth.roles import ROLE_ADMIN
from auth.security import hash_password, verify_password
from auth.token_store import token_store
from models.user import User
from models.organization import Organization
from schemas.auth import (
    ChangePasswordRequest,
    ConfirmRequest,
    EnrollRequest,
    ForgotPasswordRequest,
    Login2FARequest,
    LoginRequest,
    LogoutRequest,
    ReauthRequest,
    RefreshRequest,
    RegisterRequest,
    Reset2FARequest,
    ResetPasswordRequest,
    StepUpRequest,
    UnlockAccountRequest,
)

from app.core.audit import client_ip, record_audit
from app.core.config import settings
from app.core.errors import BadRequestError, ConflictError, UnauthenticatedError
from app.core.permissions import permissions_for_role
from app.db.session import get_db
from app.api.deps import (
    current_principal,
    Principal,
    principal_or_enroll,
    require_permissions_dep,
    require_step_up_dep,
)
from app.core.permissions import Permission
from app.schemas.auth import (
    MessageOut,
    MfaChallenge,
    RestrictedToken,
    TokenBundle,
    UserOut,
)
from utils.logger import logger
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
        totp_enabled=bool(user.totp_enabled),
    )


def _issue_tokens(db: Session, user: User) -> TokenBundle:
    org = db.get(Organization, user.organization_id)
    access = token_service.create_access_token(user.id)
    refresh = token_service.create_refresh_token(user.id)
    access_jti = token_service.decode_token(access).get("jti")
    refresh_jti = token_service.decode_token(refresh).get("jti")
    token_store.store_access(access, user.id, sibling=refresh_jti)
    token_store.store_refresh(refresh, user.id, sibling=access_jti)
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


@router.post(
    "/login",
    response_model=TokenBundle | MfaChallenge | RestrictedToken,
)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db),
):
    """Password step. Returns a TokenBundle, an MFA challenge, or a
    restricted enrollment token -- never more than one credential kind."""
    from auth import lockout as lockout_mod
    from auth.security import DUMMY_PASSWORD_HASH, DUMMY_PASSWORD_PREIMAGE
    from utils.logger import logger

    identifier = data.username.strip().lower()
    ip = client_ip(request) or "unknown"
    acct, ipc = lockout_mod.account_counter(), lockout_mod.ip_counter()

    # Lock state first: Redis loss fails closed with the generic response
    # (identical to unknown-user/wrong-password; see test_redis_down_*).
    try:
        acct_locked = acct.is_locked(identifier)
        ip_locked = ipc.is_locked(ip)
    except lockout_mod.LockoutUnavailable as exc:
        from app.core.errors import ServiceUnavailableError

        logger.error("lockout store unreachable during login: %s",
                     type(exc).__name__)
        raise ServiceUnavailableError(
            "Authentication temporarily unavailable",
            code="auth_unavailable",
        )

    user: User | None = (
        db.query(User).filter(User.username == data.username).first()
    )
    # Always burn exactly one bcrypt so unknown, wrong, and locked attempts
    # share a timing shape (dummy constant for unknown users).
    if user is None:
        password_ok = verify_password(
            DUMMY_PASSWORD_PREIMAGE, DUMMY_PASSWORD_HASH)
    else:
        password_ok = verify_password(data.password, user.password_hash)

    if acct_locked or ip_locked:
        # Locked accounts reject even correct passwords until expiry.
        # No remaining-time or lock-status leaks to the client.
        raise UnauthenticatedError("Invalid credentials")

    if user is None or not password_ok:
        try:
            # Account takes precedence: when it engages, the identity is
            # contained and the IP is NOT also charged for this attempt.
            # This keeps admin unlock coherent (releasing the account
            # releases the login) while the IP counter still catches
            # multi-account floods from one source.
            engaged, seconds, scope = False, 0, ""
            if user is not None:
                engaged, seconds = acct.register_failure(identifier)
                scope = "account"
            if not engaged:
                ip_engaged, ip_seconds = ipc.register_failure(ip)
                if ip_engaged:
                    engaged, seconds, scope = True, ip_seconds, "ip"
            if engaged:
                key = (acct._key(identifier) if scope == "account"
                       else ipc._key(ip))
                if user is not None:
                    # AuditLog.organization_id is FK non-nullable, so only
                    # known-user lockouts are audited; unknown-user IP
                    # lockouts are logged server-side instead.
                    record_audit(
                        db,
                        organization_id=user.organization_id,
                        actor=data.username,
                        action="auth.account_locked",
                        details={"key": key, "scope": scope,
                                 "lock_seconds": seconds},
                        request=request,
                    )
                    db.commit()
                else:
                    logger.warning(
                        "IP lockout engaged (unknown-user flood): key=%s "
                        "lock_seconds=%s", key, seconds)
        except lockout_mod.LockoutUnavailable:
            logger.warning("lockout store unreachable during failure "
                           "recording; failing login closed")
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

    # Phase 1.5.4: users with 2FA enabled never receive tokens here. They
    # get a single-use 5-minute challenge for POST /auth/login/2fa.
    # NOTE: the password-failure counter is intentionally NOT reset here;
    # only a completed 2FA exchange resets the TOTP counter.
    if user.totp_enabled:
        challenge = token_service.create_mfa_challenge_token(user.id)
        token_store.store_mfa_challenge(challenge)
        return {"mfa_required": True, "challenge": challenge}  # type: ignore[return-value]

    org = db.get(Organization, user.organization_id)
    if org is not None and org.require_2fa and not user.totp_enabled:
        # No usable credential may be issued: a restricted enrollment token
        # valid only on the 2FA enrollment endpoints and /auth/me.
        token = token_service.create_restricted_token(user.id, "enroll_2fa")
        return {"scope": "enroll_2fa", "token": token}  # type: ignore[return-value]

    try:
        acct.register_success(identifier)
    except lockout_mod.LockoutUnavailable:
        # Counter keeps its (decaying) state; erring toward locked is safe.
        logger.warning("lockout store unreachable during success reset")

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
        # Reuse signal: a revoked-but-decodable refresh token means the
        # bearer holds a rotated-out credential (theft indicator). Burn the
        # whole family so the thief's copy and the victim's current tokens
        # all die, audit it, and answer with the generic 401.
        if token_store.is_revoked(data.refresh_token):
            revoked = token_store.revoke_family(user_id)
            user = db.get(User, user_id)
            if user is not None:
                # AuditLog.organization_id is FK non-nullable: users that
                # vanished since issuance get a server log line instead.
                record_audit(
                    db,
                    organization_id=user.organization_id,
                    actor=user.username,
                    action="auth.refresh_reuse",
                    details={"revoked_sessions": revoked},
                    request=request,
                )
                db.commit()
            else:
                from utils.logger import logger

                logger.warning(
                    "refresh reuse for unknown user id=%s revoked=%s",
                    user_id, revoked)
        raise UnauthenticatedError("Refresh token expired or revoked")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise UnauthenticatedError("User not found or inactive")

    access = token_service.create_access_token(user.id)
    new_refresh = token_service.create_refresh_token(user.id)
    access_jti = token_service.decode_token(access).get("jti")
    refresh_jti = token_service.decode_token(new_refresh).get("jti")
    token_store.store_access(access, user.id, sibling=refresh_jti)
    token_store.rotate(data.refresh_token, new_refresh, user.id,
                       sibling=access_jti)

    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.refresh",
        request=request,
    )
    db.commit()

    org = db.get(Organization, user.organization_id)
    return TokenBundle(
        access_token=access,
        refresh_token=new_refresh,
        user=_user_out(user, organization_name=org.name if org else None),
    )


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


@router.post("/admin/unlock-account", response_model=MessageOut)
async def admin_unlock_account(
    request: Request,
    data: UnlockAccountRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(
        require_permissions_dep(Permission.ORG_MANAGE)),
    _stepup: None = Depends(require_step_up_dep()),
) -> MessageOut:
    """Clear a user's login-lockout counters (admin early-unlock).

    Scoped to the caller's organization: other tenants' users (and unknown
    usernames) get the identical 404. Writes an audit event on success.
    """
    from app.core.errors import NotFoundError
    from auth import lockout as lockout_mod

    target: User | None = (
        db.query(User)
        .filter(User.username == data.username,
                User.organization_id == principal.organization_id)
        .first()
    )
    if target is None:
        raise NotFoundError("User not found", code="user_not_found")
    cleared = lockout_mod.account_counter().clear(data.username)
    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="auth.account_unlocked",
        details={"username": data.username, "cleared_keys": cleared},
        request=request,
    )
    db.commit()
    return MessageOut(message="Account unlocked")


def _totp_counters():
    """TOTP-step lockout counters (separate scopes from password login)."""
    from auth import lockout as lockout_mod
    from app.core.config import settings

    return (
        lockout_mod.AttemptCounter(
            "totp-acct", settings.login_max_attempts,
            settings.login_attempt_window_seconds,
            settings.login_lockout_base_seconds,
            settings.login_lockout_max_seconds),
        lockout_mod.AttemptCounter(
            "totp-ip", settings.login_max_attempts,
            settings.login_attempt_window_seconds,
            settings.login_lockout_base_seconds,
            settings.login_lockout_max_seconds),
    )


def _replace_recovery_codes(db: Session, user: User) -> list[str]:
    """Delete all codes and issue a fresh batch of 10 (returns plaintext)."""
    from auth import totp as totp_mod
    from models.recovery_code import RecoveryCode

    db.query(RecoveryCode).filter(
        RecoveryCode.user_id == user.id).delete()
    codes = totp_mod.new_recovery_codes()
    for code in codes:
        db.add(RecoveryCode(user_id=user.id,
                            code_hash=totp_mod.hash_recovery_code(code)))
    db.flush()
    return codes


@router.post("/2fa/enroll")
async def enroll_2fa(
    request: Request,
    data: EnrollRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(principal_or_enroll),
):
    """Issue a pending TOTP secret (+otpauth URI). Never logged/returned
    again except here. Re-enrolling while enabled additionally requires a
    current code (decision 1.5.4.2)."""
    from auth import totp as totp_mod

    user = principal.user
    if not verify_password(data.password, user.password_hash):
        raise UnauthenticatedError("Invalid credentials")
    if user.totp_enabled:
        if not data.code or totp_mod.verify_code(
                user.totp_secret or "", data.code,
                user.totp_last_step) is None:
            raise BadRequestError(
                "Current code required to re-enroll", code="reauth_required")
    secret = totp_mod.new_secret()
    user.totp_secret = secret
    record_audit(
        db, organization_id=user.organization_id, actor=user.username,
        action="auth.2fa_enroll", request=request,
    )
    db.commit()
    return {"secret": secret,
            "otpauth_uri": totp_mod.otpauth_uri(secret, user.username)}


@router.post("/2fa/confirm")
async def confirm_2fa(
    request: Request,
    data: ConfirmRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(principal_or_enroll),
):
    """Activate 2FA with a first valid code; returns 10 recovery codes ONCE."""
    from auth import totp as totp_mod
    from app.core.errors import BadRequestError as BadRequest

    user = principal.user
    if not user.totp_secret:
        raise BadRequest("Nothing to confirm -- enroll first",
                         code="nothing_to_confirm")
    step = totp_mod.verify_code(user.totp_secret, data.code, None)
    if step is None or not totp_mod.claim_totp_step(db, user.id, step):
        raise BadRequest("Invalid code", code="invalid_code")
    user.totp_enabled = True
    codes = _replace_recovery_codes(db, user)
    record_audit(
        db, organization_id=user.organization_id, actor=user.username,
        action="auth.2fa_enabled", request=request,
        details={"totp_enabled": True},
    )
    db.commit()
    return {"recovery_codes": codes}


@router.post("/2fa/disable")
async def disable_2fa(
    request: Request,
    data: ReauthRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
):
    """Fully switch 2FA off (password + current code or recovery code)."""
    from auth import totp as totp_mod
    from models.recovery_code import RecoveryCode

    user = principal.user
    if not verify_password(data.password, user.password_hash):
        raise UnauthenticatedError("Invalid credentials")
    ok = (user.totp_secret and totp_mod.verify_code(
        user.totp_secret, data.code, user.totp_last_step) is not None)
    if not ok:
        row = db.query(RecoveryCode).filter(
            RecoveryCode.user_id == user.id,
            RecoveryCode.used_at.is_(None)).all()
        match = next(
            (r for r in row
             if totp_mod.verify_recovery_code(data.code, r.code_hash)),
            None)
        if match is None:
            raise BadRequestError("Invalid code", code="invalid_code")
        match.used_at = datetime.now(timezone.utc)
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_step = None
    db.query(RecoveryCode).filter(
        RecoveryCode.user_id == user.id).delete()
    record_audit(
        db, organization_id=user.organization_id, actor=user.username,
        action="auth.2fa_disabled", request=request,
        details={"totp_enabled": False},
    )
    db.commit()
    return MessageOut(message="2FA disabled")


@router.post("/2fa/regenerate-codes")
async def regenerate_2fa_codes(
    request: Request,
    data: ReauthRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
):
    """Replace all recovery codes (old batch dies). Requires 2FA enabled."""
    from auth import totp as totp_mod

    user = principal.user
    if not user.totp_enabled or not user.totp_secret:
        raise BadRequestError("2FA is not enabled", code="2fa_not_enabled")
    if not verify_password(data.password, user.password_hash):
        raise UnauthenticatedError("Invalid credentials")
    if totp_mod.verify_code(user.totp_secret, data.code,
                            user.totp_last_step) is None:
        raise BadRequestError("Invalid code", code="invalid_code")
    codes = _replace_recovery_codes(db, user)
    record_audit(
        db, organization_id=user.organization_id, actor=user.username,
        action="auth.2fa_codes_regenerated", request=request,
    )
    db.commit()
    return {"recovery_codes": codes}


@router.post("/login/2fa")
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def login_2fa(
    request: Request,
    data: Login2FARequest,
    db: Session = Depends(get_db),
):
    """Exchange a single-use challenge + TOTP/recovery code for tokens."""
    from app.core.errors import ServiceUnavailableError
    from auth import lockout as lockout_mod
    from auth import totp as totp_mod
    from models.recovery_code import RecoveryCode

    def _unavailable(exc: Exception):
        logger.error("lockout store unreachable during 2FA: %s",
                     type(exc).__name__)
        raise ServiceUnavailableError(
            "Authentication temporarily unavailable",
            code="auth_unavailable",
        )

    ip = client_ip(request) or "unknown"
    tacct, tipc = _totp_counters()
    try:
        if tipc.is_locked(ip):
            raise UnauthenticatedError("Invalid credentials")
    except lockout_mod.LockoutUnavailable as exc:
        _unavailable(exc)
    try:
        user_id = token_store.consume_mfa_challenge(data.challenge)
    except Exception as exc:
        _unavailable(exc)
    user = db.get(User, user_id) if user_id else None
    if user is None or not user.is_active:
        try:
            tipc.register_failure(ip)
        except lockout_mod.LockoutUnavailable:
            pass
        raise UnauthenticatedError("Invalid credentials")
    try:
        locked = tacct.is_locked(user.username) or tipc.is_locked(ip)
    except lockout_mod.LockoutUnavailable as exc:
        _unavailable(exc)
    if locked:
        raise UnauthenticatedError("Invalid credentials")

    authenticated = False
    if (user.totp_enabled and user.totp_secret and len(data.code) == 6
            and (step := totp_mod.verify_code(
                user.totp_secret, data.code, None)) is not None
            and totp_mod.claim_totp_step(db, user.id, step)):
        authenticated = True
    elif not authenticated:
        for row in db.query(RecoveryCode).filter(
                RecoveryCode.user_id == user.id,
                RecoveryCode.used_at.is_(None)).all():
            if totp_mod.verify_recovery_code(data.code, row.code_hash):
                row.used_at = datetime.now(timezone.utc)
                authenticated = True
                break
    if not authenticated:
        try:
            # Account precedence (same rule as password login): the IP is
            # charged only when the account does not engage.
            engaged, seconds, scope = False, 0, ""
            engaged, seconds = tacct.register_failure(user.username)
            scope = "account"
            if not engaged:
                ip_engaged, ip_seconds = tipc.register_failure(ip)
                if ip_engaged:
                    engaged, seconds, scope = True, ip_seconds, "ip"
            if engaged:
                record_audit(
                    db, organization_id=user.organization_id,
                    actor=user.username, action="auth.totp_locked",
                    details={"scope": scope, "lock_seconds": seconds},
                    request=request,
                )
                db.commit()
        except lockout_mod.LockoutUnavailable:
            logger.warning("lockout store unreachable during 2FA failure")
        raise UnauthenticatedError("Invalid credentials")

    # Full 2FA success resets ONLY the TOTP counter (never password's).
    try:
        tacct.register_success(user.username)
    except lockout_mod.LockoutUnavailable:
        logger.warning("lockout store unreachable during 2FA success reset")
    bundle = _issue_tokens(db, user)
    record_audit(
        db, organization_id=user.organization_id, actor=user.username,
        action="auth.login_2fa", details={"ip": client_ip(request)},
        request=request,
    )
    db.commit()
    return bundle


@router.post("/admin/reset-2fa", response_model=MessageOut)
async def admin_reset_2fa(
    request: Request,
    data: Reset2FARequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(
        require_permissions_dep(Permission.ORG_MANAGE)),
    _stepup: None = Depends(require_step_up_dep()),
) -> MessageOut:
    """Clear a user's 2FA state (lost device). Same-org only; unknown and
    cross-org usernames share one 404. Revokes the user's sessions."""
    from app.core.errors import NotFoundError
    from models.recovery_code import RecoveryCode

    target: User | None = (
        db.query(User)
        .filter(User.username == data.username,
                User.organization_id == principal.organization_id)
        .first()
    )
    if target is None:
        raise NotFoundError("User not found", code="user_not_found")
    target.totp_enabled = False
    target.totp_secret = None
    target.totp_last_step = None
    db.query(RecoveryCode).filter(
        RecoveryCode.user_id == target.id).delete()
    revoked = token_store.revoke_family(target.id)
    record_audit(
        db, organization_id=principal.organization_id,
        actor=principal.user.username, action="auth.2fa_reset",
        details={"username": data.username, "revoked_sessions": revoked},
        request=request,
    )
    db.commit()
    return MessageOut(message="2FA reset")


@router.post("/step-up", response_model=MessageOut)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def step_up(
    request: Request,
    data: StepUpRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> MessageOut:
    """Step-up re-authentication for the calling session on success.

    Same lockout counters and uniform failures as login; with 2FA enabled
    a TOTP or recovery code is required. Plants a SHORT-LIVED server-side
    redis marker (auth.stepup, TTL 300 s) bound to the presenting access
    jti so ``require_step_up_dep`` routes answer normally for this
    session. No client-held token is issued.
    """
    from auth import lockout as lockout_mod
    from auth import stepup as stepup_mod
    from auth import totp as totp_mod
    from auth.stepup import StepupUnavailable
    from app.core.errors import ForbiddenError, ServiceUnavailableError
    from models.recovery_code import RecoveryCode

    if principal.is_api_key:
        raise ForbiddenError("Step-up requires a user session",
                             code="api_key_forbidden")

    user = principal.user
    identifier = user.username.strip().lower()
    ip = client_ip(request) or "unknown"
    acct, ipc = lockout_mod.account_counter(), lockout_mod.ip_counter()
    try:
        if acct.is_locked(identifier) or ipc.is_locked(ip):
            raise UnauthenticatedError("Invalid credentials")
    except lockout_mod.LockoutUnavailable as exc:
        logger.error("lockout store unreachable during step-up: %s",
                     type(exc).__name__)
        raise ServiceUnavailableError(
            "Authentication temporarily unavailable",
            code="auth_unavailable",
        )

    password_ok = verify_password(data.password, user.password_hash)
    code_ok = True
    matched_recovery = None
    if password_ok and user.totp_enabled:
        code_ok = False
        if (user.totp_secret and data.code and len(data.code) == 6
                and (step := totp_mod.verify_code(
                    user.totp_secret, data.code,
                    user.totp_last_step)) is not None
                and totp_mod.claim_totp_step(db, user.id, step)):
            code_ok = True
        elif data.code:
            for row in db.query(RecoveryCode).filter(
                    RecoveryCode.user_id == user.id,
                    RecoveryCode.used_at.is_(None)).all():
                if totp_mod.verify_recovery_code(data.code, row.code_hash):
                    matched_recovery = row
                    code_ok = True
                    break

    if not password_ok or not code_ok:
        try:
            engaged, seconds, scope = False, 0, ""
            engaged, seconds = acct.register_failure(identifier)
            scope = "account"
            if not engaged:
                ip_engaged, ip_seconds = ipc.register_failure(ip)
                if ip_engaged:
                    engaged, seconds, scope = True, ip_seconds, "ip"
            if engaged and seconds:
                record_audit(
                    db, organization_id=user.organization_id,
                    actor=user.username, action="auth.account_locked",
                    details={"scope": scope, "lock_seconds": seconds},
                    request=request,
                )
            db.commit()
        except lockout_mod.LockoutUnavailable:
            logger.warning("lockout store unreachable during step-up "
                           "failure recording")
        raise UnauthenticatedError("Invalid credentials")

    if matched_recovery is not None:
        matched_recovery.used_at = datetime.now(timezone.utc)

    auth_header = request.headers.get("Authorization") or ""
    current_jti = (
        token_service.decode_token(auth_header[7:]).get("jti")
        if auth_header.startswith("Bearer ") else None
    )
    try:
        stepup_mod.grant(user.id, current_jti)
    except StepupUnavailable:
        logger.error("step-up store unreachable; failing closed")
        raise ServiceUnavailableError(
            "Step-up verification temporarily unavailable",
            code="auth_unavailable",
        )
    record_audit(
        db, organization_id=user.organization_id,
        actor=user.username, action="auth.stepup_granted",
        details={"ip": client_ip(request)},
        request=request,
    )
    db.commit()
    return MessageOut(message="Step-up verified")


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
    revoked = token_store.revoke_family(user.id)
    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.reset_password",
        request=request,
    )
    record_audit(
        db,
        organization_id=user.organization_id,
        actor=user.username,
        action="auth.sessions_revoked",
        details={"revoked_sessions": revoked, "reason": "password_reset"},
        request=request,
    )
    db.commit()

    return MessageOut(message="Password updated")


@router.post("/change-password", response_model=MessageOut)
@limiter.limit(f"{settings.rate_limit_auth_requests_per_minute}/minute")
async def change_password(
    request: Request,
    data: ChangePasswordRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> MessageOut:
    """Change the caller's own password (housekeeping, task 1.6.0).

    Interactive sessions only: API keys are rejected (a stolen key must not
    be able to take over the password). Requires the current password plus
    a TOTP/recovery code when 2FA is on. Revokes every OTHER session while
    the caller's access token keeps working; failures feed the shared login
    lockout counters with the identical 401 envelope.
    """
    from app.core.errors import ForbiddenError

    if principal.is_api_key:
        raise ForbiddenError("Password change requires a user session",
                             code="api_key_forbidden")

    from auth import lockout as lockout_mod
    from auth import totp as totp_mod
    from models.recovery_code import RecoveryCode

    user = principal.user
    identifier = user.username.strip().lower()
    ip = client_ip(request) or "unknown"
    acct, ipc = lockout_mod.account_counter(), lockout_mod.ip_counter()
    try:
        if acct.is_locked(identifier) or ipc.is_locked(ip):
            raise UnauthenticatedError("Invalid credentials")
    except lockout_mod.LockoutUnavailable as exc:
        from app.core.errors import ServiceUnavailableError

        logger.error("lockout store unreachable during password change: %s",
                     type(exc).__name__)
        raise ServiceUnavailableError(
            "Authentication temporarily unavailable",
            code="auth_unavailable",
        )

    password_ok = verify_password(data.current_password, user.password_hash)
    if password_ok and data.current_password == data.new_password:
        # No-op change: reject before touching codes, sessions, or audit.
        raise BadRequestError(
            "New password must differ from the current password",
            code="password_reuse",
        )
    code_ok = True
    matched_recovery = None
    if password_ok and user.totp_enabled:
        code_ok = False
        if (user.totp_secret and data.code and len(data.code) == 6
                and (step := totp_mod.verify_code(
                    user.totp_secret, data.code,
                    user.totp_last_step)) is not None
                and totp_mod.claim_totp_step(db, user.id, step)):
            code_ok = True
        elif data.code:
            for row in db.query(RecoveryCode).filter(
                    RecoveryCode.user_id == user.id,
                    RecoveryCode.used_at.is_(None)).all():
                if totp_mod.verify_recovery_code(data.code, row.code_hash):
                    matched_recovery = row
                    code_ok = True
                    break

    if not password_ok or not code_ok:
        try:
            engaged, seconds, scope = False, 0, ""
            engaged, seconds = acct.register_failure(identifier)
            scope = "account"
            if not engaged:
                ip_engaged, ip_seconds = ipc.register_failure(ip)
                if ip_engaged:
                    engaged, seconds, scope = True, ip_seconds, "ip"
            if engaged:
                record_audit(
                    db, organization_id=user.organization_id,
                    actor=user.username, action="auth.account_locked",
                    details={"scope": scope, "lock_seconds": seconds},
                    request=request,
                )
                db.commit()
        except lockout_mod.LockoutUnavailable:
            logger.warning("lockout store unreachable during password "
                           "change failure")
        raise UnauthenticatedError("Invalid credentials")

    if matched_recovery is not None:
        matched_recovery.used_at = datetime.now(timezone.utc)
    user.password_hash = hash_password(data.new_password)
    # Keep the caller's live access token; everything else dies.
    current_jti = None
    auth_header = request.headers.get("Authorization") or ""
    if auth_header.startswith("Bearer "):
        current_jti = token_service.decode_token(
            auth_header[7:]).get("jti")
    revoked = token_store.revoke_family_except(
        user.id, {current_jti} if current_jti else set())
    if current_jti:
        # Re-anchor the surviving access token (record was deleted above;
        # store_access derives the TTL from the token itself).
        token_store.store_access(auth_header[7:], user.id)
    record_audit(
        db, organization_id=user.organization_id, actor=user.username,
        action="auth.password_changed",
        details={"revoked_sessions": revoked},
        request=request,
    )
    db.commit()
    return MessageOut(message="Password changed")


@router.get("/me", response_model=UserOut)
async def me(
    principal: Principal = Depends(principal_or_enroll),
) -> UserOut:
    user = principal.user
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=user.organization.name if user.organization else None,
        permissions=sorted(p.value for p in principal.permissions),
    )
