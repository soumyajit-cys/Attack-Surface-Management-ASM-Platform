from datetime import datetime, timedelta, timezone

import jwt
from jwt import InvalidTokenError

from config import settings

ACCESS = "access"
REFRESH = "refresh"
PASSWORD_RESET = "password_reset"
MFA_CHALLENGE = "mfa_challenge"
RESTRICTED = "restricted"

#: Clock-skew allowance for exp/iat validation (seconds). Small on purpose:
#: a larger window would keep demonstrably expired tokens alive.
CLOCK_SKEW_LEEWAY = timedelta(seconds=5)

#: Claims every token must carry. Missing claims fail closed in
#: :func:`decode_token` (the previous library accepted them).
REQUIRED_CLAIMS = ["exp", "iat", "jti", "sub"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: int) -> str:
    expire = _now() + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    return _encode(user_id, ACCESS, expire)


def create_refresh_token(user_id: int) -> str:
    expire = _now() + timedelta(
        days=settings.refresh_token_expire_days
    )
    return _encode(user_id, REFRESH, expire)


def create_password_reset_token(user_id: int) -> str:
    expire = _now() + timedelta(minutes=30)
    return _encode(user_id, PASSWORD_RESET, expire)


def create_mfa_challenge_token(user_id: int) -> str:
    """Short-lived single-use 2FA challenge (5 minutes, see token_store)."""
    expire = _now() + timedelta(minutes=5)
    return _encode(user_id, MFA_CHALLENGE, expire)


def create_restricted_token(user_id: int, scope: str) -> str:
    """Limited-scope token (e.g. scope='enroll_2fa'). Accepted only by the
    endpoints that explicitly allow it; rejected everywhere else because
    its type is neither ACCESS nor any other operational type."""
    payload = {
        "sub": str(user_id),
        "type": RESTRICTED,
        "scope": scope,
        "exp": _now() + timedelta(minutes=15),
        "iat": _now(),
        "jti": _generate_jti(),
    }
    return jwt.encode(
        payload,
        settings.jwt_secret_for_use,
        algorithm="HS256",
    )


def _encode(user_id: int, token_type: str, expire: datetime) -> str:
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "exp": expire,
        "iat": _now(),
        "jti": _generate_jti(),
    }
    return jwt.encode(
        payload,
        settings.jwt_secret_for_use,
        algorithm=settings.jwt_algorithm,
    )


def _generate_jti() -> str:
    import uuid
    return uuid.uuid4().hex


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_for_use,
            algorithms=["HS256"],
            leeway=CLOCK_SKEW_LEEWAY,
            options={"require": REQUIRED_CLAIMS},
        )
    except InvalidTokenError:
        return {}
    if "sub" not in payload:
        return {}
    return payload


def token_expiry(payload: dict) -> datetime:
    return datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )