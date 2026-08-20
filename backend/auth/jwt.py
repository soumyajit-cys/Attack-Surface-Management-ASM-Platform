from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError

from config import settings

ACCESS = "access"
REFRESH = "refresh"
PASSWORD_RESET = "password_reset"


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
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError:
        return {}
    if "sub" not in payload:
        return {}
    return payload


def token_expiry(payload: dict) -> datetime:
    return datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )