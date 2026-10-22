"""Server-side step-up re-authentication markers (v1.6.x).

After ``POST /api/v1/auth/step-up`` verifies the caller's credentials the
route plants a short-lived marker in Redis keyed by the user id **and** the
current access token's jti:

    stepup:{user_id}:{jti}  ->  "1", TTL 300 s

Sensitive org-admin write routes guard themselves with
``require_step_up_dep`` (see ``app.api.deps``), which answers
``403 step_up_required`` unless the marker exists for the *presenting*
session. No client-held token is issued: possession of the live session
plus this marker is the only proof, and a second session of the same user
cannot ride another session's marker.

Redis loss fails closed (StepupUnavailable -> 503), like the login lockout
store.
"""

import redis

from utils.redis_client import get_redis

STEPUP_KEY = "stepup:{user_id}:{jti}"
STEPUP_TTL_SECONDS = 300


class StepupUnavailable(Exception):
    """Marker store unreachable; fail closed like LockoutUnavailable."""


def get_marker_key(user_id: int, jti: str | None) -> str | None:
    if not user_id or not jti:
        return None
    return STEPUP_KEY.format(user_id=int(user_id), jti=jti)


def grant(user_id: int, jti: str) -> int:
    """Plant (or refresh) the marker; returns its remaining TTL."""
    key = get_marker_key(user_id, jti)
    if key is None:
        raise ValueError("step-up grant requires user_id and jti")
    try:
        return int(get_redis().set(key, "1", ex=STEPUP_TTL_SECONDS) or 0)
    except redis.RedisError as exc:
        raise StepupUnavailable(str(exc)) from exc


def active(user_id: int, jti: str | None) -> bool:
    """True when the presenting session holds a live marker."""
    key = get_marker_key(user_id, jti)
    if key is None:
        return False
    try:
        return bool(get_redis().exists(key))
    except redis.RedisError as exc:
        raise StepupUnavailable(str(exc)) from exc
