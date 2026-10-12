import redis

import json
from datetime import datetime, timedelta, timezone

from auth import jwt as token_service
from config import settings
from utils.redis_client import get_redis

REFRESH_KEY = "refresh:{jti}"
REVOKED_KEY = "revoked:{jti}"
RESET_USED_KEY = "reset_used:{jti}"
SESSIONS_KEY = "sessions:{user_id}"


def _ttl_seconds(payload: dict) -> int:
    expiry = token_service.token_expiry(payload)
    remaining = expiry - datetime.now(timezone.utc)
    return max(int(remaining.total_seconds()), 1)


def _decode_stored(raw) -> dict:
    """Refresh/access records are JSON {user_id, parent}; legacy int values
    (user id only, pre-1.5.6) still decode."""
    if raw is None:
        return {}
    if isinstance(raw, (int, float)):
        return {"user_id": int(raw), "parent": None}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if isinstance(data, int):
        return {"user_id": data, "parent": None}
    if isinstance(data, dict):
        return {"user_id": data.get("user_id"), "parent": data.get("parent")}
    return {}


class TokenStore:

    def __init__(self, client: redis.Redis = None):
        self.client = client or get_redis()

    def store_refresh(self, token: str, user_id: int) -> None:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return
        ttl = _ttl_seconds(payload)
        self.client.set(
            REFRESH_KEY.format(jti=jti),
            json.dumps({"user_id": user_id, "parent": None}),
            ex=ttl,
        )
        self.client.sadd(SESSIONS_KEY.format(user_id=user_id), jti)
        self.client.expire(SESSIONS_KEY.format(user_id=user_id), ttl)

    def refresh_valid(self, token: str, user_id: int) -> bool:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return False
        stored = self.client.get(REFRESH_KEY.format(jti=jti))
        record = _decode_stored(stored)
        if not record or record.get("user_id") is None:
            return False
        if int(record["user_id"]) != int(user_id):
            return False
        if self.client.exists(REVOKED_KEY.format(jti=jti)):
            return False
        return True

    def store_access(self, token: str, user_id: int) -> None:
        """Track an access jti so family revocation reaches it too."""
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return
        ttl = _ttl_seconds(payload)
        self.client.set(
            REFRESH_KEY.format(jti=jti),
            json.dumps({"user_id": user_id, "parent": None}),
            ex=ttl,
        )
        self.client.sadd(SESSIONS_KEY.format(user_id=user_id), jti)
        self.client.expire(SESSIONS_KEY.format(user_id=user_id), ttl)

    def revoke_family(self, user_id: int) -> int:
        """Revoke every known access+refresh token of a user.

        Returns the number of tokens revoked. Used on refresh reuse and on
        password change/reset. Unknown/legacy entries are revoked by jti.
        """
        key = SESSIONS_KEY.format(user_id=user_id)
        members = self.client.smembers(key) or set()
        count = 0
        for jti in members:
            # 90-day marker: outlives any refresh TTL so late replays still
            # read as reuse rather than plain expiry. Tiny values; bounded.
            self.client.set(REVOKED_KEY.format(jti=jti), 1, ex=90 * 86400)
            self.client.delete(REFRESH_KEY.format(jti=jti))
            count += 1
        self.client.delete(key)
        return count

    def rotate(self, old_token: str, new_token: str, user_id: int) -> None:
        old_payload = token_service.decode_token(old_token)
        old_jti = old_payload.get("jti")
        if old_jti:
            self.client.set(
                REVOKED_KEY.format(jti=old_jti),
                user_id,
                ex=_ttl_seconds(old_payload),
            )
            self.client.delete(REFRESH_KEY.format(jti=old_jti))
        self.store_refresh(new_token, user_id)

    def revoke(self, token: str) -> None:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return
        self.client.set(
            REVOKED_KEY.format(jti=jti),
            1,
            ex=_ttl_seconds(payload),
        )

    def is_revoked(self, token: str) -> bool:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return False
        return self.client.exists(REVOKED_KEY.format(jti=jti))

    def mark_reset_used(self, token: str) -> None:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return
        self.client.set(
            RESET_USED_KEY.format(jti=jti),
            1,
            ex=_ttl_seconds(payload),
        )

    def reset_used(self, token: str) -> bool:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return True
        return self.client.exists(RESET_USED_KEY.format(jti=jti))


token_store = TokenStore()