import redis

from datetime import datetime, timedelta, timezone

from auth import jwt as token_service
from config import settings
from utils.redis_client import get_redis

REFRESH_KEY = "refresh:{jti}"
REVOKED_KEY = "revoked:{jti}"
RESET_USED_KEY = "reset_used:{jti}"


def _ttl_seconds(payload: dict) -> int:
    expiry = token_service.token_expiry(payload)
    remaining = expiry - datetime.now(timezone.utc)
    return max(int(remaining.total_seconds()), 1)


class TokenStore:

    def __init__(self, client: redis.Redis = None):
        self.client = client or get_redis()

    def store_refresh(self, token: str, user_id: int) -> None:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return
        self.client.set(
            REFRESH_KEY.format(jti=jti),
            user_id,
            ex=_ttl_seconds(payload),
        )

    def refresh_valid(self, token: str, user_id: int) -> bool:
        payload = token_service.decode_token(token)
        jti = payload.get("jti")
        if not jti:
            return False
        stored = self.client.get(REFRESH_KEY.format(jti=jti))
        if stored is None:
            return False
        if int(stored) != int(user_id):
            return False
        if self.client.exists(REVOKED_KEY.format(jti=jti)):
            return False
        return True

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