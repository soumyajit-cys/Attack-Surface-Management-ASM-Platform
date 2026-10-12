"""Login (and future TOTP / password-reset) attempt lockout (Phase 1.5.3).

Per-identity counters in Redis with a sliding window and exponential
backoff. Keys are SHA-256 hex of the NORMALIZED identifier, so raw emails
and usernames never appear in Redis or logs (log only the key itself).

Fail-closed on Redis errors: the caller must deny the attempt with the
generic response. Rationale: Redis is already a hard login dependency
(refresh-token store); failing open would grant an unlimited guessing
window exactly when observability is degraded.

Thresholds come from settings on every call (no caching) so tests can
shrink them with monkeypatch and rotation takes effect without restart.
"""

from __future__ import annotations

import hashlib
import logging
import time

logger = logging.getLogger("sentinelasm")

KEY_PREFIX = "lockout"


class LockoutUnavailable(Exception):
    """Redis backing the counters is unreachable (caller must fail closed)."""


class AttemptCounter:
    """Sliding-window failures + exponential lockout for one identity kind.

    ``prefix`` namespaces the keys (``"login-acct"``, ``"login-ip"``;
    sub-task 4 reuses this for TOTP and password-reset scopes).
    """

    def __init__(
        self,
        prefix: str,
        max_attempts: int,
        window_s: int,
        base_s: int,
        cap_s: int,
        client=None,
    ) -> None:
        self.prefix = prefix
        self.max_attempts = max_attempts
        self.window_s = window_s
        self.base_s = base_s
        self.cap_s = cap_s
        self._client = client

    # -- key handling ----------------------------------------------------

    @staticmethod
    def normalize(ref: str) -> str:
        return ref.strip().lower()

    def _key(self, ref: str) -> str:
        digest = hashlib.sha256(self.normalize(ref).encode()).hexdigest()
        return f"{KEY_PREFIX}:{self.prefix}:{digest}"

    def _backoff_seconds(self, engagements: int) -> int:
        return min(self.base_s * (2 ** max(engagements - 1, 0)), self.cap_s)

    def _redis(self):
        if self._client is not None:
            return self._client
        from utils.redis_client import get_redis

        return get_redis()

    # -- public API ------------------------------------------------------

    def is_locked(self, ref: str, now: float | None = None) -> bool:
        """True while a lock is in force. Never raises for missing keys."""
        try:
            remaining = self._redis().ttl(self._key(ref) + ":until")
        except Exception as exc:
            raise LockoutUnavailable(str(exc)) from exc
        return remaining is not None and remaining > 0

    def register_failure(
        self, ref: str, now: float | None = None
    ) -> tuple[bool, int]:
        """Record a failure; returns (lock_engaged, lock_seconds).

        Sliding window: only failures within ``window_s`` count. On
        engagement the lock duration doubles per consecutive engagement,
        capped at ``cap_s``.
        """
        moment = now if now is not None else time.time()
        try:
            client = self._redis()
            key = self._key(ref)
            client.zadd(key + ":hits", {str(moment): moment})
            client.zremrangebyscore(key + ":hits", 0, moment - self.window_s)
            client.expire(key + ":hits", self.window_s + self.cap_s)
            recent = client.zcard(key + ":hits")
            if recent < self.max_attempts:
                return False, 0
            engagements = client.incr(key + ":locks")
            client.expire(key + ":locks", self.cap_s * 4)
            seconds = self._backoff_seconds(engagements)
            client.set(key + ":until", int(moment + seconds), ex=seconds)
            # Reset the window so the NEXT failure starts a fresh count
            # toward a (longer) subsequent lock instead of re-locking now.
            client.delete(key + ":hits")
            return True, seconds
        except LockoutUnavailable:
            raise
        except Exception as exc:
            raise LockoutUnavailable(str(exc)) from exc

    def register_success(self, ref: str) -> None:
        """Clear consecutive failures (locks already expired are untouched)."""
        try:
            self._redis().delete(self._key(ref) + ":hits")
        except Exception as exc:
            raise LockoutUnavailable(str(exc)) from exc


def _counter(prefix: str, client=None) -> AttemptCounter:
    from app.core.config import settings

    return AttemptCounter(
        prefix,
        max_attempts=settings.login_max_attempts,
        window_s=settings.login_attempt_window_seconds,
        base_s=settings.login_lockout_base_seconds,
        cap_s=settings.login_lockout_max_seconds,
        client=client,
    )


def account_counter(client=None) -> AttemptCounter:
    """Per-account lockout counter (keyed by normalized username/email)."""
    return _counter("login-acct", client)


def ip_counter(client=None) -> AttemptCounter:
    """Per-IP lockout counter (keyed by client IP from utils.client_ip)."""
    return _counter("login-ip", client)
