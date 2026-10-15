"""TOTP 2FA primitives (Phase 1.5.4).

RFC 6238 defaults authenticator apps support: SHA-1, 6 digits, 30 s step,
+/-1 step window. Verification is constant-time (compare_digest over the
full candidate set); replays are rejected via the stored last-accepted
counter. Recovery codes are 16 base32 chars (80 bits), SHA-256 hashed,
single-use; regenerating replaces the whole batch.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

import pyotp

STEP_SECONDS = 30
WINDOW_STEPS = 1
RECOVERY_CODE_COUNT = 10


def new_secret() -> str:
    """Fresh base32 TOTP secret for enrollment."""
    return pyotp.random_base32()


def otpauth_uri(secret: str, username: str,
                issuer: str = "SentinelASM") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=issuer)


def verify_code(secret: str, code: str, last_step: int | None,
                now: float | None = None) -> int | None:
    """Verify a 6-digit code; returns the matched step, else None.

    Accepts steps in [now-1, now+1]; any step <= last_step is a replay.
    Candidate comparison is constant-time; malformed input fails closed
    without comparison.
    """
    text = (code or "").strip().replace(" ", "")
    if len(text) != 6 or not text.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    now_step = int((now if now is not None else time.time()) // STEP_SECONDS)
    for offset in (0, -1, 1):
        step = now_step + offset
        if last_step is not None and step <= last_step:
            continue
        candidate = totp.at(step * STEP_SECONDS)
        if hmac.compare_digest(candidate, text):
            return step
    return None


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """16-char base32 codes (80 bits each); caller stores only hashes."""
    import base64

    codes = set()
    while len(codes) < count:
        # 10 bytes = 80 bits = exactly 16 base32 chars, no padding.
        codes.add(base64.b32encode(secrets.token_bytes(10)).decode())
    return sorted(codes)


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


def verify_recovery_code(code: str, code_hash: str) -> bool:
    return hmac.compare_digest(hash_recovery_code(code), code_hash)


def claim_totp_step(db, user_id: int, step: int) -> bool:
    """Atomically adopt a TOTP counter step; True iff this caller won.

    A single UPDATE ... WHERE last_step IS NULL OR last_step < step, so two
    concurrent verifications of the same code cannot both succeed: the
    loser's UPDATE matches zero rows. Callers must treat False as a replay.
    """
    from sqlalchemy import or_

    from models.user import User

    updated = (
        db.query(User)
        .filter(User.id == user_id,
                or_(User.totp_last_step.is_(None),
                    User.totp_last_step < step))
        .update({"totp_last_step": step}, synchronize_session="fetch")
    )
    return updated == 1
