#!/usr/bin/env python3
"""Clear a user's 2FA state (lost-device recovery for the only admin).

Same effects as POST /api/v1/auth/admin/reset-2fa without needing an
authenticated admin: disables TOTP, deletes recovery codes, revokes the
user's sessions. Prints only counts -- never usernames, secrets, or codes.

Usage:  python scripts/reset_2fa.py <username>
"""

import argparse
import sys
from pathlib import Path


def _repo_backend_dir() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent / "backend"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Login username to reset 2FA for")
    args = parser.parse_args(argv)

    if str(_repo_backend_dir()) not in sys.path:
        sys.path.insert(0, str(_repo_backend_dir()))

    from app.db.session import SessionLocal
    from auth.token_store import token_store
    from models.recovery_code import RecoveryCode
    from models.user import User

    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.username == args.username).first()
        if user is None:
            print("cleared 0 users")
            return 1
        user.totp_enabled = False
        user.totp_secret = None
        user.totp_last_step = None
        codes = db.query(RecoveryCode).filter(
            RecoveryCode.user_id == user.id).delete()
        revoked = token_store.revoke_family(user.id)
        db.commit()
        print(f"cleared 1 user, {codes} recovery codes, "
              f"{revoked} revoked tokens")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
