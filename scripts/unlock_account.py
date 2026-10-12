#!/usr/bin/env python3
"""Clear a user's login-lockout counters (operator early-unlock).

Same key derivation as the API endpoint (auth.lockout.account_counter), so
both paths agree. Prints only counts -- never the username, key, or any
secret. Requires Redis; honors REDIS_URL from the environment.

Usage:  python scripts/unlock_account.py <username>
"""

import argparse
import sys
from pathlib import Path


def _repo_backend_dir() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent / "backend"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Login username to unlock")
    args = parser.parse_args(argv)

    if str(_repo_backend_dir()) not in sys.path:
        sys.path.insert(0, str(_repo_backend_dir()))

    from auth.lockout import account_counter

    cleared = account_counter().clear(args.username)
    print(f"cleared {cleared} lockout keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
