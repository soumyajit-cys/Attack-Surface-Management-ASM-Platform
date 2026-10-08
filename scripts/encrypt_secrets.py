#!/usr/bin/env python3
"""Encrypt / inspect / rotate alert-integration secrets at rest.

Uses the same shared functions as the Alembic migration
(``app.core.crypto``), so behavior is identical. Back up the database first.

  --dry-run   report per-column counts only (never prints values)
  --apply     encrypt plaintext rows in place (skips already-encrypted rows)
  --rotate    re-encrypt everything under the FIRST configured key; fails if
              any value cannot be decrypted (nothing is partially rewritten)
"""

import argparse
import sys
from pathlib import Path


def _repo_backend_dir() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent / "backend"


def _connect():
    if str(_repo_backend_dir()) not in sys.path:
        sys.path.insert(0, str(_repo_backend_dir()))
    from sqlalchemy import create_engine

    from app.core.config import settings  # validates SECRETS_ENCRYPTION_KEY

    engine = create_engine(settings.database_url)
    return engine.connect(), settings


def _report(counts: dict) -> int:
    total = 0
    for name in sorted(counts):
        print(f"{name}: {counts[name]}")
        total += counts[name]
    print(f"total: {total}")
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--rotate", action="store_true")
    args = parser.parse_args(argv)

    if str(_repo_backend_dir()) not in sys.path:
        sys.path.insert(0, str(_repo_backend_dir()))
    from app.core import crypto

    conn, _settings = _connect()
    try:
        if args.dry_run:
            print("rows needing encryption:")
            _report(crypto._pending_counts(conn, encrypted=False))
            return 0
        if args.apply:
            with conn.begin():
                total = _report(crypto.encrypt_existing_rows(conn))
            print(f"applied ({total} values encrypted)")
            return 0
        with conn.begin():
            total = _report(crypto.rotate_existing_rows(conn))
        print(f"rotated ({total} values re-encrypted under the first key)")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
