"""scripts/seed_demo.py contract.

The seeder is the screenshot/demo path: FIXTURE data only, no network, and
it must refuse to run against any database whose name does not start with
``demo_``/``scratch_`` (defence in depth on top of scripts/db_guard.sh,
which it also invokes). These tests check the refusal behaviour and the
no-network property without touching any database.

Doc-only tests: no DB, no network.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEEDER = ROOT / "scripts" / "seed_demo.py"


def _run_seeder(database_url: str) -> subprocess.CompletedProcess[str]:
    env = {
        # A minimal environment: DATABASE_URL only. The guard must trip
        # BEFORE any connection attempt, so bogus credentials are safe.
        "DATABASE_URL": database_url,
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
    }
    return subprocess.run(
        [sys.executable, str(SEEDER)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,  # the seeder is EXPECTED to fail here; exit code is the assertion
    )


def test_seeder_exists_and_is_documented():
    assert SEEDER.exists(), "scripts/seed_demo.py missing (screenshots/demo path)"
    text = SEEDER.read_text()
    assert "FIXTURE" in text, "seeder must document that it seeds FIXTURE data"
    assert "db_guard" in text, "seeder must reference scripts/db_guard.sh"


def test_seeder_refuses_dev_database():
    # The dev database name must never be written by automation; the seeder
    # has to refuse it by name AND by prefix before any connection.
    result = _run_seeder("postgresql://sentinel:bogus@localhost:5432/sentinelasm")
    assert result.returncode != 0, "seeder ran against the dev database name"
    combined = result.stdout + result.stderr
    assert "sentinelasm" in combined, "refusal should name the offending DB"
    assert "demo_" in combined and "scratch_" in combined, (
        "refusal should explain the demo_/scratch_ rule"
    )


def test_seeder_refuses_productionish_names():
    for name in ["production", "asm_prod", "sentinel"]:
        result = _run_seeder(f"postgresql://sentinel:bogus@localhost:5432/{name}")
        assert result.returncode != 0, f"seeder accepted DB name {name!r}"


def test_seeder_does_not_import_network_libraries():
    """FIXTURE-only guarantee: the seeder must not grow network imports."""
    text = SEEDER.read_text()
    for banned in ["import requests", "import httpx", "import urllib",
                   "import socket", "urllib.request", "aiohttp"]:
        assert banned not in text, f"seeder must stay network-free: {banned!r}"
