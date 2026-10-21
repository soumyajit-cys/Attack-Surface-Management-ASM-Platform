#!/usr/bin/env python3
"""Repository text-integrity gate (incident follow-up, 2026-10-21).

Fails when ANY tracked text file contains a NUL byte or is not valid
UTF-8. Born from the 2026-10-20 incident where a snapshotting process
committed `backend/tests/v3/test_audit_logs_api.py` with 2,348 trailing
NUL bytes (commits 918ae86 / cbd7f6d, repaired in the capture that
followed) — a corruption pytest only tripped over at collection time
("source code string cannot contain null bytes").

Usage:
    python scripts/check_text_integrity.py            # scan git ls-files
    python scripts/check_text_integrity.py FILE...    # scan explicit paths

Exit codes: 0 = clean, 1 = problems found, 2 = usage/internal error.
"""

import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

TEXT_EXTENSIONS: tuple[str, ...] = (
    ".py", ".ts", ".tsx", ".md", ".yml", ".yaml", ".toml",
    ".json", ".sh", ".css",
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def tracked_text_files() -> list[Path]:
    """Tracked files (git ls-files) restricted to the text extensions."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT, check=True, capture_output=True,
    )
    names = [p for p in result.stdout.split(b"\x00") if p]
    return [
        REPO_ROOT / n.decode("utf-8")
        for n in names
        if n.decode("utf-8", "replace").endswith(TEXT_EXTENSIONS)
    ]


def file_problems(path: Path) -> list[str]:
    """Integrity problems for one file (NUL bytes and invalid UTF-8)."""
    if path.suffix not in TEXT_EXTENSIONS:
        return []  # non-text file types are out of scope for this gate
    data = path.read_bytes()
    problems: list[str] = []
    nul = data.find(b"\x00")
    if nul != -1:
        problems.append(
            f"{path}: contains a NUL byte (first at byte offset {nul})")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        problems.append(
            f"{path}: invalid UTF-8 (byte {exc.start}: {exc.reason})")
    return problems


def scan(paths: Iterable[Path]) -> list[str]:
    problems: list[str] = []
    for path in paths:
        problems.extend(file_problems(path))
    return problems


def main(argv: list[str]) -> int:
    paths = (
        [Path(a).resolve() for a in argv[1:]]
        if len(argv) > 1
        else tracked_text_files()
    )
    problems = scan(paths)
    if problems:
        print(f"text-integrity: FAILED — {len(problems)} problem(s):")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    scanned = len(list(paths))
    print(f"text-integrity: OK — {scanned} text file(s) clean "
          "(no NUL bytes, valid UTF-8)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
