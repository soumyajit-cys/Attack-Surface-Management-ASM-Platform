"""Text-integrity gate tests (incident follow-up, 2026-10-21).

The 2026-10-20 capture committed ``tests/v3/test_audit_logs_api.py`` with
2,348 trailing NUL bytes (commits 918ae86 / cbd7f6d). This gate (and its
Makefile target ``make check-text-integrity``, wired into ``make check``
and CI) fails the build when any tracked text file contains a NUL byte
or invalid UTF-8, and the tests here prove both the RED and GREEN sides.
"""

import importlib.util
import subprocess
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent
SCRIPT = REPO_ROOT / "scripts" / "check_text_integrity.py"

_spec = importlib.util.spec_from_file_location("check_text_integrity", SCRIPT)
check_text_integrity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_text_integrity)


class TestTextIntegrityGate:
    def test_tracked_text_files_are_clean(self):
        """GREEN side: the real repo tree passes the gate."""

        assert check_text_integrity.main([]) == 0

    def test_flags_nul_bytes_and_invalid_utf8(self, tmp_path):
        """RED side: a temp file with NUL bytes / invalid UTF-8 is flagged."""

        bad = tmp_path / "corrupted.py"
        bad.write_bytes(
            b"first_line = 1\n\x00\x00\x00trailing-corruption\n"
            b"\x80invalid-utf8\n"
        )

        problems = check_text_integrity.scan([bad])

        assert len(problems) == 2, problems
        assert any("contains a NUL byte" in p for p in problems)
        assert any("invalid UTF-8" in p for p in problems)

    def test_clean_temp_file_has_no_problems(self, tmp_path):
        good = tmp_path / "clean.ts"
        good.write_bytes("// just valid utf-8 éè中文\n".encode("utf-8"))

        assert check_text_integrity.scan([good]) == []

    def test_non_text_extensions_are_out_of_scope(self, tmp_path):
        # a binary extension is skipped by the gate, not a failure
        blob = tmp_path / "payload.lock"
        blob.write_bytes(b"\x00\x00\x00")

        assert check_text_integrity.scan([blob]) == []

    def test_script_process_end_to_end(self, tmp_path):
        """The script exits nonzero with a report for a bad path, and this
        is exactly how the Makefile target invokes it."""

        bad = tmp_path / "bad.json"
        bad.write_bytes(b'{"a": 1}\x00')

        result = subprocess.run(
            [str(BACKEND_ROOT / "venv" / "bin" / "python"),
             str(SCRIPT), str(bad)],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        assert result.returncode == 1
        assert "contains a NUL byte" in result.stdout
