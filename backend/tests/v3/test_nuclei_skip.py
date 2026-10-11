"""Nuclei template scanning is unwired until Phase 4 (task 1.3/1.4 scope).

Covers both paths of ``run_nuclei_scan`` (binary missing vs present) and the
``nuclei_skipped`` flag in the pipeline scan summary. No real subprocesses or
network: the nuclei binary and its stdout are faked.
"""

import asyncio
import logging
from contextlib import contextmanager

import pytest


@contextmanager
def _capture_app_logs(caplog, level=logging.WARNING):
    """Attach pytest's capture handler to the non-propagating app logger.

    NOTE: the handler must be attached in the test body (call phase) --
    attaching in a fixture (setup phase) does not stick for this logger.
    """
    app_logger = logging.getLogger("sentinelasm")
    app_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(level):
            yield caplog
    finally:
        app_logger.removeHandler(caplog.handler)


def _run(coro):
    return asyncio.run(coro)


def test_nuclei_missing_logs_warning_and_returns_empty(monkeypatch, caplog):
    from services.findings import finding_engine

    monkeypatch.setattr("shutil.which", lambda _name: None)
    with _capture_app_logs(caplog) as logs:
        assert _run(finding_engine.run_nuclei_scan("93.184.216.34")) == []
    assert "nuclei not installed" in logs.text


def test_nuclei_present_returns_mapped_findings(monkeypatch, caplog):
    import json

    from services.findings import finding_engine

    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/nuclei")

    line = json.dumps({
        "info": {"name": "CVE-2024-0001", "severity": "high"},
        "matched-at": "https://93.184.216.34/",
    })

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return (f"{line}\nnot-json\n".encode(), b"")

    async def fake_exec(*_args, **_kwargs):
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    with _capture_app_logs(caplog) as logs:
        findings = _run(finding_engine.run_nuclei_scan("93.184.216.34"))
    assert len(findings) == 1
    assert "nuclei not installed" not in logs.text


def test_scan_summary_marks_nuclei_skipped():
    """The pipeline summary reports the unwired phase until Phase 4 lands."""
    from types import SimpleNamespace

    from tasks.discovery_tasks import _scan_targets

    scan = SimpleNamespace(organization_id=1, id=1)
    summary = _scan_targets(
        None, scan, {"subdomains": []}, "example", None, scope="passive",
    )
    assert summary["nuclei_skipped"] is True
