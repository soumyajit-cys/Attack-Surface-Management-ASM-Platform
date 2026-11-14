"""v3 exposed_services scanner module tests."""

import asyncio
import json
import re
import time

import pytest

from app.scanning.context import ScanContext
from app.scanning.registry import ScanPhase, registry
from app.scanning.scope import SCOPE_PHASES


@pytest.fixture(autouse=True)
def _fresh_registry():
    import sys
    for name in [n for n in sys.modules if n == "scanner_modules" or n.startswith("scanner_modules.")]:
        del sys.modules[name]
    registry._entries.clear()
    registry._discovered = False
    yield
    for name in [n for n in sys.modules if n == "scanner_modules" or n.startswith("scanner_modules.")]:
        del sys.modules[name]
    registry._entries.clear()
    registry._discovered = False


def _make_ctx(domain="example.com", subdomains=None, open_ports=None):
    return ScanContext(
        domain=domain,
        pinned_ip="93.184.216.34",
        org_id=1,
        scan_id=1,
        db=None,
        scope="full",
        subdomains=list(subdomains or []),
        config={"open_ports": open_ports or {}},
    )


class TestExposedServicesModule:
    def test_scope_gating(self):
        assert ScanPhase.EXPOSED_SERVICES in SCOPE_PHASES["active"]
        assert ScanPhase.EXPOSED_SERVICES in SCOPE_PHASES["full"]
        assert ScanPhase.EXPOSED_SERVICES not in SCOPE_PHASES["passive"]

    def test_empty_subdomains(self):
        import scanner_modules.exposed_services as es
        ctx = _make_ctx(subdomains=[])
        result = asyncio.run(es.exposed_services_module(ctx))
        assert result["findings"] == []

    def test_redis_info_finding(self):
        import scanner_modules.exposed_services as es
        ctx = _make_ctx(subdomains=["host.example.com"], open_ports={"host.example.com": [{"port": 6379, "status": "open", "banner": ""}]})
        result = asyncio.run(es.exposed_services_module(ctx))
        findings = result["findings"]
        assert any(f["service"] == "redis" for f in findings)
        redis_f = next(f for f in findings if f["service"] == "redis")
        assert redis_f["severity"] == "info"
        assert redis_f["confidence"] == 0.5

    def test_mysql_greeting_high(self):
        import scanner_modules.exposed_services as es
        ctx = _make_ctx(subdomains=["host.example.com"], open_ports={"host.example.com": [{"port": 3306, "status": "open", "banner": "5.7.32-log"}]})
        result = asyncio.run(es.exposed_services_module(ctx))
        findings = result["findings"]
        mysql_f = next((f for f in findings if f["service"] == "mysql"), None)
        assert mysql_f is not None
        assert mysql_f["severity"] == "high"
        assert mysql_f["confidence"] == 0.9

    def test_dedupe_key_format(self):
        import scanner_modules.exposed_services as es
        ctx = _make_ctx(subdomains=["host.example.com"], open_ports={"host.example.com": [{"port": 6379, "status": "open", "banner": ""}]})
        result = asyncio.run(es.exposed_services_module(ctx))
        for f in result["findings"]:
            assert f["dedupe_key"].startswith("exposed_services:")

    def test_signature_schema(self):
        import json
        from pathlib import Path
        data = json.loads((Path(__file__).parent.parent.parent / "scanner_modules" / "exposed_service_signatures.json").read_text())
        assert "signatures" in data
        for sig in data["signatures"]:
            assert "service" in sig
            assert "ports" in sig
            assert "severity" in sig
            assert "confidence" in sig

    def test_redos_safety(self):
        import json
        from pathlib import Path
        data = json.loads((Path(__file__).parent.parent.parent / "scanner_modules" / "exposed_service_signatures.json").read_text())
        for sig in data["signatures"]:
            for pattern in sig.get("match_patterns", []):
                start = time.monotonic()
                try:
                    re.search(pattern, "a" * 30 + "!")
                except Exception:
                    pass
                elapsed = time.monotonic() - start
                assert elapsed < 1.0, f"ReDoS in {sig['service']}: {elapsed:.2f}s"

    def test_no_raw_banners_stored(self):
        import scanner_modules.exposed_services as es
        ctx = _make_ctx(subdomains=["host.example.com"], open_ports={"host.example.com": [{"port": 6379, "status": "open", "banner": "SECRET BANNER DATA"}]})
        result = asyncio.run(es.exposed_services_module(ctx))
        result_str = str(result)
        assert "SECRET BANNER DATA" not in result_str
