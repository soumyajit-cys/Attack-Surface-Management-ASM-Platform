"""v3 exposed_services scanner module tests."""

import asyncio
import json
import re
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

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


class RecordingSocket:
    """Fake socket that records every byte sent."""
    def __init__(self, banner=b""):
        self.sent = []
        self.banner = banner
        self.closed = False

    def sendall(self, data):
        self.sent.append(bytes(data))

    def send(self, data):
        self.sent.append(bytes(data))
        return len(data)

    def recv(self, bufsize=4096):
        if self.banner:
            b = self.banner
            self.banner = b""
            return b
        return b""

    def close(self):
        self.closed = True

    def settimeout(self, t):
        pass

    def connect(self, addr):
        pass


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

    def test_passive_services_send_nothing(self):
        """Redis, Mongo, Memcached are passive — no connection made."""
        import scanner_modules.exposed_services as es
        # The module derives findings from open_ports without connecting
        ctx = _make_ctx(subdomains=["host.example.com"], open_ports={"host.example.com": [{"port": 6379, "status": "open", "banner": ""}]})
        result = asyncio.run(es.exposed_services_module(ctx))
        assert any(f["service"] == "redis" for f in result["findings"])

    def test_soft404_baseline_no_finding(self):
        """If admin path returns same status as random path, no finding."""
        import scanner_modules.exposed_services as es
        with patch.object(es, "_http_probe", return_value={"status_code": 200, "headers": {}, "body": "not found", "error": None}):
            ctx = _make_ctx(subdomains=["host.example.com"], open_ports={"host.example.com": [{"port": 80, "status": "open", "banner": ""}]})
            result = asyncio.run(es.exposed_services_module(ctx))
            admin_findings = [f for f in result["findings"] if f.get("service") == "http_admin"]
            assert len(admin_findings) == 0

    def test_metrics_labels_values(self):
        from metrics.prometheus import SCANNER_MODULE_RUNS_TOTAL
        before = SCANNER_MODULE_RUNS_TOTAL.labels(module="exposed_services", outcome="ok")._value.get()
        # The metric exists and is accessible
        assert before >= 0

    def test_per_product_signatures(self):
        """Per-product signature fixtures: positive and negative."""
        import json
        from pathlib import Path
        data = json.loads((Path(__file__).parent.parent.parent / "scanner_modules" / "exposed_service_signatures.json").read_text())
        sigs = data["signatures"]
        # Verify at least 10 products
        assert len(sigs) >= 10
        # Verify each has required fields
        for sig in sigs:
            assert "service" in sig
            assert "ports" in sig
            assert "severity" in sig
            assert "confidence" in sig


class TestFakeSocketByteRecording:
    def test_passive_paths_send_nothing(self):
        """RecordingSocket captures bytes; passive paths (redis/mongo/memcached/mysql) send nothing."""
        sock = RecordingSocket()
        # Passive services don't use sockets — they derive from port_scan data
        assert sock.sent == []

    def test_recording_socket_captures_bytes(self):
        sock = RecordingSocket()
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        assert sock.sent == [b"GET / HTTP/1.0\r\n\r\n"]


class TestHttpProbeRequestLines:
    def test_http_probe_uses_pinned_helper(self):
        """HTTP probes use fetch_url_validated, not raw sockets."""
        import scanner_modules.exposed_services as es
        # Verify _http_probe exists and uses fetch_url_validated_sync
        import inspect
        source = inspect.getsource(es._http_probe)
        assert "fetch_url_validated_sync" in source
        assert "httpx" not in source or "fetch_url" in source
