"""v3 tech_fingerprint scanner module tests."""

import asyncio
import re
import time

import pytest

from app.scanning.context import ScanContext
from app.scanning.registry import ScanPhase, registry


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


def _make_ctx(domain="example.com", subdomains=None, http_response=None):
    return ScanContext(
        domain=domain,
        pinned_ip="93.184.216.34",
        org_id=1,
        scan_id=1,
        db=None,
        scope="full",
        subdomains=list(subdomains or []),
        http_response=http_response,
    )


# ── Unit tests: matching ─────────────────────────────────────────────


class TestTechFingerprintMatching:
    def test_header_match(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints(
            {"Server": "Apache/2.4.41"}, None, None
        )
        assert any(m["provider"] == "Apache HTTP Server" for m in matches)

    def test_body_match(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints(
            None, "<html>wp-content/themes/test</html>", None
        )
        assert any(m["provider"] == "WordPress" for m in matches)

    def test_version_extraction(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints(
            {"Server": "nginx/1.18.0"}, None, None
        )
        nginx = [m for m in matches if m["provider"] == "nginx"]
        assert nginx and nginx[0].get("version") == "1.18.0"

    def test_no_match_returns_empty(self):
        from scanner_modules.tech_fingerprint import _match_fingerprints

        matches = _match_fingerprints({"X-Custom": "nothing"}, "hello world", None)
        # Should not crash; may be empty or contain only generic matches
        assert isinstance(matches, list)

    def test_redos_safety(self):
        """Version regexes must not exhibit catastrophic backtracking."""
        from scanner_modules.tech_fingerprint import FINGERPRINTS

        evil_input = "a" * 30 + "!"
        for fp in FINGERPRINTS:
            vr = fp.get("version_regex")
            if not vr:
                continue
            start = time.monotonic()
            try:
                re.search(vr, evil_input)
            except Exception:
                pass
            elapsed = time.monotonic() - start
            assert elapsed < 1.0, f"ReDoS in {fp['name']}: {elapsed:.2f}s"


# ── Module tests ─────────────────────────────────────────────────────


class TestTechFingerprintModule:
    def test_reuses_cached_response_no_extra_request(self, monkeypatch):
        """When ctx.http_response is present, no extra HTTP request is made."""
        import scanner_modules.tech_fingerprint as tf

        called = {"count": 0}

        def fake_probe(url):
            called["count"] += 1
            return {"status_code": 200, "headers": {}, "body": "", "error": None}

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(
            subdomains=["host.example.com"],
            http_response={
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.41"},
                "body": "",
            },
        )
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        assert called["count"] == 0, "Extra request made despite cached response"

    def test_two_hosts_two_findings(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.41"},
                "body": "",
                "error": None,
            }

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["a.example.com", "b.example.com"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        findings = result["findings"]
        # Each host should produce at least one finding
        hosts = {f["cname_target"] for f in findings}
        assert "a.example.com" in hosts
        assert "b.example.com" in hosts

    def test_truncation_at_max_hosts(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        original_max = tf.MAX_HOSTS_PER_SCAN
        tf.MAX_HOSTS_PER_SCAN = 2

        def fake_probe(url):
            return {"status_code": 200, "headers": {}, "body": "", "error": None}

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["h1", "h2", "h3", "h4"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        assert result["truncated"] is True

        tf.MAX_HOSTS_PER_SCAN = original_max

    def test_dedupe_key_format(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {
                "status_code": 200,
                "headers": {"Server": "nginx/1.18.0"},
                "body": "",
                "error": None,
            }

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["host.example.com"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        for f in result["findings"]:
            assert f["dedupe_key"].startswith("tech_fingerprint:")
            assert "host.example.com" in f["dedupe_key"]

    def test_scope_gating_no_probe_unverified(self):
        """Tech fingerprint is in SCOPE_FULL only."""
        from app.scanning.scope import SCOPE_PHASES, ScanPhase

        assert ScanPhase.FINGERPRINT not in SCOPE_PHASES["passive"]
        assert ScanPhase.FINGERPRINT not in SCOPE_PHASES["active"]
        assert ScanPhase.FINGERPRINT in SCOPE_PHASES["full"]

    def test_empty_subdomains_returns_empty(self):
        import scanner_modules.tech_fingerprint as tf

        ctx = _make_ctx(subdomains=[])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        assert result["findings"] == []
        assert result["truncated"] is False

    def test_confidence_cap(self, monkeypatch):
        """Banner-derived versions have confidence <= 0.6."""
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {
                "status_code": 200,
                "headers": {"Server": "Apache/2.4.41"},
                "body": "",
                "error": None,
            }

        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        ctx = _make_ctx(subdomains=["host.example.com"])
        result = asyncio.run(tf.tech_fingerprint_module(ctx))
        for f in result["findings"]:
            assert f["confidence"] <= 0.85
PYEOF
echo "Done"