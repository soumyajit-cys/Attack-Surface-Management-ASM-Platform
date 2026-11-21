"""Per-module metric tests for SCANNER_MODULE_RUNS_TOTAL."""

import asyncio

import pytest

from app.scanning.context import ScanContext
from metrics.prometheus import SCANNER_MODULE_RUNS_TOTAL


@pytest.fixture(autouse=True)
def _fresh_registry():
    import sys
    from app.scanning.registry import registry
    old_entries = dict(registry._entries)
    old_discovered = registry._discovered
    old_failed = dict(registry._failed_imports)
    _evicted = [n for n in list(sys.modules) if n == "scanner_modules" or n.startswith("scanner_modules.")]
    for n in _evicted:
        del sys.modules[n]
    registry._entries.clear()
    registry._discovered = False
    yield
    for n in _evicted:
        if n in sys.modules:
            del sys.modules[n]
    registry._entries.clear()
    registry._entries.update(old_entries)
    registry._discovered = old_discovered
    registry._failed_imports.clear()
    registry._failed_imports.update(old_failed)


def _make_ctx(domain="example.com", subdomains=None):
    return ScanContext(
        domain=domain,
        pinned_ip="93.184.216.34",
        org_id=1,
        scan_id=1,
        db=None,
        scope="full",
        subdomains=list(subdomains or []),
    )


class TestSubdomainTakeoverMetrics:
    def test_ok_increments_by_one(self, monkeypatch):
        import scanner_modules.subdomain_takeover as st
        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="subdomain_takeover", outcome="ok")
        before = counter._value.get()

        def fake_resolve(qname, rdtype, lifetime):
            raise Exception("no dns")
        monkeypatch.setattr("dns.resolver.resolve", fake_resolve)

        ctx = _make_ctx(subdomains=["host.example.com"])
        asyncio.run(st.subdomain_takeover_module(ctx))

        assert counter._value.get() == before + 1

    def test_truncated_increments_by_one(self, monkeypatch):
        import scanner_modules.subdomain_takeover as st
        st.MAX_HOSTS_PER_SCAN = 0
        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="subdomain_takeover", outcome="truncated")
        before = counter._value.get()

        def fake_resolve(qname, rdtype, lifetime):
            raise Exception("no dns")
        monkeypatch.setattr("dns.resolver.resolve", fake_resolve)

        ctx = _make_ctx(subdomains=["host.example.com"])
        asyncio.run(st.subdomain_takeover_module(ctx))

        assert counter._value.get() == before + 1


class TestTechFingerprintMetrics:
    def test_ok_increments_by_one(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf

        def fake_probe(url):
            return {"status_code": 200, "headers": {}, "body": "", "error": None}
        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="tech_fingerprint", outcome="ok")
        before = counter._value.get()

        ctx = _make_ctx(subdomains=["host.example.com"])
        asyncio.run(tf.tech_fingerprint_module(ctx))

        assert counter._value.get() == before + 1

    def test_truncated_increments_by_one(self, monkeypatch):
        import scanner_modules.tech_fingerprint as tf
        tf.MAX_HOSTS_PER_SCAN = 0

        def fake_probe(url):
            return {"status_code": 200, "headers": {}, "body": "", "error": None}
        monkeypatch.setattr(tf, "_http_probe", fake_probe)

        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="tech_fingerprint", outcome="truncated")
        before = counter._value.get()

        ctx = _make_ctx(subdomains=["host.example.com"])
        asyncio.run(tf.tech_fingerprint_module(ctx))

        assert counter._value.get() == before + 1


class TestSslScanMetrics:
    def test_ok_increments_by_one(self, monkeypatch):
        import scanner_modules.ssl_scan as ss

        async def fake_analyze(host):
            return {"host": host, "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "expired": False, "self_signed": False, "expires_at": None}
        monkeypatch.setattr("services.scanner.ssl_scanner.analyze_ssl", fake_analyze)

        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="ssl_scan", outcome="ok")
        before = counter._value.get()

        ctx = _make_ctx()
        asyncio.run(ss.ssl_scan_module(ctx))

        assert counter._value.get() == before + 1

    def test_error_increments_by_one(self, monkeypatch):
        import scanner_modules.ssl_scan as ss

        async def fake_analyze(host):
            raise RuntimeError("boom")
        monkeypatch.setattr("services.scanner.ssl_scanner.analyze_ssl", fake_analyze)

        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="ssl_scan", outcome="error")
        before = counter._value.get()

        ctx = _make_ctx()
        try:
            asyncio.run(ss.ssl_scan_module(ctx))
        except RuntimeError:
            pass

        assert counter._value.get() == before + 1


class TestEmailSecurityMetrics:
    def test_ok_increments_by_one(self, monkeypatch):
        import scanner_modules.email_security as es

        def fake_resolve(qname, rdtype, lifetime):
            raise Exception("no dns")
        monkeypatch.setattr("dns.resolver.resolve", fake_resolve)

        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="email_security", outcome="ok")
        before = counter._value.get()

        ctx = _make_ctx()
        asyncio.run(es.email_security_module(ctx))

        assert counter._value.get() == before + 1

    def test_disabled_increments_by_one(self, monkeypatch):
        import scanner_modules.email_security as es
        from app.core.config import settings
        monkeypatch.setattr(settings, "email_security_enabled", False)

        counter = SCANNER_MODULE_RUNS_TOTAL.labels(module="email_security", outcome="disabled")
        before = counter._value.get()

        ctx = _make_ctx()
        asyncio.run(es.email_security_module(ctx))

        assert counter._value.get() == before + 1
