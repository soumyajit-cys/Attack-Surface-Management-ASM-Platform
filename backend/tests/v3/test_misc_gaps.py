"""G8 misc gaps: health/metrics, registry failure, pin fallback (tests only).

- GET /health is public; GET /metrics is CURRENTLY public (documented by
  test_metrics_currently_public, written so 1.5 auth hardening flips it).
- A broken scanner module logs and is skipped, rest still register.
- Redis outage during pin lookup falls back to validated fresh DNS.
Hermetic: no real network (DNS faked).
"""

import logging
from contextlib import contextmanager


@contextmanager
def _capture_app_logs(caplog, level=logging.DEBUG):
    app_logger = logging.getLogger("sentinelasm")
    app_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(level):
            yield caplog
    finally:
        app_logger.removeHandler(caplog.handler)


def test_health_open(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_currently_public(client):
    """1.5-FLIP: /metrics answers without auth today; auth hardening must
    gate it (expect this test to fail then and be updated to assert 401)."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"sentinelasm_" in response.content


def test_registry_import_failure_logged_and_skipped(monkeypatch, caplog):
    import importlib
    import sys

    from app.scanning import registry as registry_mod

    evicted = {name: mod for name, mod in sys.modules.items()
               if name == "scanner_modules" or name.startswith("scanner_modules.")}
    for name in evicted:
        del sys.modules[name]
    registry_mod.registry._entries.clear()
    registry_mod.registry._discovered = False

    real_import = importlib.import_module

    def fake_import(name, *a, **k):
        if name == "scanner_modules.port_scan":
            raise ImportError("simulated broken plugin")
        return real_import(name, *a, **k)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    try:
        with _capture_app_logs(caplog) as logs:
            entries = registry_mod.registry.get_modules()
        names = {e.name for e in entries}
        assert "Failed to import scanner module" in logs.text
        assert "scanner_modules.port_scan" in logs.text
        # The broken module is skipped; the healthy ones still register.
        assert len(entries) >= 2
        assert names, "healthy modules must still register"
    finally:
        # Restore the global singleton exactly (force real re-import so the
        # import-time decorators re-register every module).
        for name in [n for n in sys.modules
                     if n == "scanner_modules"
                     or n.startswith("scanner_modules.")]:
            del sys.modules[name]
        registry_mod.registry._entries.clear()
        registry_mod.registry._discovered = False
        registry_mod.registry.get_modules()


def test_pin_fallback_when_redis_raises(monkeypatch):
    """domain_service falls back to validated fresh DNS on Redis failure."""
    import socket as stdlib_socket

    from services.discovery import domain_service
    from utils import redis_client

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)

    class DeadRedis:
        def __getattr__(self, _name):
            raise ConnectionError("redis down")

    monkeypatch.setattr(redis_client, "_redis", DeadRedis())

    import asyncio

    result = asyncio.run(domain_service.resolve_domain("fallback.example.com"))
    assert result["ip"] == "93.184.216.34"
    assert result["pinned"] is False
