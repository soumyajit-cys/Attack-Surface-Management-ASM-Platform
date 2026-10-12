"""1.5.5 /metrics deny-by-default tests.

Unauthenticated/bad-token/spoofed-XFF requests are denied; a valid bearer
or an allowed peer CIDR is admitted. No real network.
"""

import pytest


def _request(peer, headers=None):
    from starlette.requests import Request

    raw = [(b"host", b"test")]
    for key, value in (headers or {}).items():
        raw.append((key.encode(), value.encode()))
    scope = {"type": "http", "method": "GET", "path": "/metrics",
             "headers": raw, "client": (peer, 1234)}
    return Request(scope)


def test_metrics_unauthenticated_denied(client):
    response = client.get("/metrics")
    assert response.status_code == 401


def test_metrics_bad_token_denied(client):
    response = client.get("/metrics",
                          headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401


def test_metrics_good_token_allowed(client, monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "metrics_bearer_token",
                        "test-metrics-token")
    response = client.get(
        "/metrics", headers={"Authorization": "Bearer test-metrics-token"})
    assert response.status_code == 200
    assert b"sentinelasm_" in response.content


def test_metrics_spoofed_xff_grants_nothing(client, monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "metrics_bearer_token",
                        "test-metrics-token")
    monkeypatch.setattr(config_mod.settings, "metrics_allowed_cidrs",
                        "127.0.0.1/32")
    response = client.get(
        "/metrics", headers={"X-Forwarded-For": "127.0.0.1"})
    assert response.status_code == 401


def test_metrics_cidr_helper():
    """Unit: peer-CIDR admission never consults X-Forwarded-For."""
    from main import metrics_allowed

    import app.core.config as config_mod

    config_mod.settings.metrics_allowed_cidrs = "127.0.0.1/32"
    try:
        assert metrics_allowed(_request("127.0.0.1")) is True
        assert metrics_allowed(
            _request("203.0.113.9",
                     {"X-Forwarded-For": "127.0.0.1"})) is False
        assert metrics_allowed(_request("::1")) is False
    finally:
        config_mod.settings.metrics_allowed_cidrs = "127.0.0.1/32"
