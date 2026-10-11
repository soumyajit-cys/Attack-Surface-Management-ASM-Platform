"""G5 rate-limit characterization (tests only).

The limiter is NOT disabled in tests: slowapi counts against Redis db 15,
which conftest flushes between tests (storage isolation). Each case sends
limit+1 requests and pins the 429 + envelope. Hermetic: DNS faked, Celery
delays stubbed, no real network.
"""

import pytest


def _public_dns(monkeypatch, ip="93.184.216.34"):
    import socket as stdlib_socket

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", (ip, 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


@pytest.fixture()
def sterile(client, monkeypatch):
    _public_dns(monkeypatch)
    from tasks import discovery_tasks as dt

    monkeypatch.setattr(dt.run_discovery, "delay", lambda *a, **k: None)
    return client


def _hammer(client, method, url, count, **kwargs):
    responses = [
        client.request(method, url, **kwargs) for _ in range(count)
    ]
    return responses


def test_register_limit(client):
    for i in range(10):
        response = client.post(
            "/api/v1/auth/register",
            json={"username": f"rl{i}", "email": f"rl{i}@example.com",
                  "password": "password123", "organization": f"RL Org {i}"},
        )
        assert response.status_code == 201, response.text[:100]
    blocked = client.post(
        "/api/v1/auth/register",
        json={"username": "rl10", "email": "rl10@example.com",
              "password": "password123", "organization": "RL Org 10"},
    )
    assert blocked.status_code == 429
    assert "error" in blocked.json()


def test_login_limit(client):
    for _ in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "nosuchuser", "password": "wrong"})
        assert response.status_code == 401
    blocked = client.post(
        "/api/v1/auth/login",
        json={"username": "nosuchuser", "password": "wrong"})
    assert blocked.status_code == 429
    assert "error" in blocked.json()


def test_forgot_and_reset_limits(client):
    for _ in range(3):
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nobody@example.com"})
        assert response.status_code in (200, 404), response.text[:100]
    blocked = client.post(
        "/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    assert blocked.status_code == 429
    for _ in range(3):
        response = client.post(
            "/api/v1/auth/reset-password",
            json={"token": "bogus", "new_password": "password123"})
        assert response.status_code in (200, 400, 404), response.text[:100]
    blocked = client.post(
        "/api/v1/auth/reset-password",
        json={"token": "bogus", "new_password": "password123"})
    assert blocked.status_code == 429


def test_scan_limit_with_verified_domain(sterile, monkeypatch, db):
    from datetime import datetime, timedelta, timezone

    from models.verified_domain import VerifiedDomain
    from services.discovery import domain_service

    async def fake_resolve(domain):
        return {"domain": domain, "ip": "93.184.216.34", "pinned": False}

    monkeypatch.setattr(domain_service, "resolve_domain", fake_resolve)
    client = sterile
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": "rlscan", "email": "rlscan@example.com",
              "password": "password123", "organization": "RL Scan Org"},
    )
    assert reg.status_code == 201, reg.text
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    org_id = reg.json()["user"]["organization_id"]
    now = datetime.now(timezone.utc)
    db.add(VerifiedDomain(
        organization_id=org_id, domain="rlscan.example.com", method="dns_txt",
        status="verified", token="t", verified_at=now,
        expires_at=now + timedelta(days=90)))
    db.commit()
    for _ in range(5):
        response = client.post(
            "/api/v1/scans", json={"domain": "rlscan.example.com"},
            headers=headers)
        assert response.status_code == 202, response.text[:150]
    blocked = client.post(
        "/api/v1/scans", json={"domain": "rlscan.example.com"},
        headers=headers)
    assert blocked.status_code == 429
    assert "error" in blocked.json()


def test_verify_ownership_limits(sterile):
    client = sterile
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": "rlverify", "email": "rlverify@example.com",
              "password": "password123", "organization": "RL Verify Org"},
    )
    assert reg.status_code == 201, reg.text
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    for _ in range(10):
        response = client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "rlverify.example.com"}, headers=headers)
        assert response.status_code in (200, 201, 400, 403, 422), (
            response.text[:150])
    blocked = client.post(
        "/api/v1/scans/verify-ownership",
        json={"domain": "rlverify.example.com"}, headers=headers)
    assert blocked.status_code == 429
    for _ in range(20):
        response = client.get(
            "/api/v1/scans/verify-ownership/check",
            params={"domain": "rlverify.example.com"}, headers=headers)
        assert response.status_code in (200, 400, 403, 404, 422), (
            response.text[:150])
    blocked = client.get(
        "/api/v1/scans/verify-ownership/check",
        params={"domain": "rlverify.example.com"}, headers=headers)
    assert blocked.status_code == 429


def test_global_default_limit(sterile):
    """Undecorated routes share the 60/min default (SlowAPIMiddleware)."""
    client = sterile
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": "rlglob", "email": "rlglob@example.com",
              "password": "password123", "organization": "RL Glob Org"},
    )
    assert reg.status_code == 201, reg.text
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    for _ in range(60):
        response = client.get("/api/v1/assets", headers=headers)
        assert response.status_code == 200, response.text[:150]
    blocked = client.get("/api/v1/assets", headers=headers)
    assert blocked.status_code == 429
    assert "error" in blocked.json()


def test_health_exempt_from_limiter(sterile):
    """Container health checks must never 429."""
    for _ in range(65):
        response = sterile.get("/health")
        assert response.status_code == 200, response.status_code


def test_metrics_stays_limited(sterile):
    """Deliberate: /metrics keeps the 60/min default (scrapes are ~4/min)."""
    for _ in range(60):
        assert sterile.get("/metrics").status_code == 200
    assert sterile.get("/metrics").status_code == 429


def test_limiter_storage_resets_between_tests(client):
    """conftest flushes Redis db 15 per test: a fresh test starts at zero."""
    for _ in range(10):
        assert client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "x"}).status_code == 401
    # If storage leaked from another test, even the first request would 429.
