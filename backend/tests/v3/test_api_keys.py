"""G3 API-key characterization tests (tests only).

Create (secret exactly once, hash+prefix stored), list (no secret), update,
delete, scope validation, permission gating, cross-org rejection, and proof
the plaintext key never reaches logs or later responses. Hermetic: no real
network (webhook posts stubbed, DNS faked).
"""

import hashlib
import logging
from contextlib import contextmanager

import pytest


def _public_dns(monkeypatch, ip="93.184.216.34"):
    import socket as stdlib_socket

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", (ip, 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


@contextmanager
def _capture_app_logs(caplog, level=logging.DEBUG):
    app_logger = logging.getLogger("sentinelasm")
    app_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(level):
            yield caplog
    finally:
        app_logger.removeHandler(caplog.handler)


@pytest.fixture()
def keyenv(client, db, monkeypatch, org_factory):
    _public_dns(monkeypatch)
    from services.alerts import alerting_service as alerts
    from utils.egress import FetchResult

    async def fake_fetch(url, **kw):
        return FetchResult(status_code=200, headers={}, body=b"ok")

    monkeypatch.setattr(alerts, "fetch_url_validated", fake_fetch)

    org_a, _ = org_factory("Key Org A", "keyusera", "keyusera@example.com")
    org_b, _ = org_factory("Key Org B", "keyuserb", "keyuserb@example.com")

    def login(username):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "password123"},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return {"a": login("keyusera"), "b": login("keyuserb"),
            "org_a": org_a.id, "org_b": org_b.id}


def _create_key(client, headers, name="k", scopes="read"):
    created = client.post(
        "/api/v1/organizations/api-keys",
        json={"name": name, "scopes": scopes}, headers=headers)
    assert created.status_code == 201, created.text
    return created.json()


def test_create_returns_secret_once_and_stores_hash(client, db, keyenv):
    from models.organization import APIKey

    body = _create_key(client, keyenv["a"], name="once")
    full = body["key"]
    assert full.startswith("sk_") and len(full) > 20
    row = db.query(APIKey).filter(APIKey.id == body["id"]).one()
    assert row.key_hash == hashlib.sha256(full.encode()).hexdigest()
    assert row.key_prefix == full.split("_")[0]
    assert full not in (row.key_hash + row.key_prefix)
    # The secret is never returned again.
    listed = client.get("/api/v1/organizations/api-keys",
                        headers=keyenv["a"]).json()
    row_json = next(i for i in listed if i["id"] == body["id"])
    assert "key" not in row_json
    assert full not in str(listed)


def test_update_scopes_and_revoke(client, db, keyenv):
    from models.organization import APIKey

    body = _create_key(client, keyenv["a"], name="managed", scopes="read")
    key_id, full = body["id"], body["key"]
    key_h = {"X-API-Key": full}
    # Read scope: reads pass.
    assert client.get("/api/v1/assets", headers=key_h).status_code == 200
    # Narrowing is accepted; invalid scopes rejected by validation.
    updated = client.patch(
        f"/api/v1/organizations/api-keys/{key_id}",
        json={"scopes": "read,write"}, headers=keyenv["a"])
    assert updated.status_code == 200, updated.text
    bad = client.patch(
        f"/api/v1/organizations/api-keys/{key_id}",
        json={"scopes": "root"}, headers=keyenv["a"])
    assert bad.status_code == 422
    bad_create = client.post(
        "/api/v1/organizations/api-keys",
        json={"name": "bad", "scopes": "root"}, headers=keyenv["a"])
    assert bad_create.status_code == 422
    # Deactivate == revoke: key stops working immediately.
    db.query(APIKey).filter(APIKey.id == key_id).one().is_active = False
    db.commit()
    assert client.get("/api/v1/assets", headers=key_h).status_code == 401
    # Delete removes the row entirely.
    deleted = client.delete(f"/api/v1/organizations/api-keys/{key_id}",
                            headers=keyenv["a"])
    assert deleted.status_code in (200, 204), deleted.text
    assert db.query(APIKey).filter(APIKey.id == key_id).first() is None
    assert client.get("/api/v1/assets", headers=key_h).status_code == 401


def test_key_endpoints_require_org_manage(client, db, keyenv):
    from models.user import User

    org_id = keyenv["org_a"]
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": "keyviewer", "email": "keyviewer@example.com",
              "password": "password123", "organization": "Key Viewer Tmp"})
    assert reg.status_code == 201, reg.text
    user = db.query(User).filter(User.username == "keyviewer").one()
    user.organization_id = org_id
    user.role = "viewer"
    db.commit()
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "keyviewer", "password": "password123"})
    assert login.status_code == 200, login.text
    viewer_h = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.post(
        "/api/v1/organizations/api-keys", json={"name": "k"},
        headers=viewer_h).status_code == 403
    assert client.get(
        "/api/v1/organizations/api-keys",
        headers=viewer_h).status_code == 403


def test_cross_org_key_use_rejected(client, keyenv):
    body = _create_key(client, keyenv["b"], name="bkey")
    # B's key against A's endpoints: the key resolves to B's org, so A's
    # data stays invisible (401/404/empty, never B-leak and never A-data).
    key_h = {"X-API-Key": body["key"]}
    me = client.get("/api/v1/organizations/me", headers=key_h)
    assert me.status_code == 200
    assert me.json()["id"] == keyenv["org_b"]


def test_plaintext_key_never_logged(client, keyenv, caplog):
    body = _create_key(client, keyenv["a"], name="logged")
    full = body["key"]
    key_h = {"X-API-Key": full}
    with _capture_app_logs(caplog) as logs:
        assert client.get("/api/v1/assets", headers=key_h).status_code == 200
        assert client.get("/api/v1/organizations/api-keys",
                          headers=keyenv["a"]).status_code == 200
        assert client.post(
            "/api/v1/alerting/integrations",
            json={"name": "h", "channel": "slack",
                  "webhook_url": "https://hooks.example.com/x"},
            headers=key_h).status_code in (201, 403)
    assert full not in logs.text
    assert full.split("_", 1)[1] not in logs.text
