"""Change-password characterization tests.

POST /auth/change-password: current password required; TOTP/recovery code
when 2FA is on; all OTHER sessions die while the caller's access token
survives; failures feed the shared login lockout counters; audit event.
No real network.
"""

import pytest


def _register(client, username, org="PW Org"):
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": f"{username}@example.com",
              "password": "password123", "organization": org},
    )
    assert reg.status_code == 201, reg.text
    return reg.json()


def _login(client, username, password="password123"):
    response = client.post("/api/v1/auth/login",
                           json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def _totp_code(secret):
    import pyotp

    return pyotp.TOTP(secret).now()


def _next_code(secret):
    import time

    import pyotp

    return pyotp.TOTP(secret).at(int(time.time()) + 30)


def _enable_2fa(client, headers, password="password123"):
    enrolled = client.post("/api/v1/auth/2fa/enroll",
                           json={"password": password}, headers=headers)
    assert enrolled.status_code == 200, enrolled.text
    secret = enrolled.json()["secret"]
    confirmed = client.post("/api/v1/auth/2fa/confirm",
                            json={"code": _totp_code(secret)},
                            headers=headers)
    assert confirmed.status_code == 200, confirmed.text
    return secret


def test_change_password_revolves_others_keeps_self(client, db):
    _register(client, "pwchange")
    mine = _login(client, "pwchange")
    other = _login(client, "pwchange")
    mine_h = {"Authorization": f"Bearer {mine['access_token']}"}
    other_h = {"Authorization": f"Bearer {other['access_token']}"}
    changed = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "brandnewpass1"},
        headers=mine_h)
    assert changed.status_code == 200, changed.text
    # My access token survives; everything else is dead.
    assert client.get("/api/v1/auth/me", headers=mine_h).status_code == 200
    assert client.get("/api/v1/auth/me", headers=other_h).status_code == 401
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": other["refresh_token"]}).status_code == 401
    # Old password dead, new password works.
    assert client.post(
        "/api/v1/auth/login",
        json={"username": "pwchange",
              "password": "password123"}).status_code == 401
    assert client.post(
        "/api/v1/auth/login",
        json={"username": "pwchange",
              "password": "brandnewpass1"}).status_code == 200
    from models.audit_log import AuditLog

    assert db.query(AuditLog).filter(
        AuditLog.action == "auth.password_changed").count() == 1


def test_change_password_wrong_current_fails_shut(client, db):
    """Wrong current password: identical 401, nothing revoked, no audit."""
    from models.audit_log import AuditLog

    _register(client, "pwwrong")
    mine = _login(client, "pwwrong")
    other = _login(client, "pwwrong")
    mine_h = {"Authorization": f"Bearer {mine['access_token']}"}
    other_h = {"Authorization": f"Bearer {other['access_token']}"}
    denied = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "nottheright1",
              "new_password": "brandnewpass1"},
        headers=mine_h)
    assert denied.status_code == 401
    assert client.get("/api/v1/auth/me", headers=mine_h).status_code == 200
    assert client.get("/api/v1/auth/me", headers=other_h).status_code == 200
    assert db.query(AuditLog).filter(
        AuditLog.action == "auth.password_changed").count() == 0


def test_change_password_feeds_lockout(client):
    _register(client, "pwlock")
    bundle = _login(client, "pwlock")
    headers = {"Authorization": f"Bearer {bundle['access_token']}"}
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "wrongpass1",
                  "new_password": "brandnewpass1"},
            headers=headers)
        assert response.status_code == 401
    locked = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "brandnewpass1"},
        headers=headers)
    assert locked.status_code == 401


def test_change_password_requires_2fa_code(client, db):
    _register(client, "pw2fa")
    bundle = _login(client, "pw2fa")
    headers = {"Authorization": f"Bearer {bundle['access_token']}"}
    secret = _enable_2fa(client, headers)
    db.expire_all()
    missing = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "brandnewpass1"},
        headers=headers)
    assert missing.status_code in (400, 401)
    wrong = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "brandnewpass1", "code": "000000"},
        headers=headers)
    assert wrong.status_code in (400, 401)
    ok = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "brandnewpass1",
              "code": _next_code(secret)},
        headers=headers)
    assert ok.status_code == 200, ok.text


def test_change_password_must_differ_from_current(client, db):
    """New password identical to the current one is rejected (no-op change)."""
    _register(client, "pwdiffer")
    bundle = _login(client, "pwdiffer")
    headers = {"Authorization": f"Bearer {bundle['access_token']}"}
    same = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "password123"},
        headers=headers)
    assert same.status_code == 400
    assert same.json()["error"]["code"] == "password_reuse"
    # Nothing revoked, old password still works.
    assert client.post(
        "/api/v1/auth/login",
        json={"username": "pwdiffer",
              "password": "password123"}).status_code == 200


def test_change_password_rejects_api_keys(client, db):
    """Automation keys cannot take over the password (403, JWT-only)."""
    _register(client, "pwkey")
    admin = _login(client, "pwkey")
    admin_h = {"Authorization": f"Bearer {admin['access_token']}"}
    # Api-key creation is step-up-guarded now (v1.6.x).
    stepup = client.post("/api/v1/auth/step-up",
                         json={"password": "password123"}, headers=admin_h)
    assert stepup.status_code == 200, stepup.text
    created = client.post(
        "/api/v1/organizations/api-keys",
        json={"name": "pwkey"},
        headers=admin_h)
    assert created.status_code == 201, created.text
    key_h = {"X-API-Key": created.json()["key"]}
    denied = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "password123",
              "new_password": "brandnewpass1"},
        headers=key_h)
    assert denied.status_code == 403
