"""1.5.6 session hygiene (tests only, red first).

Refresh reuse revokes the whole token family (+audit); password reset
revokes every session of the user; deactivated users lose refresh too.
Imports are function-level; behavior cases are strict-xfailed until
implementation lands. No real network.
"""

import pytest


def _register(client, username, org="Session Org"):
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


def test_refresh_reuse_revokes_family(client, db):
    _register(client, "sessreuse")
    first = _login(client, "sessreuse")
    rotated = client.post("/api/v1/auth/refresh",
                          json={"refresh_token": first["refresh_token"]})
    assert rotated.status_code == 200, rotated.text
    replay = client.post("/api/v1/auth/refresh",
                         json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401
    # The whole family is dead, including the rotated-in tokens.
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": rotated.json()["refresh_token"]}
    ).status_code == 401
    assert client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {rotated.json()['access_token']}"}
    ).status_code == 401
    from models.audit_log import AuditLog

    event = db.query(AuditLog).filter(
        AuditLog.action == "auth.refresh_reuse").order_by(
            AuditLog.id.desc()).first()
    assert event is not None


def test_password_reset_revokes_all_sessions(client, db):
    from auth import jwt as tokens
    from models.user import User

    _register(client, "sessreset")
    session_a = _login(client, "sessreset")
    session_b = _login(client, "sessreset")
    user = db.query(User).filter(User.username == "sessreset").one()
    reset_token = tokens.create_password_reset_token(user.id)
    reset = client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "brandnewpass1"})
    assert reset.status_code == 200, reset.text
    for bundle in (session_a, session_b):
        assert client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {bundle['access_token']}"}
        ).status_code == 401
        assert client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": bundle["refresh_token"]}
        ).status_code == 401


def test_refresh_after_deactivation_denied(client, db):
    """Deactivated users lose refresh as well as access (documents G6.9)."""
    from models.user import User

    _register(client, "sessdeact")
    bundle = _login(client, "sessdeact")
    db.query(User).filter(User.username == "sessdeact").one().is_active = False
    db.commit()
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": bundle["refresh_token"]}).status_code == 401
