"""v1 auth endpoint tests (error envelope, audit rows, org name in /me)."""

from sqlalchemy import select

from models.audit_log import AuditLog


def _register(client, username="v1user", org="V1 Org"):
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "organization": org,
        },
    )


def test_register_returns_user_with_org_name_and_permissions(client):
    response = _register(client)
    assert response.status_code == 201, response.text
    body = response.json()

    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]

    user = body["user"]
    assert user["role"] == "admin"
    assert user["organization_name"] == "V1 Org"
    assert "org:manage" in user["permissions"]
    assert "scan:create" in user["permissions"]


def test_register_duplicate_username_conflict_envelope(client):
    _register(client, username="dupuser")
    response = _register(client, username="dupuser", org="Other Org")
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "username_taken"
    assert error["message"] == "Username already taken"


def test_login_wrong_password_returns_401_envelope(client):
    _register(client)
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "v1user", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_me_includes_organization_name(client):
    _register(client)
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "v1user", "password": "password123"},
    )
    token = login.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["organization_name"] == "V1 Org"
    assert "finding:read" in me.json()["permissions"]


def test_refresh_rotation_and_replay_rejected(client):
    _register(client)
    tokens = client.post(
        "/api/v1/auth/login",
        json={"username": "v1user", "password": "password123"},
    ).json()

    first = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert first.status_code == 200
    new_refresh = first.json()["refresh_token"]

    # Replaying the OLD refresh token must fail.
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401

    # The rotated token still works.
    second = client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert second.status_code == 200


def test_logout_revokes_refresh_token(client):
    _register(client)
    tokens = client.post(
        "/api/v1/auth/login",
        json={"username": "v1user", "password": "password123"},
    ).json()

    out = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert out.status_code == 200

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401


def test_login_writes_audit_rows(client, db):
    _register(client)
    client.post(
        "/api/v1/auth/login",
        json={"username": "v1user", "password": "password123"},
    )
    client.post(
        "/api/v1/auth/login",
        json={"username": "v1user", "password": "bad-password"},
    )

    actions = set(db.execute(select(AuditLog.action)).scalars())
    assert "auth.register" in actions
    assert "auth.login" in actions
    assert "auth.login_failed" in actions


def test_validation_error_envelope(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "x"},  # missing fields
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"]
