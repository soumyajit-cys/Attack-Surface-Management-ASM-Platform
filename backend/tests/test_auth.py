def test_register_login_me(client):
    response = client.post(
        "/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "supersecret1",
            "organization": "Acme Corp",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]

    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "supersecret1"},
    )
    assert response.status_code == 200, response.text

    access = response.json()["access_token"]

    me = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["role"] == "admin"


def test_register_duplicate_username(client):
    payload = {
        "username": "bob",
        "email": "bob@example.com",
        "password": "supersecret1",
        "organization": "Acme Corp",
    }
    assert client.post("/auth/register", json=payload).status_code == 201
    assert client.post("/auth/register", json=payload).status_code == 409


def test_login_wrong_password(client):
    client.post(
        "/auth/register",
        json={
            "username": "carol",
            "email": "carol@example.com",
            "password": "supersecret1",
            "organization": "Acme Corp",
        },
    )
    response = client.post(
        "/auth/login",
        json={"username": "carol", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_refresh_rotates_and_revokes_old(client):
    client.post(
        "/auth/register",
        json={
            "username": "dave",
            "email": "dave@example.com",
            "password": "supersecret1",
            "organization": "Acme Corp",
        },
    )
    login = client.post(
        "/auth/login",
        json={"username": "dave", "password": "supersecret1"},
    ).json()
    old_refresh = login["refresh_token"]

    refreshed = client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert refreshed.status_code == 200, refreshed.text
    new_refresh = refreshed.json()["refresh_token"]
    assert new_refresh != old_refresh

    replay = client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert replay.status_code == 401


def test_logout_revokes_tokens(client):
    client.post(
        "/auth/register",
        json={
            "username": "erin",
            "email": "erin@example.com",
            "password": "supersecret1",
            "organization": "Acme Corp",
        },
    )
    login = client.post(
        "/auth/login",
        json={"username": "erin", "password": "supersecret1"},
    ).json()
    access = login["access_token"]

    assert (
        client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access}"},
        ).status_code
        == 200
    )

    client.post(
        "/auth/logout",
        json={"refresh_token": login["refresh_token"]},
    )

    assert (
        client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access}"},
        ).status_code
        == 401
    )


def test_password_reset_flow(client):
    client.post(
        "/auth/register",
        json={
            "username": "frank",
            "email": "frank@example.com",
            "password": "supersecret1",
            "organization": "Acme Corp",
        },
    )

    from auth import jwt as token_service
    from models.user import User
    from utils.database import SessionLocal

    db = SessionLocal()
    user = db.query(User).filter(User.username == "frank").first()
    reset_token = token_service.create_password_reset_token(user.id)
    db.close()

    response = client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": "brandnewpass1"},
    )
    assert response.status_code == 200, response.text

    login = client.post(
        "/auth/login",
        json={"username": "frank", "password": "brandnewpass1"},
    )
    assert login.status_code == 200

    reuse = client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": "anotherpass1"},
    )
    assert reuse.status_code == 400


def test_unauthenticated_requests_rejected(client):
    assert client.get("/auth/me").status_code == 401
    assert client.get("/findings/").status_code == 401
    assert client.get("/dashboard/").status_code == 401