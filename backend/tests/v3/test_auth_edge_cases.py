"""G6 auth/token edge cases (tests only).

Maps each case to a test node ID. Already covered in test_auth.py (not
duplicated here): register/login/me, duplicate username, wrong password,
refresh rotation + old revocation, logout revocation, reset flow + reuse,
unauthenticated rejection. Hermetic: no network.
"""

from datetime import datetime, timedelta, timezone


def _register(client, username, org="G6 Org"):
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": f"{username}@example.com",
              "password": "password123", "organization": org},
    )
    assert reg.status_code == 201, reg.text
    return reg.json()


def _past_token(user_id, token_type="access"):
    from auth import jwt as tokens

    return tokens._encode(
        user_id, token_type,
        datetime.now(timezone.utc) - timedelta(seconds=10))


def test_g6_tampered_signature_rejected(client, db):
    """G6.1: flipped payload chars fail signature verification (401)."""
    bundle = _register(client, "g6tamper")
    token = bundle["access_token"]
    head, payload, sig = token.split(".")
    tampered = head + ("A" if not payload.startswith("A") else "B") \
        + payload[1:] + "." + sig
    response = client.get("/api/v1/auth/me",
                          headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401


def test_g6_expired_access_rejected(client, db):
    """G6.2: exp must be in the future."""
    from models.user import User

    _register(client, "g6expaccess")
    user = db.query(User).filter(User.username == "g6expaccess").one()
    stale = _past_token(user.id, "access")
    response = client.get("/api/v1/auth/me",
                          headers={"Authorization": f"Bearer {stale}"})
    assert response.status_code == 401


def test_g6_expired_refresh_rejected(client, db):
    """G6.3: expired refresh token cannot mint (401)."""
    from models.user import User

    _register(client, "g6exprefresh")
    user = db.query(User).filter(User.username == "g6exprefresh").one()
    stale = _past_token(user.id, "refresh")
    response = client.post("/api/v1/auth/refresh",
                           json={"refresh_token": stale})
    assert response.status_code == 401


def test_g6_wrong_token_type_both_directions(client):
    """G6.4: refresh-as-access and access-as-refresh both 401."""
    bundle = _register(client, "g6types")
    access, refresh = bundle["access_token"], bundle["refresh_token"]
    assert client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {refresh}"}).status_code == 401
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": access}).status_code == 401


def test_g6_access_dead_after_logout(client):
    """G6.5: logout revokes both tokens when both are submitted."""
    bundle = _register(client, "g6logout")
    headers = {"Authorization": f"Bearer {bundle['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": bundle["refresh_token"],
              "access_token": bundle["access_token"]},
        headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_g6_refresh_reuse_after_rotation_rejected(client):
    """G6.6: rotated-out refresh token is single-use (maps test_auth rotation)."""
    bundle = _register(client, "g6reuse")
    first = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": bundle["refresh_token"]})
    assert first.status_code == 200, first.text
    replay = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": bundle["refresh_token"]})
    assert replay.status_code == 401
    # The rotated-in token still works.
    second = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first.json()["refresh_token"]})
    assert second.status_code == 200


def test_g6_reset_token_expiry(client, db):
    """G6.7: reset tokens older than 30 min are rejected."""
    from auth import jwt as tokens
    from models.user import User

    _register(client, "g6resetexp")
    user = db.query(User).filter(User.username == "g6resetexp").one()
    stale = tokens._encode(
        user.id, tokens.PASSWORD_RESET,
        datetime.now(timezone.utc) - timedelta(seconds=1))
    response = client.post(
        "/api/v1/auth/reset-password",
        json={"token": stale, "new_password": "password123"})
    assert response.status_code in (400, 401)


def test_g6_missing_and_invalid_claims(client, db):
    """G6.8: no-sub and unknown-user tokens are 401, never 500."""
    from auth import jwt as tokens
    from models.user import User

    _register(client, "g6claims")
    secret = tokens.settings.jwt_secret_for_use
    from jose import jwt as pyjwt

    now = datetime.now(timezone.utc)
    no_sub = pyjwt.encode(
        {"type": "access", "exp": now + timedelta(minutes=5)},
        secret, algorithm="HS256")
    assert client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {no_sub}"}).status_code == 401
    ghost = tokens._encode(999999999, "access",
                           now + timedelta(minutes=5))
    assert client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {ghost}"}).status_code == 401
    assert db.query(User).filter(User.id == 999999999).first() is None


def test_g6_deactivated_user_token_stops_working(client, db):
    """G6.9: deactivating the user kills outstanding tokens (is_active gate)."""
    from models.user import User

    bundle = _register(client, "g6deact")
    headers = {"Authorization": f"Bearer {bundle['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    db.query(User).filter(User.username == "g6deact").one().is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_g6_unknown_user_vs_wrong_password(client):
    """G6.10 FINDING: unknown-user and wrong-password responses compared."""
    unknown = client.post(
        "/api/v1/auth/login",
        json={"username": "nosuchuserxyz", "password": "password123"})
    _register(client, "g6known")
    wrong = client.post(
        "/api/v1/auth/login",
        json={"username": "g6known", "password": "otherpassword"})
    assert unknown.status_code == wrong.status_code == 401
    # Bodies must not distinguish the two cases (user enumeration).
    assert unknown.json() == wrong.json()
