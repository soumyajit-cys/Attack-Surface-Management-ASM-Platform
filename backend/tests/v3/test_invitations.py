"""G4 invitation lifecycle + organization creation behavior (tests only).

Documents actual behavior: token generation (secrets.token_urlsafe(32),
256 bits, stored plaintext), single-use accept, expiry/revoke paths, the
no-email-check accept semantics, role assignment, and that POST
/organizations moves the caller (admin-only). Hermetic, no real network.
"""

from datetime import datetime, timedelta, timezone


def _register(client, username, org):
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": f"{username}@example.com",
              "password": "password123", "organization": org},
    )
    assert reg.status_code == 201, reg.text
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
    # Invitations are a member-change surface now guarded by step-up;
    # give every fresh admin session a live marker up front.
    stepup = client.post("/api/v1/auth/step-up",
                         json={"password": "password123"},
                         headers=headers)
    assert stepup.status_code == 200, stepup.text
    return headers


def _invite(client, headers, email="invited@example.com", role="analyst"):
    response = client.post(
        "/api/v1/organizations/invitations",
        json={"email": email, "role": role}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _token(db, invitation_id):
    from models.organization import Invitation

    return db.query(Invitation).filter(
        Invitation.id == invitation_id).one().token


def test_invitation_token_generation_and_entropy(client, db):
    """Tokens come from secrets.token_urlsafe(32): 256-bit, unique, plaintext."""
    import secrets

    assert secrets.token_urlsafe(32) and len(secrets.token_urlsafe(32)) >= 43
    headers = _register(client, "invowner", "Inv Owner Org")
    first = _invite(client, headers, email="a1@example.com")
    second = _invite(client, headers, email="a2@example.com")
    # Tokens are not returned by the API (emailed instead); read from storage.
    token_a, token_b = _token(db, first["id"]), _token(db, second["id"])
    assert len(token_a) >= 43
    assert token_a != token_b
    from models.organization import Invitation

    row = db.query(Invitation).filter(
        Invitation.id == first["id"]).one()
    # Stored plaintext (documented behavior, not a hash).
    assert row.token == token_a
    assert (row.expires_at - row.created_at) > timedelta(days=6)


def test_invite_accept_happy_path_and_role(client, db):
    headers = _register(client, "invowner2", "Inv Owner2 Org")
    invitation = _invite(client, headers, email="newbie@example.com",
                         role="analyst")
    accept = client.post(
        f"/api/v1/organizations/invitations/{_token(db, invitation['id'])}/accept",
        json={"username": "newbie", "password": "password123"})
    assert accept.status_code == 200, accept.text
    from models.organization import Invitation
    from models.user import User

    row = db.query(Invitation).filter(
        Invitation.id == invitation["id"]).one()
    assert row.status == "accepted"
    user = db.query(User).filter(User.username == "newbie").one()
    assert user.role == "analyst"
    assert user.organization_id == row.organization_id
    # The new user can log in.
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "newbie", "password": "password123"})
    assert login.status_code == 200


def test_accept_twice_rejected_and_revoked_rejected(client, db):
    headers = _register(client, "invowner3", "Inv Owner3 Org")
    invitation = _invite(client, headers, email="twice@example.com")
    first = client.post(
        f"/api/v1/organizations/invitations/{_token(db, invitation['id'])}/accept",
        json={"username": "twice", "password": "password123"})
    assert first.status_code == 200, first.text
    # Single-use: second accept finds no PENDING row.
    second = client.post(
        f"/api/v1/organizations/invitations/{_token(db, invitation['id'])}/accept",
        json={"username": "twice2", "password": "password123"})
    assert second.status_code == 404
    assert second.json()["error"]["code"] == "invitation_invalid"

    other = _invite(client, headers, email="revoked@example.com")
    revoke = client.post(
        f"/api/v1/organizations/invitations/{other['id']}/revoke",
        headers=headers)
    assert revoke.status_code in (200, 204), revoke.text
    gone = client.post(
        f"/api/v1/organizations/invitations/{_token(db, other['id'])}/accept",
        json={"username": "revoked", "password": "password123"})
    assert gone.status_code == 404


def test_expired_invitation_marked_and_rejected(client, db):
    from models.organization import Invitation

    headers = _register(client, "invowner4", "Inv Owner4 Org")
    invitation = _invite(client, headers, email="old@example.com")
    row = db.query(Invitation).filter(
        Invitation.id == invitation["id"]).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    response = client.post(
        f"/api/v1/organizations/invitations/{_token(db, invitation['id'])}/accept",
        json={"username": "old", "password": "password123"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invitation_expired"
    db.expire_all()
    assert db.query(Invitation).filter(
        Invitation.id == invitation["id"]).one().status == "expired"


def test_accept_checks_nothing_about_caller(client, db):
    """Documented: whoever holds the token gets the account.

    Accept is unauthenticated and binds only the token; there is no email
    ownership proof. The created account always uses the invited email.
    """
    headers = _register(client, "invowner5", "Inv Owner5 Org")
    invitation = _invite(client, headers, email="victim@example.com")
    # A stranger (and even garbage auth) can consume the token.
    accept = client.post(
        f"/api/v1/organizations/invitations/{_token(db, invitation['id'])}/accept",
        json={"username": "stranger", "password": "password123"},
        headers={"Authorization": "Bearer garbage"})
    assert accept.status_code == 200, accept.text


def test_create_organization_moves_caller_as_admin(client, db):
    """POST /organizations requires ORG_MANAGE and moves the caller.

    The caller leaves their old org and becomes admin of the new one;
    duplicate names 409. Viewer/analyst get 403.
    """
    from models.organization import Organization
    from models.user import User

    headers = _register(client, "orgmaker", "Orgmaker Org")
    created = client.post("/api/v1/organizations", json={"name": "Second Org"},
                          headers=headers)
    assert created.status_code == 201, created.text
    assert created.json()["name"] == "Second Org"
    db.expire_all()
    user = db.query(User).filter(User.username == "orgmaker").one()
    new_org = db.query(Organization).filter(
        Organization.name == "Second Org").one()
    assert user.organization_id == new_org.id
    assert user.role == "admin"
    # Old org still exists but the caller is gone from it.
    assert db.query(Organization).filter(
        Organization.name == "Orgmaker Org").one() is not None
    # Duplicate name.
    again = client.post("/api/v1/organizations", json={"name": "Second Org"},
                        headers=headers)
    assert again.status_code == 409
    # Non-admin cannot create organizations.
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": "orgviewer", "email": "orgviewer@example.com",
              "password": "password123", "organization": "Viewer Org"})
    viewer = db.query(User).filter(User.username == "orgviewer").one()
    viewer.role = "viewer"
    db.commit()
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "orgviewer", "password": "password123"})
    viewer_h = {"Authorization": f"Bearer {login.json()['access_token']}"}
    denied = client.post("/api/v1/organizations", json={"name": "Nope Org"},
                         headers=viewer_h)
    assert denied.status_code == 403
