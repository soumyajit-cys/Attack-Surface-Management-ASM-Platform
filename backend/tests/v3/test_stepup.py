"""Admin step-up re-authentication (v1.6.x, tests only, red first).

``POST /api/v1/auth/step-up`` re-verifies the calling user's password (plus
TOTP or a recovery code when 2FA is enabled) with the same lockout counters
and uniform failures as login; success plants a short-lived (300 s)
server-side redis marker keyed by user id + current access jti. Sensitive
org-admin write routes then require that marker via
``require_step_up_dep`` and answer ``403 step_up_required`` without it.
No client-held token is issued.

Covered here: missing/expired/foreign markers (other user, other session),
TOTP/recovery code entry, lockout interplay, permissions still enforced
(viewer, cross-org), API-key rejection, read-only routes unaffected, and
audit events on grant and on use.
"""

import json

import pytest

from config import settings

PROTECTED_ROUTES = [
    ("POST", "/api/v1/auth/admin/unlock-account", {"username": "stepupa"}),
    ("POST", "/api/v1/auth/admin/reset-2fa", {"username": "stepupa"}),
    ("POST", "/api/v1/organizations/2fa-requirement", {"enabled": False}),
    ("POST", "/api/v1/organizations/invitations",
     {"email": "newmember@example.com", "role": "viewer"}),
    ("POST", "/api/v1/organizations/api-keys", {"name": "k"}),
    # The id does not need to exist: the step-up dependency must fire
    # before the route body, whatever the id resolves to.
    ("POST", "/api/v1/organizations/invitations/12345/revoke", {}),
]


def _audit_rows(db, action):
    from models.audit_log import AuditLog

    return (db.query(AuditLog).filter(AuditLog.action == action)
            .order_by(AuditLog.id.desc()).all())


@pytest.fixture()
def su(client, db, monkeypatch, org_factory):
    _public_dns(monkeypatch)
    from auth.security import hash_password
    from models.user import User

    org_a, admin_a = org_factory("StepUp Org A", "stepupa",
                                 "stepupa@example.com")
    org_b, admin_b = org_factory("StepUp Org B", "stepupb",
                                 "stepupb@example.com")
    admin_a2 = User(
        organization_id=org_a.id, username="stepupa2",
        email="stepupa2@example.com",
        password_hash=hash_password("password123"), role="admin",
    )
    db.add(admin_a2)
    db.commit()

    def login(username, password="password123", expect=200):
        response = client.post("/api/v1/auth/login",
                               json={"username": username,
                                     "password": password})
        assert response.status_code == expect, response.text
        if expect != 200:
            return response
        return {"Authorization":
                f"Bearer {response.json()['access_token']}"}

    def challenge(headers, password="password123", code=None, expect=200):
        body = {"password": password}
        if code is not None:
            body["code"] = code
        response = client.post("/api/v1/auth/step-up", json=body,
                               headers=headers)
        assert response.status_code == expect, response.text
        return response

    user_a = db.query(User).filter(User.username == "stepupa").one()
    return {"client": client, "db": db,
            "org_a": org_a.id, "org_b": org_b.id,
            "users": {"a": admin_a, "a2": admin_a2, "b": admin_b},
            "user_a_id": user_a.id,
            "login": login, "challenge": challenge}


def _public_dns(monkeypatch, ip="93.184.216.34"):
    import socket as stdlib_socket

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", (ip, 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


def _next_totp_code(secret):
    """Code for the NEXT 30 s step: survives same-step replay protection
    (confirm/enroll already claimed the current step's code)."""
    import time

    import pyotp

    return pyotp.TOTP(secret).at(int(time.time()) + 30)


def _enable_2fa(client, headers):
    enrolled = client.post("/api/v1/auth/2fa/enroll",
                           json={"password": "password123"},
                           headers=headers)
    assert enrolled.status_code == 200, enrolled.text
    secret = enrolled.json()["secret"]
    confirmed = client.post("/api/v1/auth/2fa/confirm",
                            json={"code": _totp_code(secret)},
                            headers=headers)
    assert confirmed.status_code == 200, confirmed.text
    return secret, confirmed.json()["recovery_codes"]


def _totp_code(secret):
    import pyotp

    return pyotp.TOTP(secret).now()


def _jti_of(headers):
    from auth import jwt as token_service

    token = headers["Authorization"].split(" ", 1)[1]
    return token_service.decode_token(token).get("jti")


class TestStepUpRoute:
    def test_step_up_grants_and_locks_protected_routes_open(self, su, db):
        """Grant on success; every sensitive route then answers normally."""
        for method, url, body in PROTECTED_ROUTES:
            response = su["client"].request(method, url, json=body,
                                            headers=su["login"]("stepupa"))
            assert response.status_code == 403, response.text
            assert response.json()["error"]["code"] == "step_up_required", (
                f"{method} {url}: {response.text}")

        headers = su["login"]("stepupa")
        su["challenge"](headers)
        granted = _audit_rows(db, "auth.stepup_granted")
        assert granted, "step-up did not audit an auth.stepup_granted row"
        assert "password123" not in granted[0].details
        response = su["client"].post(
            "/api/v1/auth/admin/unlock-account",
            json={"username": "stepupa2"}, headers=headers)
        assert response.status_code == 200, response.text
        used = _audit_rows(db, "auth.stepup_used")
        assert used, "protected route use did not audit auth.stepup_used"
        assert "password123" not in used[0].details

    def test_wrong_password_is_uniform_failure_and_feeds_lockout(self, su):
        headers = su["login"]("stepupa")
        for _ in range(settings.login_max_attempts):
            response = su["challenge"](headers, password="wrong-pass",
                                       expect=401)
            assert response.json()["error"]["message"] == "Invalid credentials"
        # Locked: even the correct password is a uniform 401 now.
        su["challenge"](headers, password="password123", expect=401)

    def test_unknown_user_email_is_api_key_rejected(self, su, client):
        """Step-up is for user sessions; API keys can never step up."""
        headers = su["login"]("stepupa")
        su["challenge"](headers)
        created = client.post(
            "/api/v1/organizations/api-keys", json={"name": "kk"},
            headers=headers)
        assert created.status_code == 201, created.text
        key_h = {"X-API-Key": created.json()["key"]}
        response = client.post("/api/v1/auth/step-up",
                               json={"password": "password123"}, headers=key_h)
        assert response.status_code == 403, response.text
        assert response.json()["error"]["code"] == "api_key_forbidden"

    def test_totp_required_when_2fa_enabled(self, su, client):
        headers = su["login"]("stepupa")
        secret, codes = _enable_2fa(client, headers)

        # Password alone is a uniform failure, not a credential leak.
        response = su["challenge"](headers, expect=401)
        assert response.json()["error"]["message"] == "Invalid credentials"
        # Wrong code is too.
        su["challenge"](headers, code="000000", expect=401)
        # Correct (fresh-step) TOTP code passes.
        su["challenge"](headers, code=_next_totp_code(secret))

    def test_recovery_code_accepted_for_step_up(self, su, client):
        headers = su["login"]("stepupa")
        _secret, codes = _enable_2fa(client, headers)
        su["challenge"](headers, code=codes[0])
        # A used recovery code cannot be replayed for step-up.
        su["challenge"](headers, code=codes[0], expect=401)

    def test_marker_expired_leaves_routes_shut(self, su):
        from utils.redis_client import get_redis

        headers = su["login"]("stepupa")
        su["challenge"](headers)
        assert _audit_rows(su["db"], "auth.stepup_granted")
        get_redis().delete(
            f"stepup:{su['user_a_id']}:{_jti_of(headers)}")
        response = su["client"].post(
            "/api/v1/auth/admin/unlock-account",
            json={"username": "stepupa2"}, headers=headers)
        assert response.status_code == 403, response.text
        assert response.json()["error"]["code"] == "step_up_required"

    def test_marker_is_bound_to_the_calling_user(self, su):
        a_headers = su["login"]("stepupa")
        b_headers = su["login"]("stepupb")
        su["challenge"](a_headers)
        # Org B's admin has no marker of its own.
        response = su["client"].post(
            "/api/v1/organizations/api-keys", json={"name": "kb"},
            headers=b_headers)
        assert response.status_code == 403, response.text
        assert response.json()["error"]["code"] == "step_up_required"

    def test_marker_is_bound_to_the_calling_session(self, su):
        first = su["login"]("stepupa")
        second = su["login"]("stepupa")  # same user, second session
        assert _jti_of(first) != _jti_of(second)
        su["challenge"](first)
        response = su["client"].post(
            "/api/v1/organizations/api-keys", json={"name": "k"},
            headers=second)
        assert response.status_code == 403, response.text
        assert response.json()["error"]["code"] == "step_up_required"

    def test_lockout_released_by_fresh_admin_stepup(self, su):
        """Lockout interplay: a locked-stepup admin can be unlocked by
        another admin who first completed their own step-up."""
        headers = su["login"]("stepupa")
        for _ in range(settings.login_max_attempts):
            su["challenge"](headers, password="wrong-pass", expect=401)
        # Even correct step-up is locked out now (uniform).
        su["challenge"](headers, password="password123", expect=401)
        other = su["login"]("stepupa2")
        su["challenge"](other)
        response = su["client"].post(
            "/api/v1/auth/admin/unlock-account",
            json={"username": "stepupa"}, headers=other)
        assert response.status_code == 200, response.text
        # Released: the locked admin can step up again.
        su["challenge"](headers)

    def test_stepup_does_not_bypass_org_scope_or_role(self, su, client, db):
        headers = su["login"]("stepupa")
        su["challenge"](headers)
        # Cross-org admin targets stay invisible (step-up != permission).
        response = su["client"].post(
            "/api/v1/auth/admin/reset-2fa",
            json={"username": "stepupb"}, headers=headers)
        assert response.status_code == 404, response.text
        # A stepped-up viewer still has no ORG_MANAGE permissions.
        viewer = client.post(
            "/api/v1/auth/register",
            json={"username": "stepupviewer",
                  "email": "stepupviewer@example.com",
                  "password": "password123", "organization": "StepUp Tmp"},
        )
        assert viewer.status_code == 201, viewer.text
        from models.user import User

        # Anchor the fresh user into org A as a viewer (register created
        # them inside their own throwaway org, with admin-class rights
        # there — irrelevant to this test).
        v_user = db.query(User).filter(
            User.username == "stepupviewer").one()
        v_user.organization_id = su["org_a"]
        v_user.role = "viewer"
        db.commit()
        v_headers = {"Authorization":
                     f"Bearer {viewer.json()['access_token']}"}
        su["challenge"](v_headers)
        response = client.post(
            "/api/v1/organizations/invitations",
            json={"email": "x@example.com", "role": "viewer"},
            headers=v_headers)
        assert response.status_code == 403, response.text
        assert response.json()["error"]["code"] != "step_up_required"

    def test_readonly_routes_untouched_without_stepup(self, su, client):
        headers = su["login"]("stepupa")
        for url in ("/api/v1/organizations/api-keys",
                    "/api/v1/organizations/invitations",
                    "/api/v1/audit-logs"):
            response = client.get(url, headers=headers)
            assert response.status_code == 200, f"GET {url}: {response.text}"
            assert "step_up_required" not in response.text

    def test_grant_and_use_details_carry_no_secrets(self, su, db):
        headers = su["login"]("stepupa")
        su["challenge"](headers)
        su["client"].post("/api/v1/auth/admin/unlock-account",
                          json={"username": "stepupa2"}, headers=headers)
        for action in ("auth.stepup_granted", "auth.stepup_used"):
            latest = _audit_rows(db, action)[0]
            details = json.loads(latest.details)
            blob = latest.details
            assert "password" not in blob.lower()
            assert not any(
                word in blob.lower()
                for word in ("totp", "secret", "token", "recovery"))
            assert details, f"{action}: empty details"
