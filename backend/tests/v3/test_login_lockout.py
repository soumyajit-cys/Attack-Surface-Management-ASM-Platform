"""1.5.3 login protection: lockout characterization (tests only, red first).

Per-account + per-IP counters, sliding window, exponential backoff with cap;
normalized hashed keys; identical 401s for unknown/wrong/locked; dummy bcrypt
timing shape; Redis-down fail-closed; reusable counter helper. Imports are
function-level; behavior cases are strict-xfailed until implementation lands.
"""

import pytest


def _register(client, username, org="Lock Org"):
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": f"{username}@example.com",
              "password": "password123", "organization": org},
    )
    assert reg.status_code == 201, reg.text
    return reg.json()


def _login(client, username, password):
    return client.post("/api/v1/auth/login",
                       json={"username": username, "password": password})


def _lockout():
    from auth import lockout

    return lockout


def test_account_locks_after_threshold(client, db):
    _register(client, "lockme")
    for _ in range(5):
        assert _login(client, "lockme", "wrong").status_code == 401
    locked = _login(client, "lockme", "wrong")
    assert locked.status_code == 401
    from models.audit_log import AuditLog

    event = db.query(AuditLog).filter(
        AuditLog.action == "auth.account_locked").order_by(
            AuditLog.id.desc()).first()
    assert event is not None


def test_locked_rejects_correct_password(client):
    _register(client, "lockcorrect")
    for _ in range(5):
        _login(client, "lockcorrect", "wrong")
    response = _login(client, "lockcorrect", "password123")
    assert response.status_code == 401


def test_locked_unknown_wrong_identical(client):
    _register(client, "lockshape")
    for _ in range(5):
        _login(client, "lockshape", "wrong")
    locked = _login(client, "lockshape", "password123")
    unknown = _login(client, "nosuchuser", "wrong")
    wrong = _login(client, "lockshape", "wrong")
    for response in (locked, unknown, wrong):
        assert response.status_code == 401
    assert locked.json() == unknown.json() == wrong.json()
    assert locked.headers.get("content-type") == unknown.headers.get(
        "content-type") == wrong.headers.get("content-type")


def test_dummy_bcrypt_timing_shape(client, monkeypatch):
    from auth import security
    import app.api.v1.auth as auth_api

    calls = []
    real_verify = security.verify_password

    def counting(password, hashed):
        calls.append(password)
        return real_verify(password, hashed)

    monkeypatch.setattr(auth_api, "verify_password", counting)
    _register(client, "lockcount")
    _login(client, "nosuchuser", "wrong")
    # Unknown users burn the dummy constant, never the submitted password.
    from auth.security import DUMMY_PASSWORD_PREIMAGE

    assert calls == [DUMMY_PASSWORD_PREIMAGE]
    for _ in range(5):
        _login(client, "lockcount", "wrong")
    before = len(calls)
    _login(client, "lockcount", "password123")
    assert len(calls) == before + 1  # locked path still burns one bcrypt


def test_success_resets_account_counter(client, db):
    """A success clears consecutive account failures.

    4 fails + success + 4 fails: the account counter restarts, so no
    ACCOUNT-scoped lockout fires. The shared test-client IP still trips the
    independent IP counter (proving the two scopes are separate).
    """
    import json

    _register(client, "lockreset")
    for _ in range(4):
        _login(client, "lockreset", "wrong")
    assert _login(client, "lockreset", "password123").status_code == 200
    from models.audit_log import AuditLog

    for _ in range(4):
        assert _login(client, "lockreset", "wrong").status_code == 401
    events = db.query(AuditLog).filter(
        AuditLog.action == "auth.account_locked").all()
    assert events, "expected the IP scope to engage independently"
    for event in events:
        assert json.loads(event.details)["scope"] == "ip"


def test_exponential_backoff_capped():
    counter = _lockout().AttemptCounter(
        "test", max_attempts=2, window_s=60, base_s=10, cap_s=25,
        client=None)
    assert counter._backoff_seconds(1) == 10
    assert counter._backoff_seconds(2) == 20
    assert counter._backoff_seconds(3) == 25
    assert counter._backoff_seconds(10) == 25


def test_keys_hashed_and_normalized():
    counter = _lockout().AttemptCounter(
        "test", max_attempts=5, window_s=60, base_s=60, cap_s=900,
        client=None)
    key = counter._key("  Alice@Example.com ")
    assert "alice" not in key and "Alice" not in key
    assert counter._key("alice@example.com") == key


def test_redis_down_returns_uniform_503(client, db, monkeypatch):
    from utils import redis_client

    _register(client, "lockdown")

    def dead():
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_client, "get_redis", dead)
    first = _login(client, "lockdown", "password123")
    second = _login(client, "nosuchuser", "wrong")
    assert first.status_code == 503
    assert first.json() == second.json()
    assert first.json()["error"]["code"] == "auth_unavailable"


def _unlock(client, headers, username):
    return client.post("/api/v1/auth/admin/unlock-account",
                       json={"username": username}, headers=headers)


def test_admin_unlock_releases_lock(client, db):
    from models.audit_log import AuditLog

    admin_h = _register(client, "lockadmin", org="Lock Admin Org")
    admin_headers = {"Authorization": f"Bearer {admin_h['access_token']}"}
    _register(client, "lockvictim", org="Lock Victim Tmp Org")
    # Same tenant: move the victim into the admin's org.
    from models.user import User

    admin_org = db.query(User).filter(
        User.username == "lockadmin").one().organization_id
    db.query(User).filter(
        User.username == "lockvictim").one().organization_id = admin_org
    db.commit()
    for _ in range(5):
        _login(client, "lockvictim", "wrong")
    assert _login(client, "lockvictim", "password123").status_code == 401
    unlocked = _unlock(client, admin_headers, "lockvictim")
    assert unlocked.status_code == 200, unlocked.text
    assert _login(client, "lockvictim", "password123").status_code == 200
    event = db.query(AuditLog).filter(
        AuditLog.action == "auth.account_unlocked").order_by(
            AuditLog.id.desc()).first()
    assert event is not None
    assert "lockvictim" in (event.details or "")


def test_unlock_forbidden_for_non_admins(client, db):
    from models.user import User

    _register(client, "lockadmin2")
    for username, role in (("lockanalyst", "analyst"),
                           ("lockviewer", "viewer")):
        _register(client, username, org=f"Lock {username} Org")
        db.query(User).filter(User.username == username).one().role = role
        db.commit()
    for username in ("lockanalyst", "lockviewer"):
        login = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "password123"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        # They lack ORG_MANAGE anywhere, so any target 403s.
        assert _unlock(client, headers, "lockadmin2").status_code == 403


def test_unlock_cross_org_matches_unknown(client, db):
    admin_h = _register(client, "lockadmin3", org="Lock Admin3 Org")
    admin_headers = {"Authorization": f"Bearer {admin_h['access_token']}"}
    _register(client, "lockother", org="Lock Other Org")
    cross = _unlock(client, admin_headers, "lockother")
    missing = _unlock(client, admin_headers, "nosuchuser")
    assert cross.status_code == missing.status_code == 404
    assert cross.json() == missing.json()
