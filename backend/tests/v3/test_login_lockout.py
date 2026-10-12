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


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
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


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
def test_locked_rejects_correct_password(client):
    _register(client, "lockcorrect")
    for _ in range(5):
        _login(client, "lockcorrect", "wrong")
    response = _login(client, "lockcorrect", "password123")
    assert response.status_code == 401


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
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


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
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
    assert calls == ["wrong"]
    for _ in range(5):
        _login(client, "lockcount", "wrong")
    before = len(calls)
    _login(client, "lockcount", "password123")
    assert len(calls) == before + 1  # locked path still burns one bcrypt


def test_success_resets_account_counter(client, db):
    """A success clears consecutive failures: 4+success+4 never locks."""
    _register(client, "lockreset")
    for _ in range(4):
        _login(client, "lockreset", "wrong")
    assert _login(client, "lockreset", "password123").status_code == 200
    from models.audit_log import AuditLog

    for _ in range(4):
        assert _login(client, "lockreset", "wrong").status_code == 401
    assert db.query(AuditLog).filter(
        AuditLog.action == "auth.account_locked").count() == 0


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
def test_exponential_backoff_capped():
    counter = _lockout().AttemptCounter(
        "test", max_attempts=2, window_s=60, base_s=10, cap_s=25,
        client=None)
    assert counter._backoff_seconds(1) == 10
    assert counter._backoff_seconds(2) == 20
    assert counter._backoff_seconds(3) == 25
    assert counter._backoff_seconds(10) == 25


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
def test_keys_hashed_and_normalized():
    counter = _lockout().AttemptCounter(
        "test", max_attempts=5, window_s=60, base_s=60, cap_s=900,
        client=None)
    key = counter._key("  Alice@Example.com ")
    assert "alice" not in key and "Alice" not in key
    assert counter._key("alice@example.com") == key


@pytest.mark.xfail(strict=True, reason="BUG-LOCK-001: lockout not implemented")
def test_redis_down_fails_closed(client, db, monkeypatch):
    from utils import redis_client

    _register(client, "lockdown")

    def dead():
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_client, "get_redis", dead)
    first = _login(client, "lockdown", "password123")
    second = _login(client, "nosuchuser", "wrong")
    assert first.status_code == 401
    assert first.json() == second.json()
