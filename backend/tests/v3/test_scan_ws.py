"""Live scan progress over WebSocket (Phase 1.1).

``GET /api/v1/scans/{id}/ws`` streams the same Redis Stream
``scan:{id}:events`` as the SSE endpoint, framed as SSE text blocks over a
WebSocket text channel.

Auth:
- ``Authorization: Bearer <jwt>`` header (primary, non-browser clients).
- ``?ticket=`` query parameter (browser fallback): a single-use, short-lived
  ticket obtained from ``POST /api/v1/scans/{id}/ws-ticket``.  The raw JWT is
  never sent in a query string.

A ticket is scoped to user + scan + org, stored in Redis with TTL
``ws_ticket_ttl_seconds`` (default 30 s), and deleted on first use.

An ``Origin`` allowlist (from ``CORS_ORIGINS`` + ``FRONTEND_URL``) protects
against cross-site WebSocket hijacking; missing or foreign origins are refused.

The presenting bearer token is re-validated periodically while the socket is
open, so revocation or deactivation mid-stream closes the connection.

TestClient buffers nothing for a connected socket, so frames are read with
``receive_text()`` directly.  A server-initiated close surfaces as
``WebSocketDisconnect`` carrying the close code.
"""

import json
import time
from types import SimpleNamespace

import pytest
from starlette.websockets import WebSocketDisconnect

from app.api.v1.scans import _WS_TICKET_PREFIX
from services.scan_events import publish_scan_event


# An origin present in the default CORS_ORIGINS / FRONTEND_URL, used for the
# allowed-Origin cases.  Foreign-origin tests use a different origin.
_ALLOWED_ORIGIN = "http://localhost:5173"
_FOREIGN_ORIGIN = "http://evil.example.com"


@pytest.fixture(autouse=True)
def _ws_limits_testable(monkeypatch):
    from config import settings

    monkeypatch.setattr(
        settings, "scan_stream_max_duration_seconds", 1.0, raising=False)
    monkeypatch.setattr(
        settings, "scan_stream_heartbeat_seconds", 0.2, raising=False)
    yield


@pytest.fixture()
def env(client, db, org_factory, auth_headers):
    org, user = org_factory("WS Org", "wsadmin", "wsadmin@example.com")
    db.expire_all()
    scan = _make_scan(db, org.id, status="running")
    scan_completed = _make_scan(db, org.id, status="completed")
    return SimpleNamespace(
        client=client, db=db, org=org, user=user,
        headers=auth_headers("wsadmin"),
        scan=scan, scan_completed=scan_completed,
    )


def _make_scan(db, org_id, status="running", target="wsevents.example.com"):
    from models.scan_history import ScanHistory

    scan = ScanHistory(
        organization_id=org_id, target=target, status=status, scope="passive",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _url(scan_id):
    return f"/api/v1/scans/{scan_id}/ws"


def _ticket_url(scan_id):
    return f"/api/v1/scans/{scan_id}/ws-ticket"


def _parse_ws_block(block: str) -> dict:
    parsed = {"id": None, "event": None, "data": None}
    for line in block.splitlines():
        if line.startswith(":"):
            continue  # comment / heartbeat
        if not line:
            continue
        if line.startswith("id:"):
            parsed["id"] = line[3:].strip()
        elif line.startswith("event:"):
            parsed["event"] = line[6:].strip()
        elif line.startswith("data:"):
            payload = line[5:].strip()
            parsed["data"] = json.loads(payload) if payload else None
    return parsed


def _publish_sequence(scan_id, items):
    for item in items:
        publish_scan_event(
            scan_id,
            item["kind"],
            phase=item.get("phase"),
            counts=item.get("counts"),
            code=item.get("code"),
        )


def _connect(client, scan_id, *, headers=None, query_params=None, origin=None):
    h = dict(headers or {})
    if origin is not None:
        h["origin"] = origin
    url = _url(scan_id)
    if query_params:
        qs = "&".join(f"{k}={v}" for k, v in query_params.items())
        url = f"{url}?{qs}"
    return client.websocket_connect(url, headers=h)


def _issue_ticket(client, scan_id, headers):
    response = client.post(_ticket_url(scan_id), headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["ticket"]


# ── auth ─────────────────────────────────────────────────────────────────────


def test_ws_requires_auth(env):
    try:
        with _connect(env.client, env.scan.id, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected the server to refuse an unauthenticated socket")


def test_ws_rejects_bad_token(env):
    try:
        with _connect(
            env.client, env.scan.id,
            headers={"Authorization": "Bearer not-a-real-token"},
            origin=_ALLOWED_ORIGIN,
        ) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected a bad token to be refused")


def test_ws_header_token_connects(env):
    _publish_sequence(env.scan_completed.id, [{"kind": "completed"}])
    with _connect(
        env.client, env.scan_completed.id,
        headers=env.headers,
        origin=_ALLOWED_ORIGIN,
    ) as ws:
        frames = []
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            frames.append(_parse_ws_block(block))
            if frames[-1]["event"] in ("completed",):
                break
    assert any(f["event"] == "snapshot" for f in frames), frames
    assert any(f["event"] == "completed" for f in frames), frames


def test_ws_ticket_connects(env):
    _publish_sequence(env.scan_completed.id, [{"kind": "completed"}])
    ticket = _issue_ticket(env.client, env.scan_completed.id, env.headers)
    with _connect(
        env.client, env.scan_completed.id,
        query_params={"ticket": ticket},
        origin=_ALLOWED_ORIGIN,
    ) as ws:
        frames = []
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            frames.append(_parse_ws_block(block))
            if frames[-1]["event"] in ("completed",):
                break
    assert any(f["event"] == "snapshot" for f in frames), frames


def test_ws_ticket_is_single_use(env):
    """A ticket may be used for exactly one connection."""
    ticket = _issue_ticket(env.client, env.scan_completed.id, env.headers)
    # First use succeeds.
    with _connect(
        env.client, env.scan_completed.id,
        query_params={"ticket": ticket},
        origin=_ALLOWED_ORIGIN,
    ) as ws:
        ws.receive_text()  # snapshot
    # Second use is refused (ticket consumed).
    try:
        with _connect(
            env.client, env.scan_completed.id,
            query_params={"ticket": ticket},
            origin=_ALLOWED_ORIGIN,
        ) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected a consumed ticket to be refused")


def test_ws_ticket_consumption_is_atomic(env):
    """GETDEL makes ticket consumption atomic: two concurrent consumers of
    the same ticket key cannot both obtain its value."""
    from utils.redis_client import get_redis

    r = get_redis()
    key = f"{_WS_TICKET_PREFIX}concurrent-test-ticket"
    r.set(key, json.dumps({"user_id": env.user.id, "scan_id": 1, "organization_id": env.org.id}), ex=30)

    results = []

    def consume():
        raw = r.getdel(key)
        results.append(raw is not None)

    import threading

    t1 = threading.Thread(target=consume)
    t2 = threading.Thread(target=consume)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results.count(True) == 1, results
    assert results.count(False) == 1, results


def test_ws_revoked_token_refused(env, db):
    from auth import jwt as token_service
    from auth.token_store import token_store

    token = token_service.create_access_token(env.user.id)
    headers = {"Authorization": f"Bearer {token}"}
    with _connect(env.client, env.scan_completed.id, headers=headers, origin=_ALLOWED_ORIGIN) as ws:
        ws.receive_text()  # snapshot succeeds while token valid
    token_store.revoke(token)
    try:
        with _connect(env.client, env.scan_completed.id, headers=headers, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected a revoked token to be refused")


def test_ws_deactivated_user_refused(env, db):
    from auth import jwt as token_service

    token = token_service.create_access_token(env.user.id)
    headers = {"Authorization": f"Bearer {token}"}
    with _connect(env.client, env.scan_completed.id, headers=headers, origin=_ALLOWED_ORIGIN) as ws:
        ws.receive_text()

    env.user.is_active = False
    db.commit()
    try:
        with _connect(env.client, env.scan_completed.id, headers=headers, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected a deactivated user to be refused")


# ── tenant isolation ─────────────────────────────────────────────────────────


@pytest.fixture()
def other_org_scan(db, org_factory):
    org_b, _user_b = org_factory("WS Other", "wsother", "wsother@example.com")
    db.expire_all()
    return _make_scan(db, org_b.id, status="running", target="other.example.com")


def test_ws_cross_org_scan_refused(env, other_org_scan):
    """A user must not open a stream on another org's scan."""
    try:
        with _connect(env.client, other_org_scan.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4004, exc.code
        return
    raise AssertionError("expected cross-org scan to be refused")


def test_ws_unknown_scan_refused(env):
    try:
        with _connect(env.client, 999999, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4004, exc.code
        return
    raise AssertionError("expected an unknown scan to be refused")


# ── Origin allowlist ─────────────────────────────────────────────────────────


def test_ws_allowed_origin_connects(env):
    _publish_sequence(env.scan_completed.id, [{"kind": "completed"}])
    with _connect(
        env.client, env.scan_completed.id,
        headers=env.headers,
        origin=_ALLOWED_ORIGIN,
    ) as ws:
        frames = []
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            frames.append(_parse_ws_block(block))
            if frames[-1]["event"] in ("completed",):
                break
    assert any(f["event"] == "snapshot" for f in frames), frames


def test_ws_missing_origin_refused(env):
    try:
        with _connect(env.client, env.scan_completed.id, headers=env.headers) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4003, exc.code
        return
    raise AssertionError("expected a missing Origin to be refused")


def test_ws_foreign_origin_refused(env):
    try:
        with _connect(env.client, env.scan_completed.id, headers=env.headers, origin=_FOREIGN_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4003, exc.code
        return
    raise AssertionError("expected a foreign Origin to be refused")


def test_ws_wildcard_origin_refused(env, monkeypatch):
    """A wildcard origin (``*``) is never accepted for WebSocket upgrades,
    even if listed in CORS_ORIGINS."""
    import app.api.v1.scans as scans_api
    from config import settings

    monkeypatch.setattr(
        settings, "cors_origins", ["*", _ALLOWED_ORIGIN], raising=False)

    try:
        with _connect(env.client, env.scan_completed.id, headers=env.headers, origin="*") as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4003, exc.code
        return
    raise AssertionError("expected a wildcard Origin to be refused")


# ── reading behavior ─────────────────────────────────────────────────────────


def test_ws_snapshot_on_connect_and_ordered_replay(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "phase_started", "phase": "discovery"},
    ])
    with _connect(env.client, env.scan.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
        frames = []
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            frames.append(_parse_ws_block(block))
            if len(frames) >= 4:
                break
    assert frames[0]["event"] == "snapshot"
    assert frames[0]["data"]["status"] == "running"
    stream_events = [f for f in frames if f["event"] != "snapshot"]
    assert [f["event"] for f in stream_events] == [
        "queued", "running", "phase_started"]
    assert stream_events[2]["data"]["phase"] == "discovery"


def test_ws_resume_from_last_event_id_without_duplicates(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "phase_started", "phase": "discovery"},
    ])
    with _connect(env.client, env.scan.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
        frames = []
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            frames.append(_parse_ws_block(block))
            if len(frames) >= 4:
                break
    ids = [f["id"] for f in frames if f.get("id")]
    assert len(ids) == 3
    resumed = []
    with _connect(
        env.client, env.scan.id,
        headers=env.headers,
        origin=_ALLOWED_ORIGIN,
        query_params={"lastEventId": ids[1]},
    ) as ws:
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            resumed.append(_parse_ws_block(block))
            if len(resumed) >= 2:
                break
    resumed_events = [f for f in resumed if f.get("id")]
    assert [f["id"] for f in resumed_events] == ids[2:]
    assert all(f["id"] != ids[1] for f in resumed_events)


def test_ws_terminal_event_closes_socket(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "completed", "counts": {"findings": 3}},
    ])
    with _connect(env.client, env.scan.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
        frames = []
        while True:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            frames.append(_parse_ws_block(block))
            if frames[-1]["event"] == "completed":
                break
    assert frames[-1]["event"] == "completed"
    assert frames[-1]["data"]["counts"] == {"findings": 3}


def test_ws_heartbeat_sent(env, monkeypatch):
    import config

    monkeypatch.setattr(config.settings, "scan_stream_heartbeat_seconds", 0.2, raising=False)
    monkeypatch.setattr(config.settings, "scan_stream_max_duration_seconds", 2.0, raising=False)
    # A non-terminal scan keeps the socket open and sends heartbeats until the
    # max duration elapses.  We only need to observe one heartbeat comment,
    # then we stop reading (we never read after the server closes).
    with _connect(env.client, env.scan.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
        saw_heartbeat = False
        for _ in range(60):  # bounded; server sends a heartbeat every 0.2 s
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            if ": heartbeat" in block:
                saw_heartbeat = True
                break
    assert saw_heartbeat, "no heartbeat comment was sent over the socket"


# ── stream cap ───────────────────────────────────────────────────────────────


def test_ws_cap_429_and_slot_freed(env, monkeypatch):
    from config import settings
    from utils.redis_client import get_redis

    monkeypatch.setattr(settings, "scan_stream_max_per_user", 1, raising=False)
    cap_key = f"scan_streams:{env.user.id}"
    seeded = get_redis()
    seeded.zadd(cap_key, {"existing-session": time.time() + 3600})

    try:
        with _connect(env.client, env.scan_completed.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4003, exc.code
    assert seeded.zcard(cap_key) == 1  # refused attempt left nothing behind


def test_ws_disconnect_frees_cap_slot(env, monkeypatch):
    from config import settings
    from utils.redis_client import get_redis

    monkeypatch.setattr(settings, "scan_stream_max_per_user", 2, raising=False)
    monkeypatch.setattr(settings, "scan_stream_max_duration_seconds", 30.0, raising=False)
    cap_key = f"scan_streams:{env.user.id}"
    seeded = get_redis()
    seeded.zadd(cap_key, {"other-session": time.time() + 3600})

    with _connect(env.client, env.scan_completed.id, headers=env.headers, origin=_ALLOWED_ORIGIN) as ws:
        ws.receive_text()  # snapshot; slot now held

    slot = seeded.zcard(cap_key)
    deadline = time.monotonic() + 5
    while slot != 1 and time.monotonic() < deadline:
        time.sleep(0.1)
        slot = seeded.zcard(cap_key)
    assert slot == 1, f"cap slot leaked after disconnect: {slot}"


# ── raw-ASGI WebSocket driver ────────────────────────────────────────────
#
# TestClient cannot be relied on to surface a server-initiated WebSocket close
# mid-stream, so revocation/expiry-during-stream is exercised through the real
# app with a scripted receive channel (same pattern as the SSE tests in
# tests/v3/test_scan_events.py).  The client stays idle after connect; the
# server's periodic re-validation is what closes the socket.


def _drive_ws_revocation(scan_id: int, token: str, timeout: float = 6.0) -> list:
    """Run the WebSocket app against an idle client that revokes *token* on
    the second receive, then capture every message the server sends."""
    from main import app
    from auth.token_store import token_store

    import asyncio

    capture: list = []
    state = {"step": 0}
    never = asyncio.Event()  # never set -> client stays idle forever

    async def receive():
        if state["step"] == 0:
            state["step"] = 1
            return {"type": "websocket.connect"}
        # Second receive: revoke the presenting token, then stay idle so the
        # server's periodic re-validation (not a client disconnect) closes it.
        token_store.revoke(token)
        await never.wait()
        return {"type": "websocket.disconnect"}

    async def send(message):
        capture.append(message)

    scope = {
        "type": "websocket",
        "http_version": "1.1",
        "method": "GET",
        "path": f"/api/v1/scans/{scan_id}/ws",
        "raw_path": f"/api/v1/scans/{scan_id}/ws".encode(),
        "query_string": b"",
        "headers": [
            [b"authorization", b"Bearer " + token.encode()],
            [b"origin", _ALLOWED_ORIGIN.encode()],
            [b"host", b"testserver"],
        ],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "scheme": "ws",
        "state": {},
        "app": app,
        "asgi": {"spec_version": "2.0"},
    }

    async def run():
        await asyncio.wait_for(app(scope, receive, send), timeout=timeout)

    try:
        asyncio.run(run())
    except asyncio.TimeoutError:
        pass
    return capture


# ── revocation / expiry during an open stream ──────────────────────────────


def test_ws_revocation_closes_open_stream(env, monkeypatch):
    """Revoking the bearer token mid-stream closes the WebSocket (fail-closed)."""
    from auth import jwt as token_service
    import app.api.v1.scans as scans_api

    # Speed up the periodic re-validation so the test stays fast.
    monkeypatch.setattr(scans_api, "_WS_REVALIDATE_INTERVAL_SECONDS", 0.2, raising=False)

    # A non-terminal scan keeps the server in the live-tail loop where
    # re-validation runs.
    running = _make_scan(env.db, env.org.id, status="running",
                         target="revokable.example.com")

    token = token_service.create_access_token(env.user.id)
    capture = _drive_ws_revocation(running.id, token)

    closes = [m for m in capture if m.get("type") == "websocket.close"]
    assert closes, f"no websocket.close was sent; capture={capture}"
    assert closes[0].get("code") == 4001, closes[0]


def test_ws_expired_token_refused_at_handshake(env, monkeypatch):
    """An expired bearer token is refused at the WebSocket handshake."""
    from auth import jwt as token_service
    import app.api.v1.scans as scans_api
    from config import settings

    monkeypatch.setattr(scans_api, "_WS_REVALIDATE_INTERVAL_SECONDS", 0.2, raising=False)

    # Token already expired at issue time.
    old_expire = settings.access_token_expire_minutes
    monkeypatch.setattr(settings, "access_token_expire_minutes", -1, raising=False)
    try:
        token = token_service.create_access_token(env.user.id)
    finally:
        monkeypatch.setattr(settings, "access_token_expire_minutes", old_expire, raising=False)

    headers = {"Authorization": f"Bearer {token}"}
    try:
        with _connect(env.client, env.scan_completed.id, headers=headers, origin=_ALLOWED_ORIGIN) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        # Expired token is refused at the handshake.
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected an expired token to be refused at handshake")
