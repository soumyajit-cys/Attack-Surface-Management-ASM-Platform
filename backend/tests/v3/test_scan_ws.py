"""Live scan progress over WebSocket (Phase 1).

``GET /api/v1/scans/{id}/ws`` streams the same Redis Stream
``scan:{id}:events`` as the SSE endpoint, framed as SSE text blocks over a
WebSocket text channel. Auth: ``Authorization: Bearer`` header, plus a
``?token=`` query fallback because browsers cannot set custom WebSocket
headers. Same org scoping and per-user concurrent cap as SSE.

TestClient buffers nothing for a connected socket, so frames are read with
``receive_text()`` directly. A server-initiated close surfaces as
``WebSocketDisconnect`` carrying the close code.
"""

import json
import time
from types import SimpleNamespace

import pytest
from starlette.websockets import WebSocketDisconnect

from services.scan_events import publish_scan_event


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


def _url(scan_like):
    return f"/api/v1/scans/{scan_like}/ws"


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


def _connect(client, scan_id, headers=None, query_params=None):
    url = _url(scan_id)
    if query_params:
        qs = "&".join(f"{k}={v}" for k, v in query_params.items())
        url = f"{url}?{qs}"
    return client.websocket_connect(url, headers=headers or {})


# ── auth ─────────────────────────────────────────────────────────────────────


def test_ws_requires_auth(env):
    try:
        with _connect(env.client, env.scan.id) as ws:
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


def test_ws_query_token_fallback_connects(env):
    from auth import jwt as token_service

    token = token_service.create_access_token(env.user.id)
    _publish_sequence(env.scan_completed.id, [{"kind": "completed"}])
    with _connect(
        env.client, env.scan_completed.id,
        query_params={"token": token},
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


def test_ws_revoked_token_refused(env, db):
    from auth import jwt as token_service
    from auth.token_store import token_store

    token = token_service.create_access_token(env.user.id)
    headers = {"Authorization": f"Bearer {token}"}
    with _connect(env.client, env.scan_completed.id, headers=headers) as ws:
        ws.receive_text()  # snapshot succeeds while token valid
    token_store.revoke(token)
    try:
        with _connect(env.client, env.scan_completed.id, headers=headers):
            pass
    except WebSocketDisconnect as exc:
        assert exc.code == 4001, exc.code
        return
    raise AssertionError("expected a revoked token to be refused")


def test_ws_deactivated_user_refused(env, db):
    from auth import jwt as token_service

    token = token_service.create_access_token(env.user.id)
    headers = {"Authorization": f"Bearer {token}"}
    with _connect(env.client, env.scan_completed.id, headers=headers) as ws:
        ws.receive_text()

    env.user.is_active = False
    db.commit()
    try:
        with _connect(env.client, env.scan_completed.id, headers=headers):
            pass
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
        with _connect(env.client, other_org_scan.id, headers=env.headers) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4004, exc.code
        return
    raise AssertionError("expected cross-org scan to be refused")


def test_ws_unknown_scan_refused(env):
    try:
        with _connect(env.client, 999999, headers=env.headers) as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        assert exc.code == 4004, exc.code
        return
    raise AssertionError("expected an unknown scan to be refused")


# ── reading behavior ─────────────────────────────────────────────────────────


def test_ws_snapshot_on_connect_and_ordered_replay(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "phase_started", "phase": "discovery"},
    ])
    with _connect(env.client, env.scan.id, headers=env.headers) as ws:
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
    with _connect(env.client, env.scan.id, headers=env.headers) as ws:
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
    with _connect(env.client, env.scan.id, headers=env.headers) as ws:
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
    with _connect(env.client, env.scan_completed.id, headers=env.headers) as ws:
        blocks = []
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                block = ws.receive_text()
            except WebSocketDisconnect:
                break
            blocks.append(block)
    assert any(": heartbeat" in b for b in blocks), blocks


# ── stream cap ───────────────────────────────────────────────────────────────


def test_ws_cap_429_and_slot_freed(env, monkeypatch):
    from config import settings
    from utils.redis_client import get_redis

    monkeypatch.setattr(settings, "scan_stream_max_per_user", 1, raising=False)
    cap_key = f"scan_streams:{env.user.id}"
    seeded = get_redis()
    seeded.zadd(cap_key, {"existing-session": time.time() + 3600})

    try:
        with _connect(env.client, env.scan_completed.id, headers=env.headers) as ws:
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

    with _connect(env.client, env.scan_completed.id, headers=env.headers) as ws:
        ws.receive_text()  # snapshot; slot now held

    slot = seeded.zcard(cap_key)
    deadline = time.monotonic() + 5
    while slot != 1 and time.monotonic() < deadline:
        time.sleep(0.1)
        slot = seeded.zcard(cap_key)
    assert slot == 1, f"cap slot leaked after disconnect: {slot}"
