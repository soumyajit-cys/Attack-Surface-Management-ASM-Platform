"""Live scan progress over Server-Sent Events (v1.6.x, tests first).

``GET /api/v1/scans/{id}/events`` streams a Redis Stream
(``scan:{id}:events``) as ``text/event-stream``: an initial snapshot (so a
late client is never blind), ordered replay from ``Last-Event-ID``, live
events while the scan runs, a ``: heartbeat`` comment every 15 s, and a
close right after the terminal event. Same permission + org scoping as
``GET /scans/{id}``. A per-user concurrent stream cap (429) and a maximum
stream duration bound the resource cost; publishing from the worker never
fails a scan and never carries error text or secrets.

Transport notes:
- ``TestClient`` buffers whole responses, so anything still-open is driven
  through a raw-ASGI harness (``_drive_with_disconnect``) that injects
  ``http.disconnect`` on demand — that is how client aborts are exercised.
- Heartbeats are bytes of the (already counted) request, so the global rate
  limiter sees exactly one request per opened stream.
- Meters/tenant/RBAC/OpenAPI coverage lives in the matrix tests and the
  committed docs.
"""

import asyncio
import json
import threading
import time
from types import SimpleNamespace

import pytest


# ── seeded environment ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _stream_limits_testable(monkeypatch):
    """Make still-open streams TestClient-readable.

    ``TestClient`` buffers whole responses, so a stream that never closes
    would hang ``client.request``. Test-wide defaults give every stream a
    short max duration (the client finishes reading when the server closes;
    frames/ids assertions are unaffected) plus a fast heartbeat cadence.
    Individual tests may override either knob again.
    """
    from config import settings

    monkeypatch.setattr(
        settings, "scan_stream_max_duration_seconds", 1.0, raising=False)
    monkeypatch.setattr(
        settings, "scan_stream_heartbeat_seconds", 0.2, raising=False)
    yield


@pytest.fixture()
def env(client, db, org_factory, auth_headers):
    org, user = org_factory("SSE Org", "sseadmin", "sseadmin@example.com")
    db.expire_all()
    scan = _make_scan(db, org.id, status="running")
    scan_completed = _make_scan(db, org.id, status="completed")
    return SimpleNamespace(
        client=client, db=db, org=org, user=user,
        headers=auth_headers("sseadmin"),
        scan=scan, scan_completed=scan_completed,
    )


def _make_scan(db, org_id, status="running", target="events.example.com"):
    from models.scan_history import ScanHistory

    scan = ScanHistory(
        organization_id=org_id, target=target, status=status, scope="passive",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# ── helpers ──────────────────────────────────────────────────────────────────


def _url(env, scan_like):
    return f"/api/v1/scans/{scan_like}/events"


def _parse_frames(text):
    """Parse SSE text (TestClient body or raw harness body) into frames."""
    parsed = []
    current = {"id": None, "event": None, "data": None}
    for line in text.splitlines():
        if line.startswith(":"):
            parsed.append({"comment": line[1:].strip()})
            continue
        if not line:
            if current.get("event") or current.get("data") is not None:
                parsed.append(current)
            current = {"id": None, "event": None, "data": None}
            continue
        if line.startswith("id:"):
            current["id"] = line[3:].strip()
        elif line.startswith("event:"):
            current["event"] = line[6:].strip()
        elif line.startswith("data:"):
            payload = line[5:].strip()
            current["data"] = json.loads(payload) if payload else None
    return parsed


def _publish_sequence(scan_id, items):
    from services.scan_events import publish_scan_event

    for item in items:
        publish_scan_event(
            scan_id,
            item["kind"],
            phase=item.get("phase"),
            counts=item.get("counts"),
            code=item.get("code"),
        )


def _body_from_capture(capture) -> str:
    return b"".join(
        m.get("body", b"") for m in capture if m.get("type") == "http.response.body"
    ).decode()


# ── raw-ASGI stream harness ──────────────────────────────────────────────────
#
# TestClient buffers the entire response before it is readable, so it can
# only test streams that close on their own (terminal scans). To exercise
# still-open streams (heartbeats, disconnect release, max duration) we call
# the real app with a scripted receive channel: after
# ``heartbeats`` heartbeats were observed in the captured ``send`` frames, it
# delivers ``http.disconnect`` — the same message a production ASGI server
# produces when the client disappears.


def _drive_with_disconnect(headers, scan_id, heartbeats, timeout=10.0):
    from main import app

    auth = headers["Authorization"]
    assert auth.startswith("Bearer ")
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": f"/api/v1/scans/{scan_id}/events",
        "raw_path": b"",
        "query_string": b"",
        "headers": [[b"authorization", f"Bearer ".encode() + auth[7:].encode()]],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "scheme": "http",
        "state": {},
        "app": app,
        "asgi": {"spec_version": "2.0"},
    }
    capture: list = []

    async def run():
        served_request = {"flag": False}

        async def receive():
            # First call: the GET request body. After that, a real server
            # never emits another http.request — dispatch stays open until
            # either the injectable disconnect resonates or forever.
            if not served_request["flag"]:
                served_request["flag"] = True
                return {"type": "http.request", "body": b"", "more_body": False}
            while True:
                if heartbeats is not None:
                    beats = sum(
                        1 for m in capture
                        if m.get("body") == b": heartbeat\n\n"
                    )
                    if beats >= heartbeats:
                        return {"type": "http.disconnect"}
                await asyncio.sleep(0.01)

        async def send(message):
            capture.append(message)

        scope["receive"] = receive
        await asyncio.wait_for(app(scope, receive, send), timeout)

    try:
        asyncio.run(run())
    except asyncio.TimeoutError:
        capture.append({"timeout": True})
    return SimpleNamespace(body=_body_from_capture(capture), capture=capture)


def _drive_open_stream(headers, scan_id, timeout=10.0):
    """Open the stream and return after the app terminated on its own."""
    from main import app

    auth = headers["Authorization"]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": f"/api/v1/scans/{scan_id}/events",
        "raw_path": b"",
        "query_string": b"",
        "headers": [[b"authorization", f"Bearer ".encode() + auth[7:].encode()]],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "scheme": "http",
        "state": {},
        "app": app,
        "asgi": {"spec_version": "2.0"},
    }
    capture: list = []

    async def run():
        served_request = {"flag": False}

        async def receive():
            # No client disconnect in this scenario: after the request body
            # the channel stays silent, exactly like a healthy connection.
            if not served_request["flag"]:
                served_request["flag"] = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.sleep(3600)

        async def send(message):
            capture.append(message)

        scope["receive"] = receive
        await asyncio.wait_for(app(scope, receive, send), timeout)

    try:
        asyncio.run(run())
    except asyncio.TimeoutError:
        capture.append({"timeout": True})
    return SimpleNamespace(body=_body_from_capture(capture), capture=capture)


# ── auth ─────────────────────────────────────────────────────────────────────


def test_events_require_bearer(env):
    response = env.client.get(_url(env, env.scan.id))
    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "unauthenticated"


def test_events_reject_query_string_token(env):
    from auth import jwt as token_service

    token = token_service.create_access_token(env.user.id)
    response = env.client.get(_url(env, env.scan_completed.id) + f"?token={token}")
    assert response.status_code == 401, response.text


def test_events_api_key_with_scan_read_works(env):
    stepup = env.client.post(
        "/api/v1/auth/step-up",
        json={"password": "password123"},
        headers=env.headers,
    )
    assert stepup.status_code == 200, stepup.text
    created = env.client.post(
        "/api/v1/organizations/api-keys",
        json={"name": "ssekey", "scopes": "read"},
        headers=env.headers,
    )
    assert created.status_code == 201, created.text
    key_headers = {"X-API-Key": created.json()["key"]}
    response = env.client.get(_url(env, env.scan_completed.id), headers=key_headers)
    assert response.status_code == 200, response.text
    frames = _parse_frames(response.text)
    assert frames[0]["event"] == "snapshot"


def test_events_cross_org_404_same_as_missing(env, other_org_scan):
    response = env.client.get(_url(env, other_org_scan.id), headers=env.headers)
    assert response.status_code == 404, response.text
    missing = env.client.get(_url(env, 999999), headers=env.headers)
    assert missing.status_code == 404, missing.text
    assert response.json()["error"]["code"] == "scan_not_found"
    assert missing.json()["error"]["code"] == "scan_not_found"
    assert missing.json()["error"]["message"] == response.json()["error"]["message"]
    assert "other.example.com" not in response.text


@pytest.fixture()
def other_org_scan(db, org_factory, auth_headers):
    org_b, _user_b = org_factory("SSE Other", "sseother", "sseother@example.com")
    db.expire_all()
    return _make_scan(db, org_b.id, status="running",
                      target="other.example.com")


# ── reading behavior ─────────────────────────────────────────────────────────


def test_snapshot_on_connect_and_ordered_replay(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "phase_started", "phase": "discovery"},
    ])
    response = env.client.get(_url(env, env.scan.id), headers=env.headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/event-stream")
    frames = _parse_frames(response.text)
    assert frames[0]["event"] == "snapshot"
    assert frames[0]["data"]["status"] == "running"
    assert frames[0]["id"] is None
    stream_frames = [f for f in frames if f.get("id")]
    assert [f["event"] for f in stream_frames] == [
        "queued", "running", "phase_started"]
    ids = [tuple(map(int, f["id"].split("-"))) for f in stream_frames]
    assert ids == sorted(ids) and len(ids) == len(set(ids))
    assert stream_frames[0]["data"]["status"] == "queued"
    assert stream_frames[2]["data"]["phase"] == "discovery"


def test_resume_from_last_event_id_without_duplicates(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "phase_started", "phase": "discovery"},
    ])
    first = env.client.get(_url(env, env.scan.id), headers=env.headers)
    assert first.status_code == 200, first.text
    ids = [f["id"] for f in _parse_frames(first.text) if f.get("id")]
    assert len(ids) == 3
    resumed = env.client.get(
        _url(env, env.scan.id),
        headers={**env.headers, "Last-Event-ID": ids[1]},
    )
    assert resumed.status_code == 200, resumed.text
    stream_frames = [f for f in _parse_frames(resumed.text) if f.get("id")]
    assert [f["id"] for f in stream_frames] == ids[2:]
    assert all(f["id"] != ids[1] for f in stream_frames)


def test_terminal_event_closes_stream(env):
    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "completed", "counts": {"findings": 3}},
    ])
    response = env.client.get(_url(env, env.scan.id), headers=env.headers)
    assert response.status_code == 200, response.text
    frames = _parse_frames(response.text)
    assert frames[-1]["event"] == "completed"
    assert frames[-1]["data"]["counts"] == {"findings": 3}
    # nothing after the terminal frame
    assert all(
        f.get("event") not in ("running", "phase_started")
        for f in frames[frames.index(frames[-1]) + 1:]
    )


def test_terminal_status_closes_immediately(env):
    """Empty stream + terminal DB status: snapshot + synthesized close."""
    response = env.client.get(_url(env, env.scan_completed.id), headers=env.headers)
    assert response.status_code == 200, response.text
    frames = _parse_frames(response.text)
    assert frames[0]["event"] == "snapshot"
    assert frames[0]["data"]["status"] == "completed"
    assert frames[-1]["event"] == "completed"
    assert len(frames) == 2


# ── stream cap, disconnect release, duration, rate limit ─────────────────────


def test_stream_cap_429_and_slot_freed(env, monkeypatch):
    from config import settings
    from utils.redis_client import get_redis

    monkeypatch.setattr(settings, "scan_stream_max_per_user", 2, raising=False)
    cap_key = f"scan_streams:{env.user.id}"
    seeded = get_redis()
    seeded.sadd(cap_key, "a")
    seeded.sadd(cap_key, "b")

    response = env.client.get(_url(env, env.scan.id), headers=env.headers)
    assert response.status_code == 429, response.text
    assert response.json()["error"]["code"] == "stream_cap_reached"
    assert seeded.scard(cap_key) == 2  # refused attempt left nothing behind


def test_disconnect_frees_cap_slot(env, monkeypatch):
    """Aborting an open stream releases its concurrent-cap slot (finally)."""
    from config import settings
    from utils.redis_client import get_redis

    monkeypatch.setattr(settings, "scan_stream_heartbeat_seconds", 0.2, raising=False)
    monkeypatch.setattr(settings, "scan_stream_max_duration_seconds", 30.0, raising=False)
    cap_key = f"scan_streams:{env.user.id}"
    seeded = get_redis()
    seeded.sadd(cap_key, "other-session")

    result = None

    def runner():
        nonlocal result
        result = _drive_with_disconnect(env.headers, env.scan.id, heartbeats=3)

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join(timeout=15)
    assert result is not None, "stream never returned to the harness"
    assert result.body.count(": heartbeat") >= 3
    assert "completed" not in result.body

    slot = seeded.scard(cap_key)
    deadline = time.monotonic() + 5
    while slot != 1 and time.monotonic() < deadline:
        time.sleep(0.1)
        slot = seeded.scard(cap_key)
    assert slot == 1, f"cap slot leaked after disconnect: {slot}"


def test_max_duration_closes_stream(env, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "scan_stream_max_duration_seconds", 0.5, raising=False)
    monkeypatch.setattr(settings, "scan_stream_heartbeat_seconds", 3600, raising=False)
    result = _drive_open_stream(env.headers, env.scan.id, timeout=8.0)
    frames = _parse_frames(result.body)
    assert [f["event"] for f in frames] == ["snapshot"], result.body


def test_opening_a_stream_counts_once_toward_rate_limit(env):
    """Default limiter: N opens == N requests; the (N+1)th returns 429."""
    from config import settings

    limit = settings.rate_limit_requests_per_minute
    statuses = [
        env.client.get(_url(env, env.scan_completed.id), headers=env.headers).status_code
        for _ in range(limit + 1)
    ]
    assert statuses[:limit] == [200] * limit, statuses
    assert statuses[-1] == 429


def test_heartbeat_is_comment_not_an_event(env, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "scan_stream_heartbeat_seconds", 0.2, raising=False)
    result = _drive_with_disconnect(env.headers, env.scan.id, heartbeats=3)
    assert result.body.count(": heartbeat") >= 3
    frames = _parse_frames(result.body)
    # only the snapshot is a real event so far; every heartbeat is a comment
    events = [f for f in frames if "comment" not in f]
    assert [f["event"] for f in events] == ["snapshot"]
    # and it carried no id (never moves Last-Event-ID)
    assert events[0]["id"] is None


# ── publishing isolation & hygiene ───────────────────────────────────────────


def test_publish_failure_never_fails_and_logs_exception_type(db, env, monkeypatch, caplog):
    import logging

    import services.scan_events as scan_events
    import tasks.discovery_tasks as dt

    def raise_publish(*a, **k):
        raise RuntimeError("redis down")

    monkeypatch.setattr(scan_events, "get_redis", raise_publish)
    with caplog.at_level(logging.WARNING):
        scan_events.publish_scan_event(env.scan.id, "running")
    assert any("RuntimeError" in r.message for r in caplog.records), caplog.text

    # the same isolation holds for the worker's fail path: a raising
    # publisher must never break _fail_scan
    monkeypatch.setattr(scan_events, "publish_scan_event", raise_publish)
    dt._fail_scan(db, env.scan, str(env.org.id), "boom")
    db.refresh(env.scan)
    assert env.scan.status == "failed"
    assert env.scan.error == "boom"


def test_failed_publish_has_no_error_text(db, env):
    import tasks.discovery_tasks as dt
    from utils.redis_client import get_redis

    scan = _make_scan(db, env.org.id, status="running")
    dt._fail_scan(db, scan, str(env.org.id), "SECRET-banner-value ACE ban")
    entries = get_redis().xrange(f"scan:{scan.id}:events", min="-", max="+")
    assert entries, "no events published for the failed scan"
    last_kind = entries[-1][1]["kind"]
    assert last_kind == "failed"
    payload = json.loads(entries[-1][1]["data"])
    assert set(payload.keys()) <= {"status", "code", "counts"}
    assert "SECRET-banner-value" not in json.dumps(dict(entries[-1][1]))


def test_event_payload_whitelist(db, env):
    from utils.redis_client import get_redis

    _publish_sequence(env.scan.id, [
        {"kind": "queued"},
        {"kind": "running"},
        {"kind": "phase_started", "phase": "discovery"},
        {"kind": "phase_finished", "phase": "discovery",
         "counts": {"subdomains_discovered": 7}},
        {"kind": "phase_finished", "phase": "scanning",
         "counts": {"ports_open": 2, "ports_total": 100,
                    "ssl_scanned": 4, "ssl_issues": 1}},
        {"kind": "phase_unavailable", "phase": "ssl",
         "code": "module_unavailable"},
    ])
    entries = get_redis().xrange(f"scan:{env.scan.id}:events", min="-", max="+")
    assert [e[1]["kind"] for e in entries] == [
        "queued", "running", "phase_started", "phase_finished",
        "phase_finished", "phase_unavailable",
    ]
    for _eid, fields in entries:
        data = json.loads(fields["data"])
        assert set(data.keys()) <= {"status", "phase", "code", "counts",
                                    "started_at", "completed_at"}
        if "counts" in data:
            assert all(isinstance(v, int) for v in data["counts"].values())


def test_stream_maxlen_and_ttl(env, monkeypatch):
    """xadd carries MAXLEN (settings value, approximate) and the TTL is set."""
    from config import settings
    from utils.redis_client import get_redis

    monkeypatch.setattr(settings, "scan_events_stream_maxlen", 3, raising=False)
    calls: list = []

    class RecordingRedis:
        def xadd(self, key, fields, maxlen=None, approximate=False):
            calls.append(("xadd", key, maxlen, approximate))
            return "id"

        def expire(self, key, ttl):
            calls.append(("expire", key, ttl))

    import services.scan_events as scan_events

    monkeypatch.setattr(scan_events, "get_redis", lambda: RecordingRedis())
    for _ in range(3):
        _publish_sequence(env.scan.id, [{"kind": "running"}])
    assert calls[0][2] == 3  # maxlen == configured value
    assert calls[0][3] is True  # approximate trimming
    assert calls[0][1] == f"scan:{env.scan.id}:events"
    # every publish refreshes the TTL
    assert calls[-1][0] == "expire"
    assert calls[-1][2] == settings.scan_events_expire_seconds
