import pytest
from starlette.websockets import WebSocketDisconnect
from services.scan_events import publish_scan_event

@pytest.fixture(autouse=True)
def _limits(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "scan_stream_max_duration_seconds", 1.0, raising=False)
    monkeypatch.setattr(settings, "scan_stream_heartbeat_seconds", 0.2, raising=False)

@pytest.fixture()
def env(client, db, org_factory, auth_headers):
    from tests.v3.test_scan_ws import _make_scan
    org, user = org_factory("C Org", "cadm", "cadm@example.com")
    db.expire_all()
    scan = _make_scan(db, org.id, status="completed")
    from types import SimpleNamespace
    return SimpleNamespace(client=client, db=db, org=org, user=user, headers=auth_headers("cadm"), scan=scan)

def test_probe(env):
    with env.client.websocket_connect(f"/api/v1/scans/{env.scan.id}/ws", headers=env.headers) as ws:
        print("FIRST:", ws.receive_text()[:60])
        print("SECOND:", ws.receive_text()[:60])
        try:
            print("THIRD:", ws.receive_text()[:60])
        except WebSocketDisconnect as e:
            print("DISCONNECT code:", e.code)
        except Exception as e:
            print("OTHER:", type(e).__name__, e)
