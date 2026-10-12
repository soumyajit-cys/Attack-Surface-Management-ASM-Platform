"""Audit-IP tests: spoofed headers never reach audit entries (tests only).

Untrusted peer + spoofed X-Forwarded-For -> audit records the peer.
Trusted peer + X-Forwarded-For -> audit records the forwarded client.
The TestClient peer ("testclient") is never a trusted IP, so the trusted
case is proven at the helper level with crafted requests; the untrusted
case runs end-to-end through failed logins.
"""

import json


def _request(peer, xff=None):
    from starlette.requests import Request

    raw = [(b"host", b"test")]
    if xff is not None:
        raw.append((b"x-forwarded-for", xff.encode()))
    scope = {"type": "http", "method": "GET", "path": "/",
             "headers": raw, "client": (peer, 1234)}
    return Request(scope)


def test_audit_helper_untrusted_peer_uses_peer(monkeypatch):
    import app.core.config as config_mod
    from app.core.audit import client_ip

    monkeypatch.setattr(config_mod.settings, "trusted_proxies", "")
    assert client_ip(_request("203.0.113.9",
                              xff="198.51.100.7")) == "203.0.113.9"


def test_audit_helper_trusted_peer_uses_forwarded(monkeypatch):
    import app.core.config as config_mod
    from app.core.audit import client_ip

    monkeypatch.setattr(config_mod.settings, "trusted_proxies",
                        "10.0.0.0/8")
    assert client_ip(_request("10.1.2.3",
                              xff="203.0.113.9")) == "203.0.113.9"


def test_failed_login_audit_records_peer_not_spoof(client, db):
    from models.audit_log import AuditLog

    client.post(
        "/api/v1/auth/register",
        json={"username": "auditip", "email": "auditip@example.com",
              "password": "password123", "organization": "Audit IP Org"},
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "auditip", "password": "wrong"},
        headers={"X-Forwarded-For": "198.51.100.7"})
    assert response.status_code == 401
    entry = db.query(AuditLog).filter(
        AuditLog.action == "auth.login_failed").order_by(
            AuditLog.id.desc()).first()
    assert entry is not None
    details = json.loads(entry.details)
    assert details["ip"] != "198.51.100.7"
    assert details["ip"] == "testclient"
