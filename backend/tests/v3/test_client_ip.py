"""1.5.2 client-IP and proxy trust (tests only, then implementation).

get_client_ip(request) is the single source for the limiter key, audit log,
and (1.5.3) lockout. X-Forwarded-For is honored ONLY when the immediate peer
is in TRUSTED_PROXIES; otherwise the direct peer is used (spoof-proof).
Imports are function-level so this file collects before the helper exists;
behavior cases are strict-xfailed until implementation lands.
"""

import pytest


def _request(peer, xff=None, headers=None):
    from starlette.requests import Request

    raw = [(b"host", b"test")]
    if xff is not None:
        raw.append((b"x-forwarded-for", xff.encode()))
    for key, value in (headers or {}).items():
        raw.append((key.encode(), value.encode()))
    scope = {"type": "http", "method": "GET", "path": "/",
             "headers": raw, "client": (peer, 1234)}
    return Request(scope)


def _helper():
    from utils.client_ip import get_client_ip

    return get_client_ip


@pytest.mark.xfail(
    strict=True, reason="BUG-IP-001: get_client_ip helper does not exist yet")
def test_spoofed_header_ignored_from_untrusted_peer(monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "trusted_proxies", "")
    request = _request("203.0.113.9", xff="198.51.100.7")
    assert _helper()(request) == "203.0.113.9"


@pytest.mark.xfail(
    strict=True, reason="BUG-IP-001: get_client_ip helper does not exist yet")
def test_header_honored_from_trusted_peer(monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "trusted_proxies",
                        "10.0.0.0/8")
    request = _request("10.1.2.3", xff="203.0.113.9")
    assert _helper()(request) == "203.0.113.9"


@pytest.mark.xfail(
    strict=True, reason="BUG-IP-001: get_client_ip helper does not exist yet")
def test_rightmost_untrusted_hop(monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "trusted_proxies",
                        "10.0.0.0/8, 172.16.0.0/12")
    # Client -> proxy1 (untrusted, spoofable) -> trusted ingress.
    request = _request("10.9.9.9",
                       xff="203.0.113.5, 198.51.100.99, 10.9.9.9")
    assert _helper()(request) == "198.51.100.99"


@pytest.mark.xfail(
    strict=True, reason="BUG-IP-001: get_client_ip helper does not exist yet")
def test_ipv6_and_malformed(monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "trusted_proxies",
                        "2001:db8::/32")
    v6 = _request("2001:db8::1", xff="2001:db8:abcd::9")
    assert _helper()(v6) == "2001:db8:abcd::9"
    junk = _request("2001:db8::1", xff="not-an-ip, , 2001:db8::2")
    assert _helper()(junk) == "2001:db8::2"
    all_junk = _request("2001:db8::1", xff="garbage")
    assert _helper()(all_junk) == "2001:db8::1"


@pytest.mark.xfail(
    strict=True, reason="BUG-IP-001: get_client_ip helper does not exist yet")
def test_all_trusted_chain_uses_leftmost(monkeypatch):
    import app.core.config as config_mod

    monkeypatch.setattr(config_mod.settings, "trusted_proxies",
                        "10.0.0.0/8")
    request = _request("10.9.9.9", xff="10.1.1.1, 10.2.2.2")
    assert _helper()(request) == "10.1.1.1"


@pytest.mark.xfail(
    strict=True, reason="BUG-IP-002: limiter keys on X-Forwarded-For first, "
    "so rotating the header resets the bucket")
def test_limiter_key_ignores_spoofed_header(client):
    """Rotating X-Forwarded-For must not reset the login limit (default:
    TRUSTED_PROXIES empty, TestClient peer untrusted)."""
    for i in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "nosuchuser", "password": "wrong"},
            headers={"X-Forwarded-For": f"10.0.0.{i}"})
        assert response.status_code == 401
    blocked = client.post(
        "/api/v1/auth/login",
        json={"username": "nosuchuser", "password": "wrong"},
        headers={"X-Forwarded-For": "10.9.9.9"})
    assert blocked.status_code == 429
