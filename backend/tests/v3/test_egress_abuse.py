"""Task 1.3 abuse-case suite (TESTS FIRST).

Committed red: ``utils.egress`` and ``utils.ssrf_guard.is_globally_routable_ip``
do not exist yet. Every test here is mocked -- no real network access.
"""

import socket as real_socket
from typing import ClassVar

import pytest

from utils.egress import (
    EgressBlocked,
    fetch_url_validated,
    open_tcp_validated,
    resolve_validated_ips,
    validate_webhook_url,
)
from utils.ssrf_guard import is_globally_routable_ip


def _addrs(*ips):
    return [(real_socket.AF_INET, 1, 6, "", (ip, 80)) for ip in ips]


def _addrs6(*ips):
    return [(real_socket.AF_INET6, 1, 6, "", (ip, 80, 0, 0)) for ip in ips]


class TestGloballyRoutableTable:
    @pytest.mark.parametrize("ip", [
        # Private ranges, v4 and v6.
        "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1",
        "fc00::1", "fd12:3456::1",
        # Loopback.
        "127.0.0.1", "127.1", "::1",
        # Link-local.
        "169.254.10.20", "fe80::1",
        # Cloud metadata endpoints.
        "169.254.169.254", "169.254.170.2", "100.100.100.200",
        "fd00:ec2::254",
        # CGNAT shared space.
        "100.64.0.1", "100.127.255.254",
        # Multicast.
        "224.0.0.1", "ff02::1", "ff05::1",
        # Reserved / unspecified / broadcast.
        "240.0.0.1", "0.0.0.0", "::", "255.255.255.255",
        # IPv4-mapped IPv6 hiding blocked v4.
        "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
        # NAT64 embedding blocked v4 (well-known prefix + embedded private).
        "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:101",
        # 6to4 embedding blocked v4.
        "2002:7f00:1::", "2002:a00:1::", "2002:c0a8:101::",
        # Non-standard IPv4 encodings of blocked addresses.
        "2130706433",          # 127.0.0.1 decimal
        "3232235777",          # 192.168.1.1 decimal
        "2852038105",          # 169.254.169.254 decimal
        "0177.0.0.1",          # 127.0.0.1 octal
        "0x7f.0.0.1",          # 127.0.0.1 hex
        "0x7f.1",              # 127.0.0.1 short hex
        "0xa.0x0.0x0.0x1",     # 10.0.0.1 hex
        # IPv6 zone ids (unparseable / link-local scope).
        "fe80::1%eth0", "127.0.0.1%lo",
        # Garbage is fail-closed.
        "", "not-an-ip", "999.1.1.1", "1.2.3.4.5",
    ])
    def test_blocked(self, ip):
        assert is_globally_routable_ip(ip) is False

    @pytest.mark.parametrize("ip", [
        "93.184.216.34", "1.1.1.1", "8.8.8.8",
        "2606:4700:4700::1111", "2001:4860:4860::8888",
        "::ffff:93.184.216.34",          # mapped, but globally routable v4
        "64:ff9b::5db8:6401",           # NAT64 embedding public v4
        "2002:5db8:6401::",             # 6to4 embedding public v4
        "0x5d.0xb8.0x64.0x1",           # 93.184.100.1 hex, public
    ])
    def test_allowed(self, ip):
        assert is_globally_routable_ip(ip) is True


class TestResolveValidatedIps:
    def test_mixed_public_and_private_fails_closed(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: _addrs("93.184.216.34", "10.9.9.9"),
        )
        with pytest.raises(EgressBlocked):
            resolve_validated_ips("mixed.example.com")

    def test_all_public_returns_ips(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: _addrs("93.184.216.34", "1.1.1.1"),
        )
        assert resolve_validated_ips("ok.example.com") == [
            "93.184.216.34", "1.1.1.1"]

    def test_unresolvable_fails(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: (_ for _ in ()).throw(real_socket.gaierror()),
        )
        with pytest.raises(EgressBlocked):
            resolve_validated_ips("missing.invalid")


def _aio_run(coro):
    import asyncio
    return asyncio.run(coro)


class TestOpenTcpValidated:
    def test_dials_validated_ip_not_hostname(self, monkeypatch):
        import asyncio

        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("93.184.216.34"))
        dialed = []

        async def fake_open(ip, port, **kw):
            dialed.append((ip, port, kw.get("server_hostname")))
            return asyncio.StreamReader(), object()

        monkeypatch.setattr(asyncio, "open_connection", fake_open)

        async def go():
            return await open_tcp_validated("target.example.com", 443)

        reader, _writer = _aio_run(go())
        assert dialed == [("93.184.216.34", 443, None)]
        assert isinstance(reader, asyncio.StreamReader)

    def test_blocked_host_never_dials(self, monkeypatch):
        import asyncio

        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("10.9.9.9"))

        async def _boom(*a, **k):
            raise AssertionError("must not dial blocked hosts")

        monkeypatch.setattr(asyncio, "open_connection", _boom)

        async def go():
            return await open_tcp_validated("evil.example.com", 443)

        with pytest.raises(EgressBlocked):
            _aio_run(go())

    def test_tls_sni_and_verification_pinned_to_name(self, monkeypatch):
        import asyncio
        import ssl as stdlib_ssl

        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("93.184.216.34"))
        dialed = []

        async def fake_open(ip, port, **kw):
            dialed.append((ip, port, kw.get("ssl"), kw.get("server_hostname")))
            return asyncio.StreamReader(), object()

        monkeypatch.setattr(asyncio, "open_connection", fake_open)

        async def go():
            ctx = stdlib_ssl.create_default_context()
            return await open_tcp_validated(
                "tls.example.com", 443, ssl_context=ctx,
                server_hostname="tls.example.com",
            )

        _aio_run(go())
        assert len(dialed) == 1
        ip, port, ctx, name = dialed[0]
        assert (ip, port, name) == ("93.184.216.34", 443, "tls.example.com")
        assert ctx.verify_mode == stdlib_ssl.CERT_REQUIRED
        assert ctx.check_hostname is True


class FakeStream:
    def __init__(self, status_code, body, headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def aiter_bytes(self):
        yield self._body


def _fake_client_class(requests_log, responder):
    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, headers=None, **kw):
            requests_log.append((method, url, dict(headers or {})))
            return responder(url, dict(headers or {}))

    return FakeClient


class TestFetchValidated:
    def test_single_lookup_no_rebinding(self, monkeypatch):
        lookups = []

        def fake_getaddrinfo(host, *a, **k):
            lookups.append(host)
            return _addrs("93.184.216.34")

        monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)

        requests_log = []

        def responder(url, headers):
            # Helper must dial the validated IP, never the hostname, and must
            # pin the Host header + SNI to the original name.
            assert "target.example.com" not in url
            assert "93.184.216.34" in url
            assert headers.get("Host") == "target.example.com"
            return FakeStream(200, b"hello")

        monkeypatch.setattr(
            "utils.egress.httpx.AsyncClient",
            _fake_client_class(requests_log, responder),
        )
        import asyncio
        result = asyncio.run(fetch_url_validated("http://target.example.com/"))
        assert result.status_code == 200
        assert result.body == b"hello"
        assert lookups == ["target.example.com"]

    def test_redirect_public_to_internal_blocked(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda host, *a, **k: _addrs(
                {"start.example.com": "93.184.216.34",
                 "evil.example.com": "10.9.9.9"}[host]),
        )
        requests_log = []

        def responder(url, headers):
            if "93.184.216.34" in url:
                return FakeStream(302, b"", {"location": "http://evil.example.com/"})
            raise AssertionError(f"must not fetch internal hop: {url}")

        monkeypatch.setattr(
            "utils.egress.httpx.AsyncClient",
            _fake_client_class(requests_log, responder),
        )
        import asyncio
        with pytest.raises(EgressBlocked):
            asyncio.run(fetch_url_validated("http://start.example.com/"))
        assert len(requests_log) == 1

    def test_too_many_redirects_rejected(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("93.184.216.34"))
        requests_log = []

        def responder(url, headers):
            return FakeStream(302, b"", {"location": "http://loop.example.com/"})

        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda host, *a, **k: _addrs("93.184.216.34"),
        )
        monkeypatch.setattr(
            "utils.egress.httpx.AsyncClient",
            _fake_client_class(requests_log, responder),
        )
        import asyncio
        with pytest.raises(EgressBlocked):
            asyncio.run(fetch_url_validated("http://loop.example.com/"))
        assert len(requests_log) <= 4


class TestWebhookValidation:
    @pytest.mark.parametrize("url", [
        "https://user:pass@hooks.example.com/x",   # userinfo
        "https://user@hooks.example.com/x",        # userinfo, no password
        "http://hooks.example.com/x",              # plain http
        "https://hooks.example.com:8444/x",        # non-allowed port
        "https://hooks.example.com:0/x",
        "ftp://hooks.example.com/x",
        "https://[::ffff:127.0.0.1]/x",            # mapped loopback
        "not-a-url",
        "",
    ])
    def test_rejected_shapes(self, url):
        with pytest.raises(EgressBlocked):
            validate_webhook_url(url)

    def test_private_host_rejected(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("10.9.9.9"))
        with pytest.raises(EgressBlocked):
            validate_webhook_url("https://hooks.example.com/x")

    def test_public_host_accepted(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("93.184.216.34"))
        host, port, path = validate_webhook_url("https://hooks.example.com/hook")
        assert (host, port) == ("hooks.example.com", 443)

    def test_send_path_validates_before_traffic(self, monkeypatch, db, org_factory):
        from services.alerts import alerting_service as alerts

        monkeypatch.setattr(
            "socket.getaddrinfo", lambda *a, **k: _addrs("169.254.169.254"))

        async def _boom(*a, **k):
            raise AssertionError("blocked webhooks must not be fetched")

        monkeypatch.setattr(alerts, "fetch_url_validated", _boom)
        import asyncio
        from models.asset import Asset
        from models.finding import Finding
        org, _ = org_factory("WH Org", "whorg", "whorg@example.com")
        asset = Asset(organization_id=org.id, name="wh.example.com")
        db.add(asset)
        db.flush()
        finding = Finding(organization_id=org.id, asset_id=asset.id,
                          title="T", severity="high")
        db.add(finding)
        db.flush()
        # Blocked webhooks fail delivery (False) without any HTTP traffic.
        result = asyncio.run(alerts.send_slack_alert(
            "https://hooks.example.com/x", finding, asset))
        assert result is False


class TestNoDirectSocketUse:
    """Scanner paths must go through utils.egress (grep-style guard)."""

    ALLOW: ClassVar[dict] = {
        # Third-party API fetches, not target connections; each feed hostname
        # is validated before use. Kept visible so new direct uses fail loudly.
        "backend/services/discovery/subdomain_service.py": {"requests.get"},
        "backend/services/enrichment/cve_service.py": {"requests.post"},
        "backend/services/scoring/risk_engine.py": {"requests.get"},
        # The helper itself + legacy guard internals.
        "backend/utils/egress.py": set(),
        "backend/utils/ssrf_guard.py": set(),
    }
    DENY: ClassVar[set] = {
        "socket.create_connection",
        "asyncio.open_connection",
        "httpx.get",
        "httpx.post",
        "httpx.request",
        "requests.get",
        "requests.post",
    }
    SCOPES: ClassVar[list] = [
        "backend/services/scanner",
        "backend/services/discovery",
        "backend/services/verification",
        "backend/services/alerts",
        "backend/scanner_modules",
        "backend/tasks",
    ]

    def test_no_bypass(self):
        import ast
        from pathlib import Path

        root = Path(__file__).resolve().parents[3]
        violations = []
        for scope in self.SCOPES:
            for path in sorted((root / scope).rglob("*.py")):
                tree = ast.parse(path.read_text())
                used = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                        used.add(f"{node.value.id}.{node.attr}")
                denied = used & self.DENY
                rel = str(path.relative_to(root))
                allowed = self.ALLOW.get(rel, set())
                unexpected = {u for u in denied if u not in allowed}
                if unexpected:
                    violations.append(f"{rel}: {sorted(unexpected)}")
        assert not violations, (
            "Direct network calls outside utils.egress:\n" + "\n".join(violations)
        )
