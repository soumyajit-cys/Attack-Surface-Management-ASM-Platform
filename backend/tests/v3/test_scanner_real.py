"""Scanner-service coverage against REAL local TLS/TCP servers.

The servers here follow the pattern of ``test_egress_tls.py``: loopback
listeners, certificates minted with the pinned ``cryptography`` library,
and trust injected via ``SSL_CERT_FILE`` (honored by default contexts at
call time).

TEST-ONLY SEAM (shown explicitly, required by the batch brief):
production routing is NOT weakened. The SSRF/egress guard still runs on
every socket made through ``utils.egress``; two things are injected, and
only at the seam points the modules already delegate to:

1. ``utils.egress.resolve_validated_ips`` → ``["127.0.0.1"]`` — the same
   seam ``test_egress_tls.py`` uses; the validation function itself is
   covered by the abuse suite, here it is merely aimed at loopback.
2. the hard-coded production port (443) is routed to the ephemeral test
   listener by mirroring the module's own ``connect_tls_socket`` import.

DNS/WHOIS/crt.sh have no embeddable local server, so their transports are
stubbed at the import boundary (``dns.resolver.resolve``,
``socket.getaddrinfo``, ``utils.egress.fetch_url_validated``); malformed
responses and failures go through the real parsing code.
"""

from __future__ import annotations

import asyncio
import socket as real_socket
import ssl as stdlib_ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from utils.egress import (
    FetchResult,
    connect_tls_socket as _egress_connect,
    fetch_url_validated,
)


def _run(coro):
    return asyncio.run(coro)


# ══ The two test-only seams ═══════════════════════════════════════════════════


@pytest.fixture()
def loopback_seam(monkeypatch):
    """Aim the egress resolver at loopback (same seam as test_egress_tls)."""
    monkeypatch.setattr(
        "utils.egress.resolve_validated_ips", lambda host, port=80: ["127.0.0.1"]
    )
    return monkeypatch


def _mirror_port(monkeypatch, module, test_port):
    """Route a module's hard-coded 443 to the ephemeral listener.

    The module calls ``connect_tls_socket(host, 443, ...)``; tests cannot
    bind 443, so the import inside *module* is mirrored onto the real
    egress helper with the listener port. IP validation, TLS verification
    and host pinning all run the production path unchanged.
    """
    monkeypatch.setattr(
        module,
        "connect_tls_socket",
        lambda host, port, server_hostname=None, verified=True, **kw:
        _egress_connect(host, test_port,
                        server_hostname=server_hostname or host,
                        verified=verified, **kw),
    )


# ══ Certificate minting ═══════════════════════════════════════════════════════


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _build_cert(key, subject: str, issuer_key, issuer_name: x509.Name, *,
                not_before: datetime, not_after: datetime,
                is_ca: bool = False) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(microsecond=0))
        .not_valid_after(not_after.replace(microsecond=0))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject)]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture()
def pki(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _build_cert(ca_key, "FixtureCA", ca_key, _name("FixtureCA"),
                          not_before=now - timedelta(days=2),
                          not_after=now + timedelta(days=2), is_ca=True)
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    return {
        "anchor_pem": ca_cert.public_bytes(serialization.Encoding.PEM),
        "valid": (srv_key, _build_cert(
            srv_key, "right.example", ca_key, ca_cert.subject,
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=30))),
        "expired": (srv_key, _build_cert(
            srv_key, "right.example", ca_key, ca_cert.subject,
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1))),
        "selfsigned_key": rsa.generate_private_key(
            public_exponent=65537, key_size=2048),
        "selfsigned": _name("right.example"),
    }


class _Listener:
    """Loopback TLS/TCP server in a thread with a canned behaviour.

    TLS enabled when *key*/*cert* are given (cert chains are built to temp
    PEM files); otherwise plain TCP. Modes: raw HTTP ``response`` bytes,
    immediate ``banner`` bytes, or ``silent`` (send nothing at all).
    """

    def __init__(self, key=None, cert=None, *, response=None, silent=False,
                 banner=None, tls_min_max=None):
        self.received: list[bytes] = []
        self.response = response
        self.silent = silent
        self.banner = banner
        self.cert_key = key

        self._ctx = None
        if key is not None:
            self._ctx = stdlib_ssl.SSLContext(stdlib_ssl.PROTOCOL_TLS_SERVER)
            if tls_min_max is not None:
                self._ctx.minimum_version, self._ctx.maximum_version = tls_min_max
            self._chain_files = self._write_chain(key, cert)

        listener = real_socket.socket(real_socket.AF_INET,
                                      real_socket.SOCK_STREAM)
        listener.setsockopt(real_socket.SOL_SOCKET, real_socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(32)
        listener.settimeout(0.2)
        self.port = listener.getsockname()[1]
        self._listener = listener
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _write_chain(key, cert):
        with tempfile.NamedTemporaryFile(delete=False,
                                         suffix=".pem") as cert_f:
            cert_f.write(cert.public_bytes(serialization.Encoding.PEM))
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_f:
            key_f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalPKCS,
                serialization.NoEncryption(),
            ))
        return cert_f.name, key_f.name

    def _serve(self):
        if self._ctx is not None:
            cert_path, key_path = self._chain_files
            self._ctx.load_cert_chain(cert_path, key_path)
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except real_socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(raw)
            except Exception:
                try:
                    raw.close()
                except OSError:
                    pass
        self._listener.close()

    def _handle(self, raw):
        if self._ctx is not None:
            raw = self._ctx.wrap_socket(raw, server_side=True)
        raw.settimeout(3)
        try:
            self.received.append(raw.recv(65536))
        except Exception:
            pass
        if self.banner is not None:
            raw.sendall(self.banner)
        elif not self.silent:
            raw.sendall(self.response or (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nhi"))
        raw.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=5)


# ══ ssl_scanner ═══════════════════════════════════════════════════════════════


class TestSSLScannerRealServer:
    def test_valid_cert_parses_low_risk(self, pki, loopback_seam):
        from services.scanner import ssl_scanner as ss

        srv_key, valid = pki["valid"]
        with _Listener(srv_key, valid) as srv:
            _mirror_port(loopback_seam, ss, srv.port)
            result = _run(ss.analyze_ssl("right.example"))

        assert result is not None
        assert result["host"] == "right.example"
        assert result["expired"] is False and result["self_signed"] is False
        assert result["risk_level"] == "low"
        assert "CN=right.example" in result["subject"]
        assert result["san"] == ["right.example"]
        assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
        assert result["cipher"] is not None
        assert result["expires_soon"] is False  # valid for 30 days

    def test_expired_cert_falls_back_and_flags_critical(self, pki,
                                                        loopback_seam):
        from services.scanner import ssl_scanner as ss

        srv_key, expired = pki["expired"]
        with _Listener(srv_key, expired) as srv:
            _mirror_port(loopback_seam, ss, srv.port)
            result = _run(ss.analyze_ssl("right.example"))

        assert result is not None
        assert result["expired"] is True
        assert result["risk_level"] == "critical"
        # the verification failure is recorded, never silent
        assert isinstance(result.get("verify_error"), str)

    def test_self_signed_cert_flags_critical(self, pki, loopback_seam):
        from services.scanner import ssl_scanner as ss

        with _Listener(pki["selfsigned_key"], pki["selfsigned"]) as srv:
            _mirror_port(loopback_seam, ss, srv.port)
            result = _run(ss.analyze_ssl("right.example"))

        assert result is not None
        assert result["self_signed"] is True
        assert result["risk_level"] == "critical"

    def test_no_listener_returns_none(self, loopback_seam):
        from services.scanner import ssl_scanner as ss

        _mirror_port(loopback_seam, ss, 1)  # tcp/1: nothing listens locally
        assert _run(ss.analyze_ssl("right.example")) is None

    def test_old_protocol_version_is_high_risk(self):
        from services.scanner.ssl_scanner import _calculate_risk_level

        # TLS version branch (no old-protocol server can be started on
        # modern openssl, so this is asserted at the decision function).
        assert _calculate_risk_level(False, False, False, "TLSv1") == "high"
        assert _calculate_risk_level(False, False, False, "SSLv3") == "high"
        assert _calculate_risk_level(False, True, False, "TLSv1.3") == "high"
        assert _calculate_risk_level(False, False, False, "TLSv1.3") == "low"

    def test_forced_tls12_negotiation(self, pki, loopback_seam):
        from services.scanner import ssl_scanner as ss

        srv_key, valid = pki["valid"]
        with _Listener(srv_key, valid,
                       tls_min_max=(stdlib_ssl.TLSVersion.TLSv1_2,
                                    stdlib_ssl.TLSVersion.TLSv1_2)) as srv:
            _mirror_port(loopback_seam, ss, srv.port)
            result = _run(ss.analyze_ssl("right.example"))

        assert result["tls_version"] == "TLSv1.2"
        assert result["cipher_version"] in ("TLSv1.2", "TLSv1.3")


# ══ port_scanner ══════════════════════════════════════════════════════════════


@pytest.fixture()
def socket_sweep(monkeypatch):
    """Force the socket sweep path (naabu absent) so TESTS are hermetic."""
    monkeypatch.setattr("services.scanner.port_scanner.shutil.which",
                        lambda *a, **k: None)
    return monkeypatch


class TestPortScannerRealSockets:
    def test_open_closed_and_banner(self, pki, loopback_seam, socket_sweep):
        from services.scanner import port_scanner as ps

        with _Listener(banner=b"fixture-sshd-2.0\r\n") as srv:
            # Banner policy from the live port (TEST-ONLY: the production
            # constant stays in place for every other port).
            socket_sweep.setattr(ps, "BANNER_PORTS", frozenset({srv.port}))
            results = _run(ps.scan_ports("scanme.example"))
            by_port = {r["port"]: r for r in results}

            open_row = by_port[srv.port]
            assert open_row["status"] == "open"
            assert open_row["protocol"] == "tcp"
            assert open_row["service"] is None  # ephemeral port not mapped
            assert open_row["banner"] == "fixture-sshd-2.0"
            # every COMMON port reported exactly once; closed ports too
            assert len(results) == len(ps.COMMON_PORTS)
            assert by_port.get(23, {}).get("status") == "closed"

    def test_open_silent_port_has_no_banner(self, loopback_seam, socket_sweep):
        from services.scanner import port_scanner as ps

        with _Listener(silent=True) as srv:
            socket_sweep.setattr(ps, "BANNER_PORTS", frozenset({srv.port}))
            results = _run(ps.scan_ports("quiet.example"))
            by_port = {r["port"]: r for r in results}

            assert by_port[srv.port]["status"] == "open"
            assert by_port[srv.port]["banner"] is None  # graceful timeout

    def test_egress_blocked_propagates(self, loopback_seam):
        from services.scanner import port_scanner as ps
        from utils.egress import EgressBlocked

        def _blocked(host, port=80):
            raise EgressBlocked("fail-closed")

        loopback_seam.setattr(ps, "resolve_validated_ips", _blocked)
        with pytest.raises(EgressBlocked):
            _run(ps.scan_ports("blocked.example"))

    def test_naabu_json_parsing_and_malformed_lines(self, monkeypatch):
        from services.scanner import port_scanner as ps

        class _Proc:
            returncode = 0

            async def communicate(self):
                out = (
                    '{"port": 443, "host": "1.2.3.4"}\n'
                    "not-json-at-all\n"
                    '{"port": 22}\n'
                    '{"no_port_field": true}\n'
                )
                return out.encode(), b""

        async def _fake_exec(*args, **kwargs):
            return _Proc()

        monkeypatch.setattr("services.scanner.port_scanner.shutil.which",
                            lambda *a, **k: "/usr/bin/naabu")
        monkeypatch.setattr("services.scanner.port_scanner.asyncio."
                            "create_subprocess_exec", _fake_exec)

        results = _run(ps._naabu_scan("1.2.3.4"))
        assert results == [
            {"port": 443, "status": "open", "protocol": "tcp",
             "service": "https"},
            {"port": 22, "status": "open", "protocol": "tcp",
             "service": "ssh"},
        ]


# ══ header_scanner ════════════════════════════════════════════════════════════

_DISABLED_HEADERS_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: FixtureServer/1.0\r\n"
    b"X-Powered-By: FixtureExpress\r\n"
    b"Strict-Transport-Security: max-age=3600\r\n"
    b"Content-Length: 2\r\nConnection: close\r\n\r\nhi"
)


class TestHeaderScannerRealServer:
    def test_real_https_headers_produce_findings(self, pki, loopback_seam):
        from services.scanner import header_scanner as hs

        srv_key, valid = pki["valid"]

        def fake_fetch(url, **kw):
            assert url.startswith("https://"), url
            return fetch_url_validated(url, **kw)

        with _Listener(srv_key, valid,
                       response=_DISABLED_HEADERS_RESPONSE) as srv:
            loopback_seam.setenv("SSL_CERT_FILE", self := None)  # marker only

        # Rerun with trust: SSL_CERT_FILE is read at connect time via the
        # default context, so we rebuild the listener inside the env patch.
        loopback_seam2 = loopback_seam
        with _Listener(srv_key, valid,
                       response=_DISABLED_HEADERS_RESPONSE) as srv:
            loopback_seam2.setenv("SSL_CERT_FILE", pki["anchor_pem"]
                                  and _write_anchor(pki))
            findings = _run(hs.analyze_headers(
                f"https://right.example:{srv.port}/"))

        titles = {f["title"] for f in findings}
        assert "Missing CSP Header" in titles
        assert "Missing X-Frame-Options Header" in titles
        assert ("Information Disclosure: Server Header") in titles
        assert ("Information Disclosure: X-Powered-By Header") in titles
        assert "Missing HSTS Header" in titles  # HSTS was present-but-weak? no:
        # strict-transport-security present with max-age=3600 → too-low
        # finding instead of the "missing" one.
        assert "HSTS Max-Age Too Low" in titles

    def test_self_signed_downgrades_and_records_finding(
            self, pki, loopback_seam):
        from services.scanner import header_scanner as hs

        with _Listener(pki["selfsigned_key"], pki["selfsigned"],
                       response=_DISABLED_HEADERS_RESPONSE) as srv:
            findings = _run(hs.analyze_headers(
                f"https://right.example:{srv.port}/"))

        titles = [f["title"] for f in findings]
        assert "Invalid TLS certificate" in titles, (
            "self-signed cert must downgrade via verify_tls=False and record "
            "the finding (the first attempt hits the real verification path)"
        )
        # the retry is unverified but headers were still read
        assert "Missing CSP Header" in titles

    def test_silent_server_yields_empty(self, pki, loopback_seam):
        from services.scanner import header_scanner as hs

        with _Listener(pki["selfsigned_key"], pki["selfsigned"],
                       silent=True) as srv:
            findings = _run(hs.analyze_headers(
                f"https://right.example:{srv.port}/"))
        # both attempts (verified + unverified) get garbage/silence → no find.
        assert findings == []


def _write_anchor(pki) -> str:
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(pki["anchor_pem"])
        return f.name


# ══ dns_service ═══════════════════════════════════════════════════════════════


class TestDNSService:
    def test_records_and_failures(self, monkeypatch):
        from services.discovery import dns_service as ds

        import dns.resolver

        def fake_resolve(name, rtype):
            if rtype == "A":
                return ["93.184.216.34", "93.184.216.35"]
            if rtype == "TXT":
                return ['"v=spf1 -all"']
            raise Exception("NXDOMAIN")

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        results = _run(ds.enumerate_dns("demo-corp.example"))

        a_rows = [r for r in results if r["type"] == "A"]
        txt_rows = [r for r in results if r["type"] == "TXT"]
        assert a_rows == [
            {"type": "A", "value": "93.184.216.34"},
            {"type": "A", "value": "93.184.216.35"},
        ]
        assert txt_rows == [{"type": "TXT", "value": '"v=spf1 -all"'}]
        assert all(r["type"] in ("A", "TXT") for r in results), (
            "failing record types must be skipped, not raised"
        )


# ══ subdomain_service ═════════════════════════════════════════════════════════


class TestSubdomainService:
    def test_crt_sh_parsing(self, monkeypatch):
        import json

        from services.discovery import subdomain_service as ssd

        body = json.dumps([
            {"name_value": "www.demo-corp.example\n*.demo-corp.example\n"},
            {"name_value": "API.demo-corp.example."},
            {"no_name": True},
        ]).encode()

        async def fake_fetch(url, **kw):
            return FetchResult(status_code=200, headers={}, body=body)

        monkeypatch.setattr("utils.egress.fetch_url_validated", fake_fetch)
        subs = _run(ssd._crt_sh_discovery("demo-corp.example"))

        assert "www.demo-corp.example" in subs
        assert "api.demo-corp.example" in subs  # lowercased, trailing dot gone
        assert not any("*" in s for s in subs)

    def test_crt_sh_malformed_json_yields_empty(self, monkeypatch):
        from services.discovery import subdomain_service as ssd

        async def fake_fetch(url, **kw):
            return FetchResult(status_code=200, headers={}, body=b"{nope")

        monkeypatch.setattr("utils.egress.fetch_url_validated", fake_fetch)
        assert _run(ssd._crt_sh_discovery("demo-corp.example")) == []

    def test_crt_sh_http_error_yields_empty(self, monkeypatch):
        from services.discovery import subdomain_service as ssd

        async def fake_fetch(url, **kw):
            return FetchResult(status_code=503, headers={}, body=b"")

        monkeypatch.setattr("utils.egress.fetch_url_validated", fake_fetch)
        assert _run(ssd._crt_sh_discovery("demo-corp.example")) == []

    def test_discover_subdomains_combines_sources(self, monkeypatch):
        import json
        import socket as sock

        from services.discovery import subdomain_service as ssd

        async def fake_fetch(url, **kw):
            return FetchResult(status_code=200, headers={}, body=json.dumps([
                {"name_value": "wiki.demo-corp.example"},
            ]).encode())

        monkeypatch.setattr("utils.egress.fetch_url_validated", fake_fetch)

        def fake_gethostbyname(name):
            if name.startswith(("www.", "api.")):
                return "93.184.216.34"
            raise OSError("does not resolve")

        monkeypatch.setattr(sock, "gethostbyname", fake_gethostbyname)
        result = _run(ssd.discover_subdomains("demo-corp.example"))

        by_sub = {r["subdomain"]: r["source"] for r in result}
        assert by_sub["wiki.demo-corp.example"] == "crt.sh"
        assert by_sub["www.demo-corp.example"] == "dns_brute"
        assert by_sub["api.demo-corp.example"] == "dns_brute"

    def test_resolve_subdomain_ips_filters_guarded(self, monkeypatch):
        import socket as sock

        from services.discovery import subdomain_service as ssd

        addrs = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("10.20.30.40", 0)),   # RFC1918 → guarded out
            (2, 1, 6, "", ("127.0.0.1", 0)),     # loopback → guarded out
        ]
        monkeypatch.setattr(sock, "getaddrinfo", lambda *a, **k: addrs)
        ips = _run(ssd.resolve_subdomain_ips("www.demo-corp.example"))

        assert "93.184.216.34" in ips
        assert "10.20.30.40" not in ips and "127.0.0.1" not in ips

    def test_resolve_subdomain_ips_failure_returns_empty(self, monkeypatch):
        import socket as sock

        from services.discovery import subdomain_service as ssd

        def boom(*a, **k):
            raise OSError("resolver down")

        monkeypatch.setattr(sock, "getaddrinfo", boom)
        assert _run(ssd.resolve_subdomain_ips("x.example")) == []


# ══ whois_service ═════════════════════════════════════════════════════════════


class TestWhoisService:
    def test_success_mapping(self, monkeypatch):
        from services.discovery import whois_service as ws

        class _Data:
            registrar = "Fixture Registrar LLC"
            creation_date = datetime(2020, 1, 2, 3, 4, 5)

        monkeypatch.setattr(ws.whois, "whois", lambda d: _Data())
        result = _run(ws.get_whois("demo-corp.example"))

        assert result["registrar"] == "Fixture Registrar LLC"
        assert "2020-01-02" in result["creation_date"]

    def test_failure_returns_placeholders(self, monkeypatch):
        from services.discovery import whois_service as ws

        def boom(domain):
            raise Exception("whois server down")

        monkeypatch.setattr(ws.whois, "whois", boom)
        result = _run(ws.get_whois("demo-corp.example"))

        assert result == {"registrar": None, "creation_date": None,
                          "asn": None}
