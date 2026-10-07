"""Task 1.3 A.3: SNI + certificate verification through the IP-rewritten path.

Spins a real local TLS server (127.0.0.1) with an openssl-minted CA +
server certificate, then proves:
  (a) a certificate valid for a DIFFERENT hostname fails the connection;
  (b) the right hostname succeeds through the validated-IP path, with the
      Host header pinned to the original name.

``ssl_scanner.analyze_ssl`` performs no network I/O of its own (proven by
the anti-bypass test); all of its TLS goes through ``connect_tls_socket``,
covered below. Routing validation is bypassed on purpose here (resolve
mocked to 127.0.0.1): the routing layer is covered by the abuse table.
Trust is injected via SSL_CERT_FILE, honored by default contexts at call
time. No external network access.
"""

import shutil
import socket as real_socket
import ssl as stdlib_ssl
import subprocess
import threading

import pytest

from utils.egress import connect_tls_socket, fetch_url_validated


def _openssl(*args, cwd):
    subprocess.run(
        ["openssl", *args], cwd=cwd, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


@pytest.fixture()
def tls_server(tmp_path, monkeypatch):
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI required for TLS tests")
    anchor = tmp_path / "pki"
    anchor.mkdir()
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-keyout", "ca.key",
             "-out", "ca.pem", "-days", "2", "-nodes", "-subj", "/CN=TestCA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
             cwd=str(anchor))
    _openssl("req", "-newkey", "rsa:2048", "-keyout", "srv.key",
             "-out", "srv.csr", "-nodes", "-subj", "/CN=right.example",
             cwd=str(anchor))
    (anchor / "ext.cnf").write_text("subjectAltName=DNS:right.example\n")
    _openssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem",
             "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.pem",
             "-days", "2", "-extfile", "ext.cnf", cwd=str(anchor))

    monkeypatch.setenv("SSL_CERT_FILE", str(anchor / "ca.pem"))
    # Routing is bypassed: every name resolves to the local test server.
    monkeypatch.setattr(
        "utils.egress.resolve_validated_ips", lambda host, port=80: ["127.0.0.1"]
    )

    received = []
    stop = threading.Event()
    server_ctx = stdlib_ssl.SSLContext(stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(anchor / "srv.pem"), str(anchor / "srv.key"))

    listener = real_socket.socket(real_socket.AF_INET, real_socket.SOCK_STREAM)
    listener.setsockopt(real_socket.SOL_SOCKET, real_socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.5)
    port = listener.getsockname()[1]

    def serve():
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except real_socket.timeout:
                continue
            try:
                with server_ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(5)
                    try:
                        data = tls.recv(65536)
                    except Exception:
                        data = b""
                    received.append(data)
                    body = b"verified-body"
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                        b"Connection: close\r\n\r\n" % len(body) + body
                    )
            except Exception:
                pass
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield {"port": port, "received": received}
    stop.set()
    thread.join(timeout=10)


def _aio(coro):
    import asyncio
    return asyncio.run(coro)


async def _dial(hostname, port):
    import asyncio

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: connect_tls_socket(hostname, port, server_hostname=hostname),
    )


class TestConnectTlsSocket:
    def test_wrong_hostname_fails(self, tls_server):
        with pytest.raises(stdlib_ssl.SSLError):
            _aio(_dial("wrong.example", tls_server["port"]))

    def test_right_hostname_succeeds(self, tls_server):
        sock = _aio(_dial("right.example", tls_server["port"]))
        try:
            cert = sock.getpeercert()
            sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
            assert "right.example" in sans
        finally:
            sock.close()


class TestFetchHttps:
    def test_wrong_hostname_fails(self, tls_server):
        with pytest.raises(Exception, match="(?i)certificate|ssl|verify"):
            _aio(fetch_url_validated(
                f"https://wrong.example:{tls_server['port']}/"))

    def test_right_hostname_succeeds_with_pinned_host(self, tls_server):
        result = _aio(fetch_url_validated(
            f"https://right.example:{tls_server['port']}/.well-known/x"))
        assert result.status_code == 200
        assert result.body == b"verified-body"
        # Origin-form request line carries no host; Host header pins the name.
        raw = tls_server["received"][-1]
        assert b"Host: right.example" in raw
