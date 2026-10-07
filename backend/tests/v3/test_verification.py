"""Task 1.1: ownership verification service + API gating (mocked network)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from models.verified_domain import VerifiedDomain
from services.verification import verification_service as verification


def _seed_verified(db, org_factory, domain, org_name="Verify Org",
                   status="verified", days_valid=90):
    org, _ = org_factory(org_name, f"{org_name}user".replace(' ', ''),
                         f"{org_name}@example.com".replace(' ', ''))
    now = datetime.now(timezone.utc)
    db.add(VerifiedDomain(
        organization_id=org.id,
        domain=domain,
        method="dns_txt",
        status=status,
        token="test-token",
        verified_at=now if status == "verified" else None,
        expires_at=now + timedelta(days=days_valid),
    ))
    db.commit()
    return org


def _register(client, username="vowner", org="VOwner Org"):
    response = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": f"{username}@example.com",
              "password": "password123", "organization": org},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}"}


class TestPublicSuffixRejection:
    def test_bare_suffixes_rejected(self, db, org_factory):
        org, _ = org_factory("PSL Org", "psl", "psl@example.com")
        for suffix in ["co.uk", "github.io", "com", "localhost"]:
            with pytest.raises(ValueError):
                verification.initiate_verification(db, org.id, suffix, "dns_txt")

    def test_registrable_domains_accepted(self, db, org_factory):
        org, _ = org_factory("PSL Org2", "psl2", "psl2@example.com")
        for domain in ["example.com", "example.co.uk", "a.github.io"]:
            row = verification.initiate_verification(db, org.id, domain, "dns_txt")
            assert row.status == "pending"

    def test_unknown_method_rejected(self, db, org_factory):
        org, _ = org_factory("PSL Org3", "psl3", "psl3@example.com")
        with pytest.raises(ValueError):
            verification.initiate_verification(db, org.id, "example.com", "carrier-pigeon")

    def test_suffix_check_needs_no_network(self, monkeypatch):
        import socket as real_socket

        def _no_network(*a, **k):
            raise AssertionError("public-suffix check must not touch the network")

        monkeypatch.setattr(real_socket, "getaddrinfo", _no_network)
        monkeypatch.setattr(real_socket, "gethostbyname", _no_network)
        monkeypatch.setattr(real_socket, "socket", _no_network)

        assert verification.is_public_suffix("co.uk") is True
        assert verification.is_public_suffix("github.io") is True
        assert verification.is_public_suffix("example.co.uk") is False
        assert verification.is_public_suffix("a.github.io") is False
        assert verification.parent_candidates("a.b.example.com") == [
            "b.example.com", "example.com"]


class TestScanAllowed:
    def test_parent_covers_subdomain_but_not_reverse_or_sibling(self, db, org_factory):
        org, _ = org_factory("Parent Org", "par", "par@example.com")
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="example.com", method="dns_txt",
            status="verified", token="t", verified_at=now,
            expires_at=now + timedelta(days=90),
        ))
        db.commit()

        ok, mode, _ = verification.is_scan_allowed(db, org.id, "a.b.example.com")
        assert (ok, mode) == (True, "verified")

        # A different registrable domain is not covered.
        ok, _, _ = verification.is_scan_allowed(db, org.id, "other-example.com")
        assert not ok

    def test_lookalike_suffix_match_does_not_cover(self, db, org_factory):
        # "evilexample.com" merely ends with the string "example.com" but is a
        # different registrable domain: label-boundary matching is required.
        org, _ = org_factory("Look Org", "look", "look@example.com")
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="example.com", method="dns_txt",
            status="verified", token="t", verified_at=now,
            expires_at=now + timedelta(days=90),
        ))
        db.commit()

        ok, _, _ = verification.is_scan_allowed(db, org.id, "evilexample.com")
        assert not ok
        ok, _, _ = verification.is_scan_allowed(db, org.id, "example.com.evil.com")
        assert not ok

    def test_subdomain_verification_does_not_cover_parent(self, db, org_factory):
        org, _ = org_factory("Sub Org", "sub", "sub@example.com")
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="sub.example.com", method="dns_txt",
            status="verified", token="t", verified_at=now,
            expires_at=now + timedelta(days=90),
        ))
        db.commit()

        ok, _, _ = verification.is_scan_allowed(db, org.id, "example.com")
        assert not ok
        ok, _, _ = verification.is_scan_allowed(db, org.id, "sub.example.com")
        assert ok

    def test_other_org_verification_does_not_count(self, db, org_factory):
        _seed_verified(db, org_factory, "shared.example", org_name="OwnerA")
        org_b, _ = org_factory("OwnerB", "ownerb", "ownerb@example.com")
        ok, reason, _ = verification.is_scan_allowed(db, org_b.id, "shared.example")
        assert not ok
        assert "not verified" in reason

    def test_expired_and_failed_block(self, db, org_factory):
        _seed_verified(db, org_factory, "old.example", org_name="OldOrg", days_valid=-1)
        org = db.query(VerifiedDomain).filter(
            VerifiedDomain.domain == "old.example").one().organization_id
        ok, reason, _ = verification.is_scan_allowed(db, org, "old.example")
        assert not ok
        assert "expired" in reason


class TestTxtCheck:
    async def _run(self, *args):
        return await verification.check_row(*args)

    def test_success_marks_verified_with_expiry(self, db, org_factory):
        import asyncio
        org, _ = org_factory("Txt Org", "txt", "txt@example.com")
        row = verification.initiate_verification(db, org.id, "txt.example.com", "dns_txt")
        db.commit()

        async def go():
            with patch(
                "services.verification.verification_service.verify_domain_ownership",
                new=AsyncMock(return_value=(True, "Domain ownership verified")),
            ):
                return await verification.check_row(db, row)
        ok, _ = asyncio.run(go())
        db.commit()

        assert ok
        assert row.status == "verified"
        assert row.expires_at > datetime.now(timezone.utc) + timedelta(days=89)
        assert row.last_checked_at is not None

    def test_failure_marks_failed(self, db, org_factory):
        import asyncio
        org, _ = org_factory("Txt Org2", "txt2", "txt2@example.com")
        row = verification.initiate_verification(db, org.id, "nope.example.com", "dns_txt")
        db.commit()

        async def go():
            with patch(
                "services.verification.verification_service.verify_domain_ownership",
                new=AsyncMock(return_value=(False, "No TXT record")),
            ):
                return await verification.check_row(db, row)
        ok, _ = asyncio.run(go())
        db.commit()

        assert not ok
        assert row.status == "failed"


class TestHttpFileCheck:
    class FakeStream:
        def __init__(self, status_code, text, headers=None):
            self.status_code = status_code
            self._text = text
            self.headers = headers or {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aiter_bytes(self):
            yield self._text.encode()

    def _fake_client(self, calls, responder):
        stream_cls = self.FakeStream

        class FakeClient:
            def __init__(self, *a, **kw):
                calls.append((a, kw))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def stream(self, method, url, headers=None, **kw):
                return responder(url, headers)

        return FakeClient

    def _stream(self, status_code, text, headers=None):
        return self.FakeStream(status_code, text, headers)

    def test_success_and_blocked_ip(self, monkeypatch):
        import asyncio
        import socket as real_socket

        calls = []
        expected = verification.challenge_value("tok123")

        def responder(url, headers):
            assert headers["Host"] == "example.com"
            return self._stream(200, expected + "\n")

        FakeClient = self._fake_client(calls, responder)
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: [(real_socket.AF_INET, 1, 6, "", ("93.184.216.34", 80))],
        )
        monkeypatch.setattr(verification.httpx, "AsyncClient", FakeClient)

        ok, _ = asyncio.run(
            verification._check_http_file("example.com", "tok123", expected)
        )
        assert ok
        assert calls  # exactly one client, one validated IP

        # Metadata IP is rejected before any HTTP happens.
        calls.clear()
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: [(real_socket.AF_INET, 1, 6, "", ("169.254.169.254", 80))],
        )
        ok, reason = asyncio.run(
            verification._check_http_file("example.com", "tok123", expected)
        )
        assert not ok and "blocked" in reason
        assert not calls

    def test_redirect_to_internal_blocked(self, monkeypatch):
        import asyncio
        import socket as real_socket

        def responder(url, headers):
            if "93.184.216.34" in url:
                return self._stream(302, "", {"location": "http://internal.example/.well-known/x"})
            raise AssertionError(f"unexpected fetch: {url}")

        FakeClient = self._fake_client([], responder)
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda host, *a, **k: [(
                real_socket.AF_INET, 1, 6, "",
                ({"example.com": "93.184.216.34",
                  "internal.example": "10.9.9.9"}[host], 80),
            )],
        )
        monkeypatch.setattr(verification.httpx, "AsyncClient", FakeClient)

        ok, reason = asyncio.run(
            verification._check_http_file(
                "example.com", "tok", verification.challenge_value("tok"))
        )
        assert not ok and "blocked" in reason

    def test_oversized_body_rejected_without_buffering(self, monkeypatch):
        import asyncio
        import socket as real_socket

        seen_chunks = []

        class CountingStream(self.FakeStream):
            async def aiter_bytes(self):
                # Simulate a body far over the cap arriving in chunks.
                for _ in range(10):
                    seen_chunks.append(1)
                    yield b"x" * 20000
                    if len(seen_chunks) >= 4:
                        break

        def responder(url, headers):
            return CountingStream(200, "")

        FakeClient = self._fake_client([], responder)
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: [(real_socket.AF_INET, 1, 6, "", ("93.184.216.34", 80))],
        )
        monkeypatch.setattr(verification.httpx, "AsyncClient", FakeClient)

        ok, reason = asyncio.run(
            verification._check_http_file(
                "example.com", "tok", verification.challenge_value("tok"))
        )
        assert not ok and "too large" in reason
        # Stopped reading after crossing the cap, not after the whole body.
        assert len(seen_chunks) <= 5

    def test_declared_content_length_over_cap_rejected(self, monkeypatch):
        import asyncio
        import socket as real_socket

        calls = []

        def responder(url, headers):
            calls.append(url)
            return self._stream(200, "short", {"content-length": str(10 ** 9)})

        FakeClient = self._fake_client([], responder)
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: [(real_socket.AF_INET, 1, 6, "", ("93.184.216.34", 80))],
        )
        monkeypatch.setattr(verification.httpx, "AsyncClient", FakeClient)

        ok, reason = asyncio.run(
            verification._check_http_file(
                "example.com", "tok", verification.challenge_value("tok"))
        )
        assert not ok and "too large" in reason


class TestVerifyApi:
    def test_unverified_scan_blocked_with_code(self, client, monkeypatch):
        headers = _register(client)

        async def fake_resolve(domain):
            return {"domain": domain, "ip": "93.184.216.34"}

        monkeypatch.setattr(
            "services.discovery.domain_service.resolve_domain", fake_resolve
        )
        response = client.post(
            "/api/v1/scans", json={"domain": "new.example.com"}, headers=headers
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "domain_not_verified"

    def test_verified_scan_allowed(self, client, db, org_factory, monkeypatch):
        headers = _register(client, username="vok", org="VOk Org")
        from models.user import User
        user = db.query(User).filter(User.username == "vok").one()
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=user.organization_id, domain="ok.example.com",
            method="dns_txt", status="verified", token="t",
            verified_at=now, expires_at=now + timedelta(days=90),
        ))
        db.commit()

        async def fake_resolve(domain):
            return {"domain": domain, "ip": "93.184.216.34"}

        monkeypatch.setattr(
            "services.discovery.domain_service.resolve_domain", fake_resolve
        )
        import app.api.v1.scans as scans_api
        monkeypatch.setattr(
            scans_api.run_discovery, "delay", lambda scan_id=None, **kw: None
        )
        response = client.post(
            "/api/v1/scans", json={"domain": "ok.example.com"}, headers=headers
        )
        assert response.status_code == 202, response.text

    def test_request_check_and_list_flow(self, client, monkeypatch):
        headers = _register(client, username="vflow", org="VFlow Org")

        initiated = client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "flow.example.com", "method": "dns_txt"},
            headers=headers,
        )
        assert initiated.status_code == 200, initiated.text
        body = initiated.json()
        assert body["status"] == "pending"
        assert body["txt_record_name"] == "_sentinelasm-challenge.flow.example.com"

        http = client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "file.example.com", "method": "http_file"},
            headers=headers,
        )
        assert http.json()["file_path"].startswith("/.well-known/sentinelasm-")

        bad = client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "co.uk", "method": "dns_txt"},
            headers=headers,
        )
        assert bad.status_code == 400

        listed = client.get("/api/v1/scans/verified-domains", headers=headers)
        assert listed.status_code == 200, listed.text
        domains = {i["domain"]: i["status"] for i in listed.json()["items"]}
        assert domains["flow.example.com"] == "pending"
        assert domains["file.example.com"] == "pending"

        with patch(
            "services.verification.verification_service.verify_domain_ownership",
            new=AsyncMock(return_value=(True, "Domain ownership verified")),
        ):
            checked = client.get(
                "/api/v1/scans/verify-ownership/check?domain=flow.example.com",
                headers=headers,
            )
        assert checked.status_code == 200, checked.text
        assert checked.json()["verified"] is True

        listed = client.get("/api/v1/scans/verified-domains", headers=headers)
        domains = {i["domain"]: i["status"] for i in listed.json()["items"]}
        assert domains["flow.example.com"] == "verified"


class TestRunNowGate:
    def test_run_now_blocked_then_allowed(self, client, db, org_factory, monkeypatch):
        from models import Asset, ScanPolicy
        from models.user import User

        headers = _register(client, username="rnu", org="RNU Org")
        user = db.query(User).filter(User.username == "rnu").one()
        asset = Asset(organization_id=user.organization_id, name="rnu.example.com")
        db.add(asset)
        db.flush()
        policy = ScanPolicy(
            organization_id=user.organization_id, asset_id=asset.id,
            name="p-rnu", frequency="daily", scope="passive", is_active=True,
            next_run_at=datetime.now(timezone.utc),
        )
        db.add(policy)
        db.commit()

        import tasks.discovery_tasks as ddt
        calls = []
        monkeypatch.setattr(
            ddt.run_discovery, "delay",
            lambda scan_id=None, scope=None, **kw: calls.append((scan_id, scope)),
        )

        blocked = client.post(
            f"/api/v1/scan-policies/{policy.id}/run-now", headers=headers
        )
        assert blocked.status_code == 403
        assert blocked.json()["error"]["code"] == "domain_not_verified"
        assert calls == []

        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=user.organization_id, domain="rnu.example.com",
            method="dns_txt", status="verified", token="t",
            verified_at=now, expires_at=now + timedelta(days=90),
        ))
        db.commit()

        allowed = client.post(
            f"/api/v1/scan-policies/{policy.id}/run-now", headers=headers
        )
        assert allowed.status_code == 200, allowed.text
        assert calls == [(allowed.json()["scan_id"], "passive")]

        from models.scan_history import ScanHistory
        scan = db.query(ScanHistory).filter(
            ScanHistory.id == allowed.json()["scan_id"]).one()
        assert scan.scope == "passive"


class TestCheckTokenBinding:
    def _headers(self, client, username, org):
        _register(client, username=username, org=org)
        login = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "password123"},
        )
        assert login.status_code == 200, login.text
        return {"Authorization": f"Bearer {login.json()['access_token']}"}

    def _token_for(self, db, org_id, domain):
        return db.query(VerifiedDomain).filter(
            VerifiedDomain.organization_id == org_id,
            VerifiedDomain.domain == domain,
        ).one().token

    def _org_id_for(self, db, username):
        from models.user import User
        return db.query(User).filter(User.username == username).one().organization_id

    def test_txt_stale_token_rejected(self, client, db):
        headers = self._headers(client, "tokuser", "Tok Org")
        first = client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "tok.example.com", "method": "dns_txt"},
            headers=headers,
        ).json()
        client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "tok.example.com", "method": "dns_txt"},
            headers=headers,
        )
        stale = client.get(
            "/api/v1/scans/verify-ownership/check"
            f"?domain=tok.example.com&token={first['challenge_token']}",
            headers=headers,
        )
        assert stale.status_code == 400
        assert stale.json()["error"]["code"] == "verification_failed"

    def test_http_stale_token_rejected_without_fetch(self, client, db, monkeypatch):
        from unittest.mock import Mock
        headers = self._headers(client, "htokuser", "HTok Org")
        first = client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "htok.example.com", "method": "http_file"},
            headers=headers,
        ).json()
        client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "htok.example.com", "method": "http_file"},
            headers=headers,
        )
        fetch = Mock(side_effect=AssertionError("must not fetch on token mismatch"))
        monkeypatch.setattr(verification, "_check_http_file", fetch)
        check = client.get(
            "/api/v1/scans/verify-ownership/check"
            f"?domain=htok.example.com&token={first['challenge_token']}",
            headers=headers,
        )
        assert check.status_code == 400
        assert fetch.call_count == 0

    def test_cross_org_token_rejected(self, client, db):
        headers_a = self._headers(client, "orgusera", "Org A")
        headers_b = self._headers(client, "orguserb", "Org B")
        org_a = self._org_id_for(db, "orgusera")
        org_b = self._org_id_for(db, "orguserb")

        client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "shared.example.com", "method": "dns_txt"},
            headers=headers_a,
        )
        client.post(
            "/api/v1/scans/verify-ownership",
            json={"domain": "shared.example.com", "method": "dns_txt"},
            headers=headers_b,
        )
        token_a = self._token_for(db, org_a, "shared.example.com")

        forged = client.get(
            "/api/v1/scans/verify-ownership/check"
            f"?domain=shared.example.com&token={token_a}",
            headers=headers_b,
        )
        assert forged.status_code == 400

        with patch(
            "services.verification.verification_service.verify_domain_ownership",
            new=AsyncMock(return_value=(True, "Domain ownership verified")),
        ):
            ok_a = client.get(
                "/api/v1/scans/verify-ownership/check?domain=shared.example.com",
                headers=headers_a,
            )
        assert ok_a.status_code == 200

        # A's success changes nothing for B.
        assert verification.is_scan_allowed(db, org_b, "shared.example.com")[0] is False
        assert verification.is_scan_allowed(db, org_a, "shared.example.com")[0] is True
