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
    def _fake_client(self, calls, responder):
        service = verification

        class FakeResponse:
            def __init__(self, status_code, text, headers=None):
                self.status_code = status_code
                self.text = text
                self.headers = headers or {}

        class FakeClient:
            def __init__(self, *a, **kw):
                calls.append((a, kw))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url, headers=None):
                return responder(url, headers)

        return FakeClient, FakeResponse

    def test_success_and_blocked_ip(self, monkeypatch):
        import asyncio
        import socket as real_socket

        calls = []
        expected = verification.challenge_value("tok123")

        def responder(url, headers):
            assert headers["Host"] == "example.com"
            return self._fake_client(calls, None)[1](200, expected + "\n")

        FakeClient, _ = self._fake_client(calls, responder)
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
            Fake = self._fake_client([], None)[1]
            if "93.184.216.34" in url:
                return Fake(302, "", {"location": "http://internal.example/.well-known/x"})
            raise AssertionError(f"unexpected fetch: {url}")

        FakeClient, _ = self._fake_client([], responder)
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
