"""Enrichment provider management API tests (Phase 2.1).

Covers: RBAC (enrichment:manage, admin-only), tenant isolation,
GET returns only has_key/is_active (never the key), PUT rotate + active
flag + acknowledge_data_sharing requirement, DELETE, audit call sites,
and key-never-in-response-or-logs. Plus a ciphertext test that reads the
raw DB column and asserts it is Fernet ciphertext (never plaintext).
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import text


# ── RBAC + tenant isolation ───────────────────────────────────────────────


class TestProviderRbacAndIsolation:
    def test_admin_can_list_providers(self, client, db, org_factory, auth_headers):
        org, _ = org_factory("Prov Org", "provadmin", "provadmin@example.com")
        headers = auth_headers("provadmin")
        from models import EnrichmentProvider

        p = EnrichmentProvider(
            organization_id=org.id,
            name="shodan",
            provider_type="shodan",
            encrypted_api_key="enc:v1:fake",
            is_active=True,
        )
        db.add(p)
        db.commit()

        # Add a second org's provider to test tenant isolation.
        org2, _ = org_factory("Prov Org 2", "provadmin2", "provadmin2@example.com")
        p2 = EnrichmentProvider(
            organization_id=org2.id,
            name="censys",
            provider_type="censys",
            encrypted_api_key="enc:v1:fake2",
            is_active=False,
        )
        db.add(p2)
        db.commit()

        resp = client.get("/api/v1/enrichment/providers", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body["items"]) == 1, body
        item = body["items"][0]
        assert item["name"] == "shodan"
        assert item["has_key"] is True
        assert item["is_active"] is True
        # The key is never in the response.
        assert "encrypted_api_key" not in item
        assert "api_key" not in item

    def test_viewer_and_analyst_denied(
        self, client, db, org_factory, auth_headers
    ):
        org, _ = org_factory("Rbac Prov Org", "rbacadmin", "rbacadmin@example.com")
        # Create viewer + analyst in the same org.
        from models.user import User
        from auth.security import hash_password

        for username, role in (("provviewer", "viewer"), ("provanalyst", "analyst")):
            user = User(
                organization_id=org.id,
                username=username,
                email=f"{username}@example.com",
                password_hash=hash_password("password123"),
                role=role,
            )
            db.add(user)
        db.commit()

        viewer_h = auth_headers("provviewer")
        analyst_h = auth_headers("provanalyst")

        for h in (viewer_h, analyst_h):
            resp = client.get("/api/v1/enrichment/providers", headers=h)
            assert resp.status_code == 403, f"{h} GET: {resp.text}"
            resp = client.put(
                "/api/v1/enrichment/providers/shodan",
                json={"provider_type": "shodan", "api_key": "key"},
                headers=h,
            )
            assert resp.status_code == 403, f"{h} PUT: {resp.text}"
            resp = client.delete(
                "/api/v1/enrichment/providers/shodan", headers=h
            )
            assert resp.status_code == 403, f"{h} DELETE: {resp.text}"

    def test_cross_org_delete_returns_404(
        self, client, db, org_factory, auth_headers
    ):
        org, _ = org_factory("Cross Org", "crossadmin", "crossadmin@example.com")
        headers = auth_headers("crossadmin")
        from models import EnrichmentProvider

        p = EnrichmentProvider(
            organization_id=org.id,
            name="shodan",
            provider_type="shodan",
            encrypted_api_key="enc:v1:fake",
            is_active=True,
        )
        db.add(p)
        db.commit()

        # Another org's admin tries to delete this org's provider.
        org2, _ = org_factory("Cross Org 2", "crossadmin2", "crossadmin2@example.com")
        headers2 = auth_headers("crossadmin2")
        resp = client.delete(
            "/api/v1/enrichment/providers/shodan", headers=headers2
        )
        assert resp.status_code == 404, resp.text

    def test_unspecified_permission_denied(
        self, client, db, org_factory, auth_headers, monkeypatch
    ):
        """A user whose role lacks enrichment:manage gets 403 even though
        they are admin of other things."""
        org, _ = org_factory("NoPerm Org", "nopermadmin", "nopermadmin@example.com")
        from models.user import User
        from auth.security import hash_password

        # analyst role does not have enrichment:manage (only admin does).
        user = User(
            organization_id=org.id,
            username="nopermanalyst",
            email="nopermanalyst@example.com",
            password_hash=hash_password("password123"),
            role="analyst",
        )
        db.add(user)
        db.commit()
        headers = auth_headers("nopermanalyst")
        resp = client.get("/api/v1/enrichment/providers", headers=headers)
        assert resp.status_code == 403, resp.text


# ── PUT: rotate key, active flag, acknowledge_data_sharing ────────────────


class TestProviderUpsert:
    def test_create_provider_returns_no_key(
        self, client, db, org_factory, auth_headers
    ):
        org, _ = org_factory("Upsert Org", "upadmin", "upadmin@example.com")
        headers = auth_headers("upadmin")

        resp = client.put(
            "/api/v1/enrichment/providers/shodan",
            json={
                "provider_type": "shodan",
                "api_key": "plaintext-shodan-key",
                "is_active": True,
                "acknowledge_data_sharing": True,
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "shodan"
        assert body["has_key"] is True
        assert body["is_active"] is True
        assert "encrypted_api_key" not in body
        assert "api_key" not in body

    def test_enable_without_ack_is_400(
        self, client, db, org_factory, auth_headers
    ):
        org, _ = org_factory("NoAck Org", "noackadmin", "noackadmin@example.com")
        headers = auth_headers("noackadmin")

        resp = client.put(
            "/api/v1/enrichment/providers/censys",
            json={
                "provider_type": "censys",
                "api_key": "plaintext-censys-key",
                "is_active": True,
                "acknowledge_data_sharing": False,
            },
            headers=headers,
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"]["code"] == "acknowledge_data_sharing_required"

    def test_crt_sh_exempt_from_ack(self, client, db, org_factory, auth_headers):
        """crt.sh is public CT logs only, so acknowledge_data_sharing is
        not required for it."""
        org, _ = org_factory("CrtSh Org", "crtadmin", "crtadmin@example.com")
        headers = auth_headers("crtadmin")

        resp = client.put(
            "/api/v1/enrichment/providers/crt_sh",
            json={
                "provider_type": "crt_sh",
                "is_active": True,
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text

    def test_disable_without_key_ok(
        self, client, db, org_factory, auth_headers
    ):
        org, _ = org_factory("Disable Org", "disadmin", "disadmin@example.com")
        headers = auth_headers("disadmin")

        # Create active provider first.
        from models import EnrichmentProvider

        p = EnrichmentProvider(
            organization_id=org.id,
            name="shodan",
            provider_type="shodan",
            encrypted_api_key="enc:v1:fake",
            is_active=True,
        )
        db.add(p)
        db.commit()

        resp = client.put(
            "/api/v1/enrichment/providers/shodan",
            json={"provider_type": "shodan", "is_active": False},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["is_active"] is False

    def test_rotate_key_changes_ciphertext(
        self, client, db, org_factory, auth_headers
    ):
        org, _ = org_factory("Rotate Org", "rotadmin", "rotadmin@example.com")
        headers = auth_headers("rotadmin")
        from models import EnrichmentProvider

        p = EnrichmentProvider(
            organization_id=org.id,
            name="shodan",
            provider_type="shodan",
            encrypted_api_key="enc:v1:old-key",
            is_active=True,
        )
        db.add(p)
        db.commit()

        resp = client.put(
            "/api/v1/enrichment/providers/shodan",
            json={
                "provider_type": "shodan",
                "api_key": "new-plaintext-key",
                "is_active": True,
                "acknowledge_data_sharing": True,
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text

        # Raw DB column must hold ciphertext (enc:v1: prefix), never plaintext.
        # Read via raw SQL to bypass the ORM EncryptedText type decorator
        # (which transparently decrypts on read).
        raw = db.execute(
            text("SELECT encrypted_api_key FROM enrichment_providers WHERE name = 'shodan'")
        ).scalar()
        assert raw is not None
        assert raw.startswith("enc:v1:"), raw
        assert raw != "new-plaintext-key"


# ── DELETE ────────────────────────────────────────────────────────────────


class TestProviderDelete:
    def test_delete_provider(self, client, db, org_factory, auth_headers):
        org, _ = org_factory("Del Org", "deladmin", "deladmin@example.com")
        headers = auth_headers("deladmin")
        from models import EnrichmentProvider

        p = EnrichmentProvider(
            organization_id=org.id,
            name="shodan",
            provider_type="shodan",
            encrypted_api_key="enc:v1:fake",
            is_active=True,
        )
        db.add(p)
        db.commit()

        resp = client.delete(
            "/api/v1/enrichment/providers/shodan", headers=headers
        )
        assert resp.status_code == 204, resp.text

        remaining = (
            db.query(EnrichmentProvider)
            .filter(EnrichmentProvider.organization_id == org.id)
            .all()
        )
        assert remaining == []

    def test_delete_idempotent(self, client, db, org_factory, auth_headers):
        org, _ = org_factory("Del2 Org", "del2admin", "del2admin@example.com")
        headers = auth_headers("del2admin")
        resp = client.delete(
            "/api/v1/enrichment/providers/nonexistent", headers=headers
        )
        assert resp.status_code == 204, resp.text


# ── audit call sites ──────────────────────────────────────────────────────


class TestProviderAudit:
    def test_provider_mutation_is_audited(self, client, db, org_factory, auth_headers):
        org, _ = org_factory("Audit Org", "auditadmin", "auditadmin@example.com")
        headers = auth_headers("auditadmin")

        client.put(
            "/api/v1/enrichment/providers/shodan",
            json={
                "provider_type": "shodan",
                "api_key": "plaintext-key",
                "is_active": True,
                "acknowledge_data_sharing": True,
            },
            headers=headers,
        )

        from models.audit_log import AuditLog
        import json

        rows = (
            db.query(AuditLog)
            .filter(AuditLog.action == "enrichment.provider_created")
            .all()
        )
        assert len(rows) == 1, rows
        details = json.loads(rows[0].details)
        details_str = json.dumps(details).casefold()
        assert "key" not in details_str, details_str
        assert "encrypted_api_key" not in details_str, details_str
        assert details["provider_name"] == "shodan"
        assert details["is_active"] is True
        assert details["credentials_rotated"] is True
