"""Item 6: GET /api/v1/audit-logs — ORG_MANAGE-only audit trail viewer.

Route-completeness red tests live in test_rbac_matrix.py (EXPECTED + READ_CASES)
and test_tenant_matrix.py (COVERED_LIST_ROUTES) — they failed until this
route existed. This file covers the viewer contract itself: org scoping
(one's own rows only), pagination bounds, filter validation, ordering,
secret scrubbing, and parameterized-only filtering.

Hermetic: no network, no celery.
"""

from datetime import datetime, timedelta, timezone

import pytest

MARK_A = "auditmarka.example.com"
MARK_B = "auditmarkb.example.com"


@pytest.fixture()
def audit_orgs(client, db, org_factory):
    """Two orgs, each with its own audit rows; returns admin auth headers.

    Fixture rows are dated deep in the past so rows written by org_factory
    (itself audited, dated "now") can never fall inside test windows.
    """
    from models.audit_log import AuditLog

    org_a, admin_a = org_factory(
        "Audit Org A", "audita", "audita@example.com")
    org_b, admin_b = org_factory(
        "Audit Org B", "auditb", "auditb@example.com")

    base = datetime.now(timezone.utc) - timedelta(days=100)
    for org, actor, mark, ip in (
        (org_a, "audita", MARK_A, "203.0.113.50"),
        (org_b, "auditb", MARK_B, "203.0.113.60"),
    ):
        for offset in range(3):
            row = AuditLog(
                organization_id=org.id,
                actor=actor,
                action=f"scan.started{offset}",
                details=f'{{"target": "{mark}"}}',
                ip_address=ip,
                created_at=base + timedelta(minutes=offset),
            )
            db.add(row)
    # one secret-marker row per org to prove the scrubber works
    db.add(AuditLog(
        organization_id=org_a.id, actor="audita",
        action="scan.curious",
        details='{"password": "hunter2", "secret": "s3cr3t", "note": "safe-region-7"}',
        ip_address="203.0.113.50",
        created_at=base + timedelta(minutes=10),
    ))
    db.commit()

    def login(username):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "password123"},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return {
        "auth_a": login("audita"),
        "auth_b": login("auditb"),
        "org_a_id": org_a.id,
        "org_b_id": org_b.id,
        "base": base,
    }


class TestAuditLogViewer:
    def test_lists_rows_newest_first_and_scoped(
            self, client, audit_orgs):
        response = client.get("/api/v1/audit-logs", headers=audit_orgs["auth_a"])
        assert response.status_code == 200, response.text
        body = response.json()

        # 5 fixture rows minimum; org_factory itself may add audited rows.
        assert body["total"] >= 5
        assert body["page"] == 1 and body["page_size"] == 20

        items = body["items"]
        # newest first
        created = [it["created_at"] for it in items]
        assert created == sorted(created, reverse=True)
        # org-scoped: only org A rows, never B's actor or marker
        details_blob = str(body)
        assert "auditmarkb.example.com" not in details_blob
        assert not any(
            item["actor"] == "auditb" for item in items)

    def test_org_b_admin_never_sees_org_a_rows(
            self, client, audit_orgs):
        response = client.get("/api/v1/audit-logs", headers=audit_orgs["auth_b"])
        assert response.status_code == 200, response.text
        blob = response.text
        assert "auditmarka.example.com" not in blob
        # every returned row belongs to org B (no org id in the payload, so
        # check the actor names)
        assert all(
            item["actor"] == "auditb" for item in response.json()["items"])

    def test_filters_by_action(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"action": "scan.started1"},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["action"] == "scan.started1"

    def test_filters_by_actor(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"actor": "nobody-as-such"},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 200
        assert response.json()["total"] == 0
        assert response.json()["items"] == []

    def test_filters_by_ip(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"ip": "203.0.113.50"},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 4
        assert all(it["ip_address"] == "203.0.113.50" for it in body["items"])

    def test_invalid_ip_filter_rejected(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"ip": "not-an-ip"},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 400, response.text
        assert "IP literal" in response.json()["error"]["message"]

    def test_since_until_window(self, client, audit_orgs):
        base = audit_orgs["base"]
        response = client.get(
            "/api/v1/audit-logs",
            params={
                "since": (base + timedelta(minutes=1)).isoformat(),
                "until": (base + timedelta(minutes=10)).isoformat(),
            },
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 200
        body = response.json()
        # rows at +1m, +2m and +10m; setup-time rows ("now") are outside
        assert body["total"] == 3
        actions = {it["action"] for it in body["items"]}
        assert actions == {"scan.started1", "scan.started2", "scan.curious"}

    def test_since_after_until_rejected(self, client, audit_orgs):
        base = datetime.now(timezone.utc)
        response = client.get(
            "/api/v1/audit-logs",
            params={
                "since": (base + timedelta(days=5)).isoformat(),
                "until": (base + timedelta(days=1)).isoformat(),
            },
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 400, response.text
        assert "since must not be after until" in response.text

    def test_malformed_datetime_rejected(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"since": "yesterday-ish"},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 422

    def test_pagination_bounds(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"page_size": 101},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 422  # page size cap: le=100

        response = client.get(
            "/api/v1/audit-logs",
            params={"page_size": 0},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 422

        response = client.get(
            "/api/v1/audit-logs",
            params={"page": 0},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 422

    def test_pagination_pages_are_disjoint(self, client, audit_orgs):
        first = client.get(
            "/api/v1/audit-logs", params={"page_size": 2},
            headers=audit_orgs["auth_a"]).json()
        second = client.get(
            "/api/v1/audit-logs", params={"page_size": 2, "page": 2},
            headers=audit_orgs["auth_a"]).json()

        assert first["total"] == second["total"] >= 5
        first_ids = {it["id"] for it in first["items"]}
        second_ids = {it["id"] for it in second["items"]}
        assert len(first_ids) == len(second_ids) == 2
        assert first_ids.isdisjoint(second_ids)

    def test_long_action_and_actor_filters_bounded(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"action": "x" * 200},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 422  # max_length=64

        response = client.get(
            "/api/v1/audit-logs",
            params={"actor": "y" * 400},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 422  # max_length=200


class TestAuditLogNeverReturnsSecrets:
    def test_secret_named_details_keys_are_scrubbed(self, client, audit_orgs):
        response = client.get(
            "/api/v1/audit-logs",
            params={"action": "scan.curious"},
            headers=audit_orgs["auth_a"],
        )
        assert response.status_code == 200
        blob = response.text

        assert "hunter2" not in blob       # "password" scrubbed
        assert "s3cr3t" not in blob        # "secret" scrubbed
        assert "password" not in blob and '"secret"' not in blob
        # non-secret details still come through
        assert "safe-region-7" in blob
        details = response.json()["items"][0]["details"]
        assert details == {"note": "safe-region-7"}

    def test_parameterized_only_no_sql_injection_via_filters(
            self, client, audit_orgs):
        # Malicious filter payloads must not return cross-org data.
        injection = "' OR 1=1; --"
        for param in ("action", "actor"):
            response = client.get(
                "/api/v1/audit-logs",
                params={param: injection},
                headers=audit_orgs["auth_a"],
            )
            assert response.status_code == 200
            body = response.json()
            assert body["total"] == 0   # matched nothing, executed no SQL
            assert body["items"] == []
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            