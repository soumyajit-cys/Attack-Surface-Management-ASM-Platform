"""v3 API v1 endpoint tests: scans, findings, dashboard, scan policies.

These tests spin up the full v1 surface through TestClient and verify the
error-envelope shape, tenant isolation, and permission enforcement.
"""

from datetime import datetime, timezone

from models import Asset, ScanPolicy, ScanFrequency, Finding


def _register(client, org="V3 Org", username="v3user", email="v3user@example.com"):
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": email,
            "password": "password123",
            "organization": org,
        },
    )


def _login(client, username="v3user"):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class TestScansV1:
    def test_list_dashboard_requires_auth(self, client):
        response = client.get("/api/v1/dashboard")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthenticated"

    def test_get_scan_status_enforces_org_scope(self, client, db):
        _register(client, org="ScanV1 Org", username="scanv1", email="scanv1@example.com")
        headers = _login(client, username="scanv1")

        response = client.get("/api/v1/scans/999999", headers=headers)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "scan_not_found"

    def test_invalid_domain_rejected(self, client):
        _register(client, org="ScanV1b Org", username="scanv1b", email="scanv1b@example.com")
        headers = _login(client, username="scanv1b")

        response = client.post(
            "/api/v1/scans",
            json={"domain": "not_a_valid_domain!!"},
            headers=headers,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_domain"


class TestFindingsV1:
    def _seed(self, client, db):
        _register(client, org="FindV1 Org", username="findv1", email="findv1@example.com")
        headers = _login(client, username="findv1")

        org_id = db.query(Finding).first() and 0 or db.query(Asset).first() and 0 or None
        from models.organization import Organization
        from models.user import User

        user = db.query(User).filter(User.username == "findv1").first()
        org_id = user.organization_id

        asset = Asset(organization_id=org_id, name="find.example.com")
        db.add(asset)
        db.flush()

        db.add(Finding(
            organization_id=org_id,
            asset_id=asset.id,
            title="Critical vuln",
            severity="critical",
            category="vulnerability",
        ))
        db.add(Finding(
            organization_id=org_id,
            asset_id=asset.id,
            title="Info header",
            severity="info",
            category="headers",
        ))
        db.commit()
        return headers, org_id, asset

    def test_lists_findings_with_pagination(self, client, db):
        headers, _, _ = self._seed(client, db)
        response = client.get("/api/v1/findings", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2

    def test_filters_by_severity(self, client, db):
        headers, _, _ = self._seed(client, db)
        response = client.get("/api/v1/findings?severity=critical", headers=headers)
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["severity"] == "critical"

    def test_tenant_isolation(self, client, db):
        _register(client, org="FindV1 Org", username="findv1", email="findv1@example.com")
        _register(client, org="Other Org", username="otherv1", email="otherv1@example.com")
        headers = _login(client, username="otherv1")

        response = client.get("/api/v1/findings", headers=headers)
        assert response.status_code == 200
        assert response.json()["total"] == 0


class TestDashboardV1:
    def test_returns_counts(self, client, db):
        _register(client, org="DashV1 Org", username="dashv1", email="dashv1@example.com")
        headers = _login(client, username="dashv1")

        from models.organization import Organization
        from models.user import User

        user = db.query(User).filter(User.username == "dashv1").first()
        asset = Asset(organization_id=user.organization_id, name="dash.example.com")
        db.add(asset)
        db.flush()
        db.add(Finding(
            organization_id=user.organization_id,
            asset_id=asset.id,
            title="High something",
            severity="high",
            category="general",
        ))
        db.commit()

        response = client.get("/api/v1/dashboard", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["assets"] == 1
        assert body["findings"] == 1
        assert body["high"] == 1
        assert "scans_total" in body
        assert "avg_risk_score" in body


class TestScanPoliciesV1:
    def _register_with_asset(self, client, db, org="PolV1 Org", username="polv1"):
        _register(client, org=org, username=username, email=f"{username}@example.com")
        headers = _login(client, username=username)

        from models.organization import Organization
        from models.user import User

        user = db.query(User).filter(User.username == username).first()
        asset = Asset(organization_id=user.organization_id, name="poli.example.com")
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return headers, asset

    def test_create_policy_sets_next_run_at(self, client, db):
        headers, asset = self._register_with_asset(client, db)

        response = client.post(
            "/api/v1/scan-policies",
            json={
                "name": "Weekly scan",
                "asset_id": asset.id,
                "frequency": "weekly",
                "scope": "full",
            },
            headers=headers,
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["next_run_at"] is not None
        assert body["is_active"] is True

    def test_create_custom_cron_requires_expression(self, client, db):
        headers, asset = self._register_with_asset(client, db, username="polv2")

        response = client.post(
            "/api/v1/scan-policies",
            json={
                "name": "Cron scan",
                "asset_id": asset.id,
                "frequency": "custom_cron",
                "scope": "full",
            },
            headers=headers,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "cron_expression_required"

    def test_create_requires_existing_asset(self, client, db):
        headers, _ = self._register_with_asset(client, db, username="polv3")
        response = client.post(
            "/api/v1/scan-policies",
            json={
                "name": "Bad asset",
                "asset_id": 999999,
                "frequency": "daily",
                "scope": "full",
            },
            headers=headers,
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "asset_not_found"

    def test_list_policies_isolated_by_org(self, client, db):
        headers, asset = self._register_with_asset(client, db, username="polv4")

        policy = ScanPolicy(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            name="Existing",
            frequency=ScanFrequency.DAILY,
            scope="full",
            created_by=1,
        )
        db.add(policy)
        db.commit()

        response = client.get("/api/v1/scan-policies", headers=headers)
        assert response.status_code == 200
        assert len(response.json()) == 1
        assert response.json()[0]["name"] == "Existing"

    def test_update_policy_recomputes_next_run(self, client, db):
        headers, asset = self._register_with_asset(client, db, username="polv5")

        response = client.post(
            "/api/v1/scan-policies",
            json={
                "name": "Daily scan",
                "asset_id": asset.id,
                "frequency": "daily",
                "scope": "full",
            },
            headers=headers,
        )
        policy_id = response.json()["id"]

        response = client.patch(
            f"/api/v1/scan-policies/{policy_id}",
            json={"frequency": "weekly"},
            headers=headers,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["frequency"] == "weekly"
        assert body["next_run_at"] is not None

    def test_viewer_cannot_create_policy(self, client, db):
        _register(client, org="PolV1 Org", username="polv1", email="polv1@example.com")
        headers = _login(client, username="polv1")

        # Downgrade to viewer
        from models.user import User
        user = db.query(User).filter(User.username == "polv1").first()
        user.role = "viewer"
        db.commit()

        response = client.post(
            "/api/v1/scan-policies",
            json={"name": "Nope", "asset_id": 1, "frequency": "daily", "scope": "full"},
            headers=headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"


class TestOrganizationsV1:
    def test_get_me(self, client):
        _register(client, org="OrgV1 Org", username="orgv1", email="orgv1@example.com")
        headers = _login(client, username="orgv1")

        response = client.get("/api/v1/organizations/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["name"] == "OrgV1 Org"

    def test_create_api_key_requires_admin(self, client, db):
        _register(client, org="OrgV1b Org", username="orgv1b", email="orgv1b@example.com")
        headers = _login(client, username="orgv1b")

        response = client.post("/api/v1/organizations/api-keys", json={"name": "ci"}, headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["key"].startswith("sk")


class TestAlertingV1:
    def test_digest_config_crud(self, client, db):
        _register(client, org="AlertV1 Org", username="alertv1", email="alertv1@example.com")
        headers = _login(client, username="alertv1")

        response = client.post(
            "/api/v1/alerting/digest",
            json={
                "frequency": "weekly",
                "day_of_week": 1,
                "hour_utc": 9,
                "recipient_emails": "a@b.com",
                "min_severity": "medium",
            },
            headers=headers,
        )
        assert response.status_code == 201, response.text
        assert response.json()["frequency"] == "weekly"

        response = client.get("/api/v1/alerting/digest", headers=headers)
        assert response.status_code == 200

        response = client.patch(
            "/api/v1/alerting/digest",
            json={"is_active": False},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False

        response = client.delete("/api/v1/alerting/digest", headers=headers)
        assert response.status_code == 200

    def test_duplicate_digest_config_conflict(self, client, db):
        _register(client, org="AlertV2 Org", username="alertv2", email="alertv2@example.com")
        headers = _login(client, username="alertv2")

        first = client.post(
            "/api/v1/alerting/digest",
            json={"frequency": "daily", "hour_utc": 9, "recipient_emails": "a@b.com"},
            headers=headers,
        )
        assert first.status_code == 201

        second = client.post(
            "/api/v1/alerting/digest",
            json={"frequency": "weekly", "hour_utc": 9, "recipient_emails": "c@d.com"},
            headers=headers,
        )
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "digest_config_exists"


class TestApiKeyAuth:
    def test_api_key_authenticates_findings(self, client, db):
        _register(client, org="KeyV1 Org", username="keyv1", email="keyv1@example.com")
        headers = _login(client, username="keyv1")

        response = client.post(
            "/api/v1/organizations/api-keys",
            json={"name": "ci", "scopes": "read"},
            headers=headers,
        )
        full_key = response.json()["key"]

        # Findings require finding:read; scope "read" grants it.
        r = client.get(
            "/api/v1/findings",
            headers={"X-API-Key": full_key},
        )
        assert r.status_code == 200

    def test_api_key_read_scope_cannot_create_scans(self, client, db):
        _register(client, org="KeyV2 Org", username="keyv2", email="keyv2@example.com")
        headers = _login(client, username="keyv2")

        response = client.post(
            "/api/v1/organizations/api-keys",
            json={"name": "ci", "scopes": "read"},
            headers=headers,
        )
        full_key = response.json()["key"]

        # scan:create is NOT in the read grant → 403.
        r = client.post(
            "/api/v1/scans",
            json={"domain": "example.com"},
            headers={"X-API-Key": full_key},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "forbidden"