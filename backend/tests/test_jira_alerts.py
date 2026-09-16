"""Item 4: Slack (Incoming Webhook) + Jira (REST issue creation) connectors.

Covers Jira issue payload/auth, SSRF fail-closed delivery, routing from
both finding and change dispatch paths, per-organisation configuration
validation, and RBAC (alert:manage) enforcement on the v1 API.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from models import AlertIntegration, AlertChannel, AlertSeverity, Asset, Finding


def _register(client, org, username):
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "organization": org,
        },
    )


def _login(client, username):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _jira_integration(org_id, **overrides):
    params = {
        "organization_id": org_id,
        "name": "Jira SEC",
        "channel": AlertChannel.JIRA,
        "webhook_url": None,
        "min_severity": AlertSeverity.LOW,
        "is_active": True,
        "jira_base_url": "https://sec-example.atlassian.net",
        "jira_project_key": "SEC",
        "jira_email": "security@example.com",
        "jira_api_token": "token-123",
        "jira_issue_type": "Task",
    }
    params.update(overrides)
    return AlertIntegration(**params)


def _finding(org_id, asset_id=7, severity="high"):
    return Finding(
        organization_id=org_id,
        asset_id=asset_id,
        title="Open Port 22",
        severity=severity,
        category="network_exposure",
        description="Port 22 is open",
        recommendation="Restrict access",
    )


def _asset(org_id):
    return Asset(organization_id=org_id, name="jira.example.com")


def _mock_http_client(mock_client_cls, status_code=201):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post.return_value = mock_resp
    mock_client_cls.return_value = mock_client
    return mock_client


class TestSendJiraAlert:
    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_creates_issue_with_basic_auth(self, mock_client_cls, monkeypatch):
        from services.alerts.alerting_service import send_jira_alert

        monkeypatch.setattr(
            "services.alerts.alerting_service.socket.gethostbyname",
            lambda host: "18.65.100.20",
        )
        mock_client = _mock_http_client(mock_client_cls)

        integration = _jira_integration(org_id=1)
        result = asyncio.run(send_jira_alert(integration, _finding(1), _asset(1)))

        assert result is True
        assert mock_client.post.call_count == 1
        url, kwargs = mock_client.post.call_args.args[0], mock_client.post.call_args.kwargs
        assert url == "https://sec-example.atlassian.net/rest/api/3/issue"
        assert kwargs["auth"] == ("security@example.com", "token-123")
        fields = kwargs["json"]["fields"]
        assert fields["project"] == {"key": "SEC"}
        assert fields["issuetype"] == {"name": "Task"}
        assert "[SentinelASM:HIGH]" in fields["summary"]
        assert "jira.example.com" in fields["summary"]
        assert fields["labels"] == ["sentinelasm", "severity-high"]
        assert fields["description"]["type"] == "doc"  # Jira ADF format

    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_missing_settings_returns_false(self, mock_client_cls):
        from services.alerts.alerting_service import send_jira_alert

        integration = _jira_integration(org_id=1, jira_api_token=None)
        result = asyncio.run(send_jira_alert(integration, _finding(1), _asset(1)))
        assert result is False
        mock_client_cls.assert_not_called()

    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_blocked_ip_fails_closed_without_request(self, mock_client_cls, monkeypatch):
        from services.alerts.alerting_service import send_jira_alert

        monkeypatch.setattr(
            "services.alerts.alerting_service.socket.gethostbyname",
            lambda host: "169.254.169.254",
        )
        integration = _jira_integration(org_id=1)
        result = asyncio.run(send_jira_alert(integration, _finding(1), _asset(1)))
        assert result is False
        mock_client_cls.assert_not_called()

    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_plain_http_base_url_rejected(self, mock_client_cls):
        from services.alerts.alerting_service import send_jira_alert

        integration = _jira_integration(org_id=1, jira_base_url="http://jira.internal/hook")
        result = asyncio.run(send_jira_alert(integration, _finding(1), _asset(1)))
        assert result is False
        mock_client_cls.assert_not_called()


class TestJiraRouting:
    @patch("services.alerts.alerting_service.send_jira_alert", new_callable=AsyncMock)
    def test_finding_dispatch_routes_to_jira(self, mock_jira, db, org_factory):
        from services.alerts.alerting_service import process_finding_alerts

        mock_jira.return_value = True
        org, _ = org_factory("Jira Route Org", "jiraroute", "jiraroute@test.com")
        db.add(_jira_integration(org.id))
        db.add(Asset(organization_id=org.id, name="jr.example.com"))
        db.commit()

        asset = _asset(org.id)
        asyncio.run(process_finding_alerts(db, _finding(org.id), asset))
        mock_jira.assert_called_once()

    @patch("services.alerts.alerting_service.send_jira_alert", new_callable=AsyncMock)
    def test_change_dispatch_routes_to_jira(self, mock_jira, db, org_factory):
        from services.alerts.alerting_service import process_change_alerts
        from services.history.change_detector import persist_alerts

        mock_jira.return_value = True
        org, _ = org_factory("Jira Change Org", "jirachg", "jirachg@test.com")
        db.add(_jira_integration(org.id, min_severity=AlertSeverity.INFO))
        asset = Asset(organization_id=org.id, name="jc.example.com")
        db.add(asset)
        db.commit()

        created = persist_alerts(db, [{
            "type": "port_opened", "asset_id": asset.id,
            "title": "New open port", "severity": "medium", "details": "{}",
        }], org.id)
        db.commit()

        asyncio.run(process_change_alerts(db, created, asset))
        mock_jira.assert_called_once()

    @patch("services.alerts.alerting_service.send_jira_alert", new_callable=AsyncMock)
    def test_threshold_applies_to_jira(self, mock_jira, db, org_factory):
        from services.alerts.alerting_service import process_finding_alerts

        org, _ = org_factory("Jira Thresh Org", "jirathresh", "jirathresh@test.com")
        db.add(_jira_integration(org.id, min_severity=AlertSeverity.CRITICAL))
        db.commit()

        asyncio.run(process_finding_alerts(db, _finding(org.id, severity="low"), _asset(org.id)))
        mock_jira.assert_not_called()


class TestJiraApi:
    def _jira_payload(self, **overrides):
        payload = {
            "name": "Jira SEC",
            "channel": "jira",
            "min_severity": "high",
            "jira_base_url": "https://sec-example.atlassian.net",
            "jira_project_key": "sec",
            "jira_email": "security@example.com",
            "jira_api_token": "token-123",
            "jira_issue_type": "Task",
        }
        payload.update(overrides)
        return payload

    def test_create_jira_integration(self, client, db):
        _register(client, "Jira API Org", "jiraapi")
        headers = _login(client, "jiraapi")

        response = client.post(
            "/api/v1/alerting/integrations", json=self._jira_payload(), headers=headers
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["channel"] == "jira"
        assert body["jira_base_url"] == "https://sec-example.atlassian.net/"
        assert body["jira_project_key"] == "SEC"  # normalized to upper case
        assert body["jira_email"] == "security@example.com"
        assert body["jira_issue_type"] == "Task"
        assert "jira_api_token" not in body  # token never returned

    def test_create_jira_requires_settings(self, client):
        _register(client, "Jira Req Org", "jirareq")
        headers = _login(client, "jirareq")

        payload = self._jira_payload()
        del payload["jira_api_token"]
        response = client.post(
            "/api/v1/alerting/integrations", json=payload, headers=headers
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "jira_settings_required"

    def test_create_slack_requires_webhook(self, client):
        _register(client, "Slack Req Org", "slackreq")
        headers = _login(client, "slackreq")

        response = client.post(
            "/api/v1/alerting/integrations",
            json={"name": "Broken Slack", "channel": "slack"},
            headers=headers,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "webhook_url_required"

    def test_create_slack_still_works(self, client):
        _register(client, "Slack Ok Org", "slackok")
        headers = _login(client, "slackok")

        response = client.post(
            "/api/v1/alerting/integrations",
            json={
                "name": "Team Slack",
                "channel": "slack",
                "webhook_url": "https://hooks.slack.com/services/T/B/X",
            },
            headers=headers,
        )
        assert response.status_code == 201, response.text
        assert response.json()["webhook_url"] == "https://hooks.slack.com/services/T/B/X"

    def test_viewer_cannot_configure_integrations(self, client, db):
        from models.user import User

        _register(client, "Jira Viewer Org", "jiraviewer")
        headers = _login(client, "jiraviewer")
        user = db.query(User).filter(User.username == "jiraviewer").first()
        user.role = "viewer"
        db.commit()

        response = client.post(
            "/api/v1/alerting/integrations", json=self._jira_payload(), headers=headers
        )
        assert response.status_code == 403

        response = client.get("/api/v1/alerting/integrations", headers=headers)
        assert response.status_code == 403

    def test_integrations_are_org_scoped(self, client):
        _register(client, "Jira Org A", "jiraorga")
        headers_a = _login(client, "jiraorga")
        client.post(
            "/api/v1/alerting/integrations", json=self._jira_payload(), headers=headers_a
        )

        _register(client, "Jira Org B", "jiraorgb")
        headers_b = _login(client, "jiraorgb")
        body = client.get("/api/v1/alerting/integrations", headers=headers_b).json()
        assert body == []

    def test_update_jira_fields(self, client):
        _register(client, "Jira Upd Org", "jiraupd")
        headers = _login(client, "jiraupd")

        created = client.post(
            "/api/v1/alerting/integrations", json=self._jira_payload(), headers=headers
        ).json()

        updated = client.patch(
            f"/api/v1/alerting/integrations/{created['id']}",
            json={"jira_project_key": "ops", "jira_issue_type": "Bug"},
            headers=headers,
        )
        assert updated.status_code == 200, updated.text
        body = updated.json()
        assert body["jira_project_key"] == "OPS"
        assert body["jira_issue_type"] == "Bug"
        assert "jira_api_token" not in body

    def test_test_endpoint_drives_jira_sender(self, client):
        _register(client, "Jira Test Org", "jiratest")
        headers = _login(client, "jiratest")

        created = client.post(
            "/api/v1/alerting/integrations", json=self._jira_payload(), headers=headers
        ).json()

        with patch(
            "services.alerts.alerting_service.send_jira_alert", new_callable=AsyncMock
        ) as mock_jira:
            mock_jira.return_value = True
            response = client.post(
                f"/api/v1/alerting/integrations/{created['id']}/test", headers=headers
            )
            assert response.status_code == 200, response.text
            mock_jira.assert_called_once()
