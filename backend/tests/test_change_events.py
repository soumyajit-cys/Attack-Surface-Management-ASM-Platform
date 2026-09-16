"""Item 3: asset change history as first-class alertable events.

Covers change-alert dispatch to webhook integrations (reusing the
Slack/Discord pipeline), the pipeline helper that fires it, and the
``GET /api/v1/alerts`` surface backing the dashboard "Recent Changes" panel.
"""

import asyncio
from unittest.mock import AsyncMock, patch

from models import AlertIntegration, AlertChannel, AlertSeverity
from models import Asset
from models.alert import Alert
from services.alerts.alerting_service import process_change_alerts
from services.history.change_detector import persist_alerts


def _integration(org_id, channel=AlertChannel.SLACK, min_severity=AlertSeverity.LOW):
    return AlertIntegration(
        organization_id=org_id,
        name=f"Test {channel.value}",
        channel=channel,
        webhook_url="https://hooks.example.com/test",
        min_severity=min_severity,
        is_active=True,
    )


def _alerts(db, org_id, asset_id):
    changes = [
        {"type": "port_opened", "asset_id": asset_id, "title": "New open port: www:8080",
         "severity": "medium", "details": "{}"},
        {"type": "finding_resolved", "asset_id": asset_id, "title": "Finding resolved: X",
         "severity": "info", "details": "{}"},
    ]
    created = persist_alerts(db, changes, org_id)
    db.commit()
    return created


def _asset(db, org_id, name="changes.example.com"):
    asset = Asset(organization_id=org_id, name=name)
    db.add(asset)
    db.commit()
    return asset


class TestProcessChangeAlerts:
    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_dispatches_each_change_to_slack(self, mock_slack, db, org_factory):
        mock_slack.return_value = True
        org, _ = org_factory("Change Alert Org", "chgalert", "chgalert@test.com")
        db.add(_integration(org.id, min_severity=AlertSeverity.INFO))
        db.commit()

        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)

        asyncio.run(process_change_alerts(db, created, asset))

        assert mock_slack.call_count == 2
        # Adapter preserves the change title/severity for the block builder.
        first_finding_like = mock_slack.call_args_list[0].args[1]
        assert first_finding_like.title == "New open port: www:8080"
        assert first_finding_like.severity == "medium"
        assert first_finding_like.category == "asset_change"

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_threshold_filters_low_changes(self, mock_slack, db, org_factory):
        mock_slack.return_value = True
        org, _ = org_factory("Change Thresh Org", "chgthresh", "chgthresh@test.com")
        db.add(_integration(org.id, min_severity=AlertSeverity.HIGH))
        db.commit()

        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)  # medium + info → both below high

        asyncio.run(process_change_alerts(db, created, asset))
        mock_slack.assert_not_called()

    @patch("services.alerts.alerting_service.send_discord_alert", new_callable=AsyncMock)
    def test_routes_to_discord_integration(self, mock_discord, db, org_factory):
        mock_discord.return_value = True
        org, _ = org_factory("Change Discord Org", "chgdiscord", "chgdiscord@test.com")
        db.add(_integration(org.id, channel=AlertChannel.DISCORD, min_severity=AlertSeverity.INFO))
        db.commit()

        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)

        asyncio.run(process_change_alerts(db, created, asset))
        assert mock_discord.call_count == 2

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_other_org_integration_ignored(self, mock_slack, db, org_factory):
        mock_slack.return_value = True
        org, _ = org_factory("Change Org A", "chga", "chga@test.com")
        other, _ = org_factory("Change Org B", "chgb", "chgb@test.com")
        db.add(_integration(other.id))
        db.commit()

        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)

        asyncio.run(process_change_alerts(db, created, asset))
        mock_slack.assert_not_called()

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_updates_last_triggered_at(self, mock_slack, db, org_factory):
        mock_slack.return_value = True
        org, _ = org_factory("Change Stamp Org", "chgstamp", "chgstamp@test.com")
        integration = _integration(org.id)
        db.add(integration)
        db.commit()
        assert integration.last_triggered_at is None

        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)
        asyncio.run(process_change_alerts(db, created, asset))

        db.refresh(integration)
        assert integration.last_triggered_at is not None


class TestDispatchHelper:
    def test_helper_calls_process_change_alerts(self, db, org_factory):
        from tasks import discovery_tasks

        org, _ = org_factory("Change Helper Org", "chghelp", "chghelp@test.com")
        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)

        with patch(
            "services.alerts.alerting_service.process_change_alerts",
            new_callable=AsyncMock,
        ) as mock_process:
            discovery_tasks._dispatch_alerts_for_changes(db, created, asset.id, org.id)
            mock_process.assert_called_once()

    def test_helper_swallows_delivery_errors(self, db, org_factory):
        from tasks import discovery_tasks

        org, _ = org_factory("Change Swallow Org", "chgswallow", "chgswallow@test.com")
        asset = _asset(db, org.id)
        created = _alerts(db, org.id, asset.id)

        with patch(
            "services.alerts.alerting_service.process_change_alerts",
            new_callable=AsyncMock,
        ) as mock_process:
            mock_process.side_effect = RuntimeError("webhook down")
            # Must not raise: change-alert delivery never fails a scan.
            discovery_tasks._dispatch_alerts_for_changes(db, created, asset.id, org.id)

    def test_helper_noop_without_alerts(self, db, org_factory):
        from tasks import discovery_tasks

        org, _ = org_factory("Change Noop Org", "chgnoop", "chgnoop@test.com")
        asset = _asset(db, org.id)
        with patch(
            "services.alerts.alerting_service.process_change_alerts",
            new_callable=AsyncMock,
        ) as mock_process:
            discovery_tasks._dispatch_alerts_for_changes(db, [], asset.id, org.id)
            mock_process.assert_not_called()


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


class TestAlertsApi:
    def _seed(self, client, db, org="Alerts API Org", username="alertsapi"):
        _register(client, org, username)
        headers = _login(client, username)
        from models.user import User

        user = db.query(User).filter(User.username == username).first()
        asset = Asset(organization_id=user.organization_id, name="alertsapi.example.com")
        db.add(asset)
        db.commit()
        persist_alerts(db, [
            {"type": "port_opened", "asset_id": asset.id, "title": "New open port: x:22",
             "severity": "medium", "details": "{}"},
            {"type": "finding_new", "asset_id": asset.id, "title": "New finding: Y",
             "severity": "critical", "details": "{}"},
        ], user.organization_id)
        db.commit()
        return headers, asset

    def test_lists_change_events_with_asset_name(self, client, db):
        headers, asset = self._seed(client, db)
        response = client.get("/api/v1/alerts", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2
        assert sorted(i["severity"] for i in body["items"]) == ["critical", "medium"]
        for item in body["items"]:
            assert item["asset_id"] == asset.id
            assert item["asset_name"] == "alertsapi.example.com"
            assert "read" in item

    def test_filters_by_severity_and_asset(self, client, db):
        headers, asset = self._seed(client, db)
        body = client.get("/api/v1/alerts?severity=critical", headers=headers).json()
        assert body["total"] == 1

        body = client.get(f"/api/v1/alerts?asset_id={asset.id}", headers=headers).json()
        assert body["total"] == 2

        body = client.get("/api/v1/alerts?asset_id=999999", headers=headers).json()
        assert body["total"] == 0

    def test_tenant_isolation(self, client, db):
        self._seed(client, db)
        _register(client, "Alerts Other Org", "alertsother")
        other = _login(client, "alertsother")
        body = client.get("/api/v1/alerts", headers=other).json()
        assert body["total"] == 0

    def test_requires_auth(self, client):
        response = client.get("/api/v1/alerts")
        assert response.status_code == 401
