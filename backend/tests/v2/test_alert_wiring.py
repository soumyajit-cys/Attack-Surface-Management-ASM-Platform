"""Alert wiring tests: finding → external alert dispatch.

These tests verify that process_finding_alerts() is called from the pipeline
and that the Slack/Discord webhook delivery retry logic works.
"""

import pytest
from unittest.mock import AsyncMock, patch

from models import AlertIntegration, AlertChannel, AlertSeverity
from services.alerts.alerting_service import (
    process_finding_alerts,
    severity_meets_threshold,
    _post_with_retry,
)


def _make_finding(**overrides):
    class FakeFinding:
        pass

    defaults = {
        "id": 1,
        "organization_id": 1,
        "asset_id": 1,
        "title": "Test Finding",
        "severity": "high",
        "category": "test",
        "description": "A test finding",
        "recommendation": "Fix it",
    }
    defaults.update(overrides)
    f = FakeFinding()
    for k, v in defaults.items():
        setattr(f, k, v)
    return f


def _make_asset(**overrides):
    class FakeAsset:
        pass

    defaults = {"id": 1, "organization_id": 1, "name": "test.example.com"}
    defaults.update(overrides)
    a = FakeAsset()
    for k, v in defaults.items():
        setattr(a, k, v)
    return a


class TestSeverityThreshold:
    def test_critical_above_high(self):
        assert severity_meets_threshold("critical", AlertSeverity.HIGH)

    def test_low_below_medium(self):
        assert not severity_meets_threshold("low", AlertSeverity.MEDIUM)

    def test_same_severity_meets(self):
        assert severity_meets_threshold("high", AlertSeverity.HIGH)

    def test_info_below_low(self):
        assert not severity_meets_threshold("info", AlertSeverity.LOW)


class TestProcessFindingAlerts:
    def test_no_integrations_does_nothing(self, db, org_factory):
        org, user = org_factory("Alert Org NoInt", "alert_noint", "alert_noint@test.com")
        finding = _make_finding(organization_id=org.id, asset_id=0)
        asset = _make_asset(organization_id=org.id, id=0)
        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_dispatches_to_matching_slack_integration(self, mock_slack, db, org_factory):
        mock_slack.return_value = True
        org, user = org_factory("Alert Org Slack", "alert_slack", "alert_slack@test.com")

        integration = AlertIntegration(
            organization_id=org.id,
            name="Test Slack",
            channel=AlertChannel.SLACK,
            webhook_url="https://hooks.slack.com/test",
            min_severity=AlertSeverity.LOW,
            is_active=True,
        )
        db.add(integration)
        db.flush()

        finding = _make_finding(organization_id=org.id, severity="high")
        asset = _make_asset(organization_id=org.id)

        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

        mock_slack.assert_called_once()

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_skips_when_severity_below_threshold(self, mock_slack, db, org_factory):
        org, user = org_factory("Alert Org Crit", "alert_crit", "alert_crit@test.com")
        integration = AlertIntegration(
            organization_id=org.id,
            name="Critical Only",
            channel=AlertChannel.SLACK,
            webhook_url="https://hooks.slack.com/test",
            min_severity=AlertSeverity.CRITICAL,
            is_active=True,
        )
        db.add(integration)
        db.flush()

        finding = _make_finding(organization_id=org.id, severity="low")
        asset = _make_asset(organization_id=org.id)

        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

        mock_slack.assert_not_called()

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_skips_inactive_integration(self, mock_slack, db, org_factory):
        org, user = org_factory("Alert Org Inactive", "alert_inactive", "alert_inactive@test.com")
        integration = AlertIntegration(
            organization_id=org.id,
            name="Inactive Slack",
            channel=AlertChannel.SLACK,
            webhook_url="https://hooks.slack.com/test",
            min_severity=AlertSeverity.LOW,
            is_active=False,
        )
        db.add(integration)
        db.flush()

        finding = _make_finding(organization_id=org.id, severity="critical")
        asset = _make_asset(organization_id=org.id)

        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

        mock_slack.assert_not_called()


class TestPostWithRetry:
    def _no_validate(self, monkeypatch):
        import services.alerts.alerting_service as service

        monkeypatch.setattr(
            service, "validate_webhook_url",
            lambda url: ("hook.example", 443, "/"),
        )
        return service

    def test_succeeds_on_first_try(self, monkeypatch):
        import asyncio

        from utils.egress import FetchResult

        service = self._no_validate(monkeypatch)
        calls = []

        async def fake_fetch(url, **kw):
            calls.append((url, kw))
            return FetchResult(status_code=200, headers={}, body=b"ok")

        monkeypatch.setattr(service, "fetch_url_validated", fake_fetch)
        monkeypatch.setattr("asyncio.sleep", AsyncMock())

        result = asyncio.run(_post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is True
        assert len(calls) == 1
        url, kw = calls[0]
        assert url == "https://hook.example"
        assert kw["method"] == "POST"
        assert kw["max_redirects"] == 0
        assert b'"text": "hi"' in kw["content"] or b'"text":"hi"' in kw["content"]

    def test_retries_on_500_then_succeeds(self, monkeypatch):
        import asyncio

        from utils.egress import FetchResult

        service = self._no_validate(monkeypatch)
        calls = []

        async def fake_fetch(url, **kw):
            calls.append(url)
            code = 500 if len(calls) == 1 else 200
            return FetchResult(status_code=code, headers={}, body=b"")

        monkeypatch.setattr(service, "fetch_url_validated", fake_fetch)
        monkeypatch.setattr("asyncio.sleep", AsyncMock())

        result = asyncio.run(_post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is True
        assert len(calls) == 2

    def test_returns_false_on_400_no_retry(self, monkeypatch):
        import asyncio

        from utils.egress import FetchResult

        service = self._no_validate(monkeypatch)
        calls = []

        async def fake_fetch(url, **kw):
            calls.append(url)
            return FetchResult(status_code=400, headers={}, body=b"")

        monkeypatch.setattr(service, "fetch_url_validated", fake_fetch)
        monkeypatch.setattr("asyncio.sleep", AsyncMock())

        result = asyncio.run(_post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is False
        assert len(calls) == 1

    def test_blocked_url_fails_without_fetch(self, monkeypatch):
        import asyncio
        import socket as stdlib_socket

        async def _boom(*a, **k):
            raise AssertionError("blocked webhooks must not be fetched")

        monkeypatch.setattr(
            "services.alerts.alerting_service.fetch_url_validated", _boom
        )
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: [(
                stdlib_socket.AF_INET, 1, 6, "", ("10.9.9.9", 443))],
        )

        result = asyncio.run(
            _post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is False
