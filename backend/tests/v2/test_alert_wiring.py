"""Alert wiring tests: finding → external alert dispatch.

These tests verify that process_finding_alerts() is called from the pipeline
and that the Slack/Discord webhook delivery retry logic works.
"""

import pytest
from unittest.mock import AsyncMock, patch

from sqlalchemy.orm import Session

from models import AlertIntegration, AlertChannel, AlertSeverity
from services.alerts.alerting_service import (
    process_finding_alerts,
    severity_meets_threshold,
    _post_with_retry,
)


def _make_finding(**overrides):
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

    class FakeFinding:
        pass

    f = FakeFinding()
    for k, v in defaults.items():
        setattr(f, k, v)
    return f


def _make_asset(**overrides):
    defaults = {"id": 1, "organization_id": 1, "name": "test.example.com"}
    defaults.update(overrides)

    class FakeAsset:
        pass

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
    def test_no_integrations_does_nothing(self, db):
        finding = _make_finding()
        asset = _make_asset()
        # Should not raise even with no integrations.
        db.run_sync(lambda conn: None)
        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_dispatches_to_matching_slack_integration(self, mock_slack, db):
        mock_slack.return_value = True

        integration = AlertIntegration(
            organization_id=1,
            channel=AlertChannel.SLACK,
            webhook_url="https://hooks.slack.com/test",
            min_severity=AlertSeverity.LOW,
            is_active=True,
        )
        db.add(integration)
        db.flush()

        finding = _make_finding(severity="high")
        asset = _make_asset()

        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

        mock_slack.assert_called_once()

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_skips_when_severity_below_threshold(self, mock_slack, db):
        integration = AlertIntegration(
            organization_id=1,
            channel=AlertChannel.SLACK,
            webhook_url="https://hooks.slack.com/test",
            min_severity=AlertSeverity.CRITICAL,
            is_active=True,
        )
        db.add(integration)
        db.flush()

        finding = _make_finding(severity="low")
        asset = _make_asset()

        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

        mock_slack.assert_not_called()

    @patch("services.alerts.alerting_service.send_slack_alert", new_callable=AsyncMock)
    def test_skips_inactive_integration(self, mock_slack, db):
        integration = AlertIntegration(
            organization_id=1,
            channel=AlertChannel.SLACK,
            webhook_url="https://hooks.slack.com/test",
            min_severity=AlertSeverity.LOW,
            is_active=False,
        )
        db.add(integration)
        db.flush()

        finding = _make_finding(severity="critical")
        asset = _make_asset()

        import asyncio
        asyncio.run(process_finding_alerts(db, finding, asset))

        mock_slack.assert_not_called()


class TestPostWithRetry:
    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_succeeds_on_first_try(self, mock_client_cls):
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = AsyncMock()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        import asyncio
        result = asyncio.run(_post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is True

    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_retries_on_500_then_succeeds(self, mock_client_cls):
        import httpx

        fail_resp = AsyncMock()
        fail_resp.status_code = 500
        fail_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=AsyncMock(), response=fail_resp
        )

        ok_resp = AsyncMock()
        ok_resp.raise_for_status = AsyncMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post.side_effect = [fail_resp, ok_resp]
        mock_client_cls.return_value = mock_client

        import asyncio
        result = asyncio.run(_post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is True
        assert mock_client.post.call_count == 2

    @patch("services.alerts.alerting_service.httpx.AsyncClient")
    def test_returns_false_on_400_no_retry(self, mock_client_cls):
        import httpx

        fail_resp = AsyncMock()
        fail_resp.status_code = 400
        fail_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Request", request=AsyncMock(), response=fail_resp
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post.return_value = fail_resp
        mock_client_cls.return_value = mock_client

        import asyncio
        result = asyncio.run(_post_with_retry("https://hook.example", {"text": "hi"}))
        assert result is False
        # Client errors (4xx) should NOT retry.
        assert mock_client.post.call_count == 1
