"""v3 scheduler tests: next-run computation, due-scan dispatch, digest emails."""

from datetime import datetime, timezone

from models import ScanFrequency, ScanPolicy, Asset, ScanHistory, EmailDigestConfig
from tasks.scheduler_tasks import (
    _digest_due,
    compute_next_run,
    process_due_scan_policies,
)


class TestComputeNextRun:
    def test_daily_next_day(self):
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_run(ScanFrequency.DAILY, None, now)
        assert nxt.date().isoformat() == "2026-08-29"
        assert nxt.hour == 9

    def test_weekly_next_monday(self):
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)  # Friday
        nxt = compute_next_run(ScanFrequency.WEEKLY, None, now)
        assert nxt.weekday() == 0  # Monday
        assert nxt.date().isoformat() == "2026-08-31"

    def test_monthly_first_of_next_month(self):
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_run(ScanFrequency.MONTHLY, None, now)
        assert nxt.day == 1
        assert nxt.month == 9

    def test_custom_cron(self):
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_run(ScanFrequency.CUSTOM_CRON, "0 3 * * 5", now)
        assert nxt.weekday() == 4  # Friday
        assert nxt.hour == 3

    def test_invalid_cron_falls_back_to_daily(self):
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_run(ScanFrequency.CUSTOM_CRON, "not-a-cron", now)
        assert nxt.date().isoformat() == "2026-08-29"

    def test_accepts_string_frequency(self):
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        nxt = compute_next_run("daily", None, now)
        assert nxt.date().isoformat() == "2026-08-29"


class TestProcessDueScanPolicies:
    def test_dispatches_due_policy_and_updates_runs(
        self, db, org_factory, monkeypatch
    ):
        from models.scan_history import ScanHistory
        from models.asset import Asset

        org, user = org_factory("Pol Org", "pol_org", "pol_org@test.com")

        asset = Asset(organization_id=org.id, name="policy-test.example.com")
        db.add(asset)
        db.flush()

        policy = ScanPolicy(
            organization_id=org.id,
            asset_id=asset.id,
            name="Due policy",
            frequency=ScanFrequency.DAILY,
            scope="full",
            is_active=True,
            next_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),  # overdue
        )
        db.add(policy)
        db.commit()

        dispatched = []

        def fake_delay(self, scan_id, **kw):
            dispatched.append(scan_id)

        monkeypatch.setattr("tasks.discovery_tasks.run_discovery.delay", fake_delay)
        # schedule task imports delay from discovery_tasks lazily; patch module fn
        import tasks.discovery_tasks as dt

        monkeypatch.setattr(dt.run_discovery, "delay", fake_delay)

        result = process_due_scan_policies()
        db.refresh(policy)

        assert result["dispatched"] == 1
        assert policy.last_run_at is not None
        assert policy.next_run_at is not None and policy.next_run_at > datetime(2026, 1, 1, tzinfo=timezone.utc)

        scans = db.query(ScanHistory).filter(
            ScanHistory.organization_id == org.id
        ).all()
        assert len(scans) == 1
        assert scans[0].target == "policy-test.example.com"

    def test_skips_future_policy(self, db, org_factory, monkeypatch):
        org, user = org_factory("Pol Org2", "pol_org2", "pol_org2@test.com")
        asset = Asset(organization_id=org.id, name="future.example.com")
        db.add(asset)
        db.flush()

        policy = ScanPolicy(
            organization_id=org.id,
            asset_id=asset.id,
            name="Future policy",
            frequency=ScanFrequency.WEEKLY,
            is_active=True,
            next_run_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        db.add(policy)
        db.commit()

        import tasks.discovery_tasks as dt
        calls = []
        monkeypatch.setattr(dt.run_discovery, "delay", lambda self, **kw: calls.append(kw))

        result = process_due_scan_policies()
        assert result["dispatched"] == 0
        assert calls == []

    def test_skips_inactive_policy(self, db, org_factory):
        org, user = org_factory("Pol Org3", "pol_org3", "pol_org3@test.com")
        asset = Asset(organization_id=org.id, name="inactive.example.com")
        db.add(asset)
        db.flush()

        policy = ScanPolicy(
            organization_id=org.id,
            asset_id=asset.id,
            name="Inactive",
            frequency=ScanFrequency.DAILY,
            is_active=False,
            next_run_at=None,
        )
        db.add(policy)
        db.commit()

        result = process_due_scan_policies()
        assert result["dispatched"] == 0


class TestDigestDue:
    def _config(self, **overrides):
        defaults = dict(
            organization_id=1,
            frequency="daily",
            day_of_week=1,
            hour_utc=9,
            recipient_emails="a@b.com",
            min_severity="medium",
            is_active=True,
        )
        defaults.update(overrides)

        class Cfg:
            pass

        c = Cfg()
        for k, v in defaults.items():
            setattr(c, k, v)
        return c

    def test_daily_due_when_window_passed(self):
        now = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
        cfg = self._config(frequency="daily", hour_utc=9, last_sent_at=None)
        assert _digest_due(cfg, now)

    def test_daily_not_due_before_hour(self):
        now = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)
        cfg = self._config(frequency="daily", hour_utc=9, last_sent_at=None)
        assert not _digest_due(cfg, now)

    def test_daily_not_due_after_already_sent(self):
        now = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
        cfg = self._config(
            frequency="daily",
            hour_utc=9,
            last_sent_at=datetime(2026, 8, 28, 9, 30, tzinfo=timezone.utc),
        )
        assert not _digest_due(cfg, now)

    def test_weekly_due_on_configured_day(self):
        now = datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc)  # Monday
        cfg = self._config(frequency="weekly", day_of_week=0, hour_utc=9)
        assert _digest_due(cfg, now)

    def test_weekly_not_due_on_other_day(self):
        now = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)  # Friday
        cfg = self._config(frequency="weekly", day_of_week=0, hour_utc=9)
        assert not _digest_due(cfg, now)


class TestEmailDigestTask:
    def test_digest_runs_without_error_on_empty_org(
        self, db, org_factory, monkeypatch
    ):
        from tasks.scheduler_tasks import send_due_email_digests
        from unittest.mock import AsyncMock

        org, user = org_factory("Digest Org", "digest_org", "digest_org@test.com")

        cfg = EmailDigestConfig(
            organization_id=org.id,
            frequency="daily",
            hour_utc=9,
            recipient_emails="test@receiver.com",
            min_severity="medium",
            is_active=True,
            last_sent_at=None,
        )
        db.add(cfg)
        db.commit()

        monkeypatch.setattr(
            "tasks.scheduler_tasks.send_email", lambda *a, **k: True
        )

        result = send_due_email_digests()
        assert result["sent"] == 1
        db.refresh(cfg)
        assert cfg.last_sent_at is not None