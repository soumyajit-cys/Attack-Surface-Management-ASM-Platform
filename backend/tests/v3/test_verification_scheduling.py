"""Task 1.1: scheduled-scan gating (skip vs grace) + Beat recheck task."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from models import Alert, Asset, ScanFrequency, ScanHistory, ScanPolicy
from models.verified_domain import VerifiedDomain
from tasks.scheduler_tasks import process_due_scan_policies
from tasks.verification_tasks import recheck_verified_domains


def _policy(db, org_factory, domain, org_name="SchedV Org", username="schedv"):
    org, _ = org_factory(org_name, username, f"{username}@example.com")
    asset = Asset(organization_id=org.id, name=domain)
    db.add(asset)
    db.flush()
    policy = ScanPolicy(
        organization_id=org.id,
        asset_id=asset.id,
        name=f"policy-{domain}",
        frequency=ScanFrequency.DAILY,
        scope="full",
        is_active=True,
        next_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db.add(policy)
    db.commit()
    return org, asset, policy


def _no_dispatch(monkeypatch):
    import tasks.discovery_tasks as dt
    calls = []
    monkeypatch.setattr(
        dt.run_discovery, "delay", lambda scan_id=None, **kw: calls.append(scan_id)
    )
    return calls


class TestScheduledGating:
    def test_unverified_policy_scan_skipped_and_recorded(self, db, org_factory, monkeypatch):
        calls = _no_dispatch(monkeypatch)
        org, asset, policy = _policy(db, org_factory, "never.example.com")

        result = process_due_scan_policies()

        assert result["skipped"] == 1
        assert result["dispatched"] == 0
        assert calls == []

        db.expire_all()
        scan = db.query(ScanHistory).filter(
            ScanHistory.organization_id == org.id
        ).one()
        assert scan.status == "skipped"
        assert "domain_not_verified" in (scan.error or "")

        db.refresh(policy)
        assert policy.next_run_at > datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_grandfathered_policy_runs_with_warning_alert(self, db, org_factory, monkeypatch):
        calls = _no_dispatch(monkeypatch)
        org, asset, policy = _policy(
            db, org_factory, "grace.example.com",
            org_name="Grace Org", username="grace",
        )
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="grace.example.com",
            method="grandfathered", status="grandfathered", token="grandfathered",
            expires_at=now + timedelta(days=14),
        ))
        db.commit()

        result = process_due_scan_policies()

        assert result["dispatched"] == 1
        assert result["skipped"] == 0
        assert len(calls) == 1

        db.expire_all()
        alert = db.query(Alert).filter(Alert.organization_id == org.id).one()
        assert "grace.example.com" in alert.title
        assert "before" in alert.title

    def test_lapsed_grandfathered_policy_skipped(self, db, org_factory, monkeypatch):
        _no_dispatch(monkeypatch)
        org, asset, policy = _policy(
            db, org_factory, "lapsed.example.com",
            org_name="Lapsed Org", username="lapsed",
        )
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="lapsed.example.com",
            method="grandfathered", status="grandfathered", token="grandfathered",
            expires_at=now - timedelta(days=1),
        ))
        db.commit()

        result = process_due_scan_policies()
        assert result["skipped"] == 1
        assert result["dispatched"] == 0


class TestRecheckTask:
    def _row(self, db, org_factory, domain, status, days_valid, org_name, username):
        org, _ = org_factory(org_name, username, f"{username}@example.com")
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain=domain, method="dns_txt",
            status=status, token="t",
            verified_at=now if status == "verified" else None,
            expires_at=now + timedelta(days=days_valid),
        ))
        db.commit()
        return org

    def test_failed_recheck_expires_verified_row(self, db, org_factory):
        self._row(db, org_factory, "gone.example.com", "verified", 90,
                  "Gone Org", "gone")
        with patch(
            "tasks.verification_tasks.check_row",
            new=AsyncMock(return_value=(False, "gone")),
        ):
            result = recheck_verified_domains()
        assert result == {"rechecked": 1, "expired": 1, "time_expired": 0}
        db.expire_all()
        row = db.query(VerifiedDomain).filter(
            VerifiedDomain.domain == "gone.example.com").one()
        assert row.status == "expired"

    def test_successful_recheck_keeps_expiry(self, db, org_factory):
        self._row(db, org_factory, "kept.example.com", "verified", 90,
                  "Kept Org", "kept")
        before = db.query(VerifiedDomain).filter(
            VerifiedDomain.domain == "kept.example.com").one().expires_at
        with patch(
            "tasks.verification_tasks.check_row",
            new=AsyncMock(return_value=(True, "ok")),
        ):
            result = recheck_verified_domains()
        assert result["expired"] == 0
        db.expire_all()
        row = db.query(VerifiedDomain).filter(
            VerifiedDomain.domain == "kept.example.com").one()
        assert row.status == "verified"
        assert row.expires_at == before
        assert row.last_checked_at is not None

    def test_time_expired_rows_flip_without_live_check(self, db, org_factory):
        self._row(db, org_factory, "stale.example.com", "verified", -2,
                  "Stale Org", "stale")
        with patch(
            "tasks.verification_tasks.check_row",
            new=AsyncMock(side_effect=AssertionError("must not be called")),
        ):
            result = recheck_verified_domains()
        assert result["time_expired"] == 1
        assert result["rechecked"] == 0
        db.expire_all()
        row = db.query(VerifiedDomain).filter(
            VerifiedDomain.domain == "stale.example.com").one()
        assert row.status == "expired"

    def test_lapsed_grandfathered_row_expires_without_live_check(
        self, db, org_factory
    ):
        org, _ = org_factory("Grace Gone Org", "gracegone", "gracegone@example.com")
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="grace.example.com",
            method="grandfathered", status="grandfathered", token="grandfathered",
            expires_at=now - timedelta(days=1),
        ))
        db.commit()
        with patch(
            "tasks.verification_tasks.check_row",
            new=AsyncMock(side_effect=AssertionError("must not be called")),
        ):
            result = recheck_verified_domains()
        assert result["time_expired"] == 1
        db.expire_all()
        row = db.query(VerifiedDomain).filter(
            VerifiedDomain.domain == "grace.example.com").one()
        assert row.status == "expired"
