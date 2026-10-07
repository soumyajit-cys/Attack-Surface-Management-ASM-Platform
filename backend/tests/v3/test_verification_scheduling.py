"""Task 1.1: scheduled-scan gating (skip vs grace) + Beat recheck task."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from models import Alert, Asset, ScanFrequency, ScanHistory, ScanPolicy
from models.verified_domain import VerifiedDomain
from tasks.scheduler_tasks import process_due_scan_policies
from tasks.verification_tasks import recheck_verified_domains


class TestBackstopGate:
    def _scan_row(self, db, org_factory, domain):
        org, _ = org_factory("Backstop Org", "backstop", "backstop@example.com")
        scan = ScanHistory(
            organization_id=org.id, target=domain, status="pending")
        db.add(scan)
        db.commit()
        return org, scan

    def test_direct_enqueue_skipped_before_pipeline_starts(
        self, db, org_factory, monkeypatch
    ):
        import tasks.discovery_tasks as dt

        async def _must_not_run(*a, **k):
            raise AssertionError("pipeline must not start for unverified target")

        monkeypatch.setattr(dt, "_collect", _must_not_run)
        _, scan = self._scan_row(db, org_factory, "direct.example.com")

        result = dt.run_discovery(scan.id)
        assert result == {"scan_id": scan.id, "status": "skipped"}

        db.expire_all()
        row = db.get(ScanHistory, scan.id)
        assert row.status == "skipped"
        assert "domain_not_verified" in (row.error or "")

    def test_direct_enqueue_grandfathered_passes_gate_and_alerts(
        self, db, org_factory, monkeypatch
    ):
        import tasks.discovery_tasks as dt

        org, scan = self._scan_row(db, org_factory, "gdirect.example.com")
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="gdirect.example.com",
            method="grandfathered", status="grandfathered", token="grandfathered",
            expires_at=now + timedelta(days=14),
        ))
        db.commit()

        async def _stop_after_gate(*a, **k):
            raise RuntimeError("passed-gate")

        monkeypatch.setattr(dt, "_collect", _stop_after_gate)
        # _with_retry would convert the sentinel; call the gate path only by
        # patching _with_retry to re-raise.
        monkeypatch.setattr(
            dt, "_with_retry",
            lambda task_self, scan_id, phase, fn: fn(),
        )
        with patch.object(dt, "_run_async", side_effect=RuntimeError("passed-gate")):
            with pytest.raises(RuntimeError, match="passed-gate"):
                dt.run_discovery(scan.id)

        db.expire_all()
        alert = db.query(Alert).filter(Alert.organization_id == org.id).one()
        assert "gdirect.example.com" in alert.title


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
