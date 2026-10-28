"""Dispatch-race regression tests (audit HIGH #1/#2, MED #3, LOW #8).

Celery delivery is at-least-once (``acks_late`` + ``reject_on_worker_lost``),
so the system must hold these invariants:

* a redelivered/late task must never re-execute a scan that is already
  claimed, running, or terminal (idempotent claim);
* the scheduler must COMMIT the pending scan row before publishing the task
  (a worker racing an uncommitted row reads ``not_found``);
* overlapping scheduler ticks must not double-dispatch one due policy
  (atomic single-flight claim on ``next_run_at``);
* a failed publish must never leave a scan ``pending`` forever, on the
  scheduler path or the API path.
"""

from datetime import datetime, timedelta, timezone

import pytest

import tasks.discovery_tasks as dt
from models import Asset, ScanFrequency, ScanPolicy, VerifiedDomain
from models.scan_history import ScanHistory
from tasks.discovery_tasks import run_discovery
from tasks.scheduler_tasks import process_due_scan_policies
from utils.database import SessionLocal


def _register(client, username):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "supersecret1",
            "organization": f"Org-{username}",
        },
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _org_id_for(username):
    from models.user import User

    probe = SessionLocal()
    user = probe.query(User).filter(User.username == username).first()
    org_id = user.organization_id
    probe.close()
    return org_id


def _verify_domain(db, org_id, domain):
    now = datetime.now(timezone.utc)
    db.add(
        VerifiedDomain(
            organization_id=org_id,
            domain=domain,
            method="dns_txt",
            status="verified",
            token="test-token",
            verified_at=now,
            expires_at=now + timedelta(days=90),
        )
    )
    db.commit()


@pytest.fixture()
def mock_pipeline(monkeypatch):
    """Same proven fake shapes as tests/test_scan_pipeline.py; phase-1
    resolution calls are counted so tests can assert the pipeline ran
    exactly once (or zero times for blocked deliveries)."""
    calls: list[str] = []

    async def fake_resolve(domain):
        calls.append(domain)
        return {"domain": domain, "ip": "93.184.216.34"}

    async def fake_dns(domain):
        return [{"type": "A", "value": "93.184.216.34"}]

    async def fake_subdomains(domain):
        return ["www.example.com"]

    async def fake_whois(domain):
        return {"registrar": "Test Registrar", "asn": "AS15133"}

    async def fake_ports(host):
        return [
            {"port": 443, "status": "open", "protocol": "tcp", "service": "https"},
        ]

    async def fake_ssl(host):
        return {
            "issuer": "CN=Test CA",
            "subject": "CN=example.com",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(days=200)
            ).isoformat(),
            "self_signed": False,
            "san": ["example.com"],
        }

    async def fake_headers(url):
        return []

    monkeypatch.setattr(dt, "resolve_domain", fake_resolve)
    monkeypatch.setattr(dt, "enumerate_dns", fake_dns)
    monkeypatch.setattr(dt, "discover_subdomains", fake_subdomains)
    monkeypatch.setattr(dt, "get_whois", fake_whois)
    monkeypatch.setattr("services.scanner.port_scanner.scan_ports", fake_ports)
    monkeypatch.setattr("services.scanner.ssl_scanner.analyze_ssl", fake_ssl)
    monkeypatch.setattr(
        "services.scanner.header_scanner.analyze_headers", fake_headers
    )
    return calls


# ── HIGH #1: idempotent execution claim ──────────────────────────────────────


def test_redelivered_completed_scan_not_reexecuted(client, db, mock_pipeline):
    headers = _register(client, "idem_owner")
    _verify_domain(db, _org_id_for("idem_owner"), "example.com")

    response = client.post(
        "/api/v1/scans", json={"domain": "example.com"}, headers=headers
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    assert (
        db.query(ScanHistory).filter(ScanHistory.id == scan_id).first().status
        == "completed"
    )
    runs_after_first = len(mock_pipeline)
    assert runs_after_first == 1

    # What a broker redelivery / late duplicate looks like:
    result = run_discovery(scan_id)

    assert result["status"] == "completed"  # reports current status, no rerun
    assert len(mock_pipeline) == runs_after_first, "pipeline re-executed"
    row = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    assert row.status == "completed"


def test_running_scan_blocks_duplicate_delivery(client, db, mock_pipeline):
    headers = _register(client, "idem_owner2")
    org_id = _org_id_for("idem_owner2")
    _verify_domain(db, org_id, "example.com")

    # Simulate another delivery actively holding the claim:
    scan = ScanHistory(
        organization_id=org_id, target="example.com", status="running"
    )
    db.add(scan)
    db.commit()

    result = run_discovery(scan.id)

    assert result["status"] == "running"
    assert mock_pipeline == [], "duplicate delivery re-executed the pipeline"
    row = db.query(ScanHistory).filter(ScanHistory.id == scan.id).first()
    assert row.status == "running"


# ── HIGH #2: scheduler must persist the scan row before publishing ──────────


def test_scheduler_commits_scan_before_dispatch(db, org_factory, monkeypatch):
    org, user = org_factory("Dispatch Org", "disp_org", "disp_org@test.com")
    asset = Asset(organization_id=org.id, name="sched.example.com")
    db.add(asset)
    db.flush()
    _verify_domain(db, org.id, "sched.example.com")
    policy = ScanPolicy(
        organization_id=org.id,
        asset_id=asset.id,
        name="Dispatch policy",
        frequency=ScanFrequency.DAILY,
        scope="full",
        is_active=True,
        next_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db.add(policy)
    db.commit()

    seen = {}

    def fake_delay(scan_id=None, **kw):
        # The worker opens its own session: only a COMMITTED row is visible.
        probe = SessionLocal()
        row = probe.get(ScanHistory, scan_id)
        seen["visible"] = row is not None
        seen["status"] = row.status if row else None
        probe.close()

    monkeypatch.setattr(dt.run_discovery, "delay", fake_delay)

    result = process_due_scan_policies()

    assert result["dispatched"] == 1
    assert seen["visible"] is True, "scan row uncommitted at dispatch time"
    assert seen["status"] == "pending"


# ── MED #3: single-flight claim on due policies ──────────────────────────────


def test_policy_claim_is_single_flight(db, org_factory):
    from tasks.scheduler_tasks import _claim_policy, compute_next_run

    org, user = org_factory("Race Org", "race_org", "race_org@test.com")
    asset = Asset(organization_id=org.id, name="race.example.com")
    db.add(asset)
    db.flush()
    policy = ScanPolicy(
        organization_id=org.id,
        asset_id=asset.id,
        name="Race policy",
        frequency=ScanFrequency.DAILY,
        scope="full",
        is_active=True,
        next_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db.add(policy)
    db.commit()

    now = datetime.now(timezone.utc)
    next_at = compute_next_run(ScanFrequency.DAILY, None, now)

    first = SessionLocal()
    second = SessionLocal()
    try:
        assert _claim_policy(first, policy.id, now, next_at) is True
        first.commit()
        # A second tick that read the same stale due row must lose:
        assert _claim_policy(second, policy.id, now, next_at) is False
        second.commit()
    finally:
        first.close()
        second.close()


# ── LOW #8: failed publish must not strand the scan as pending ───────────────


def test_scheduler_dispatch_failure_marks_scan_failed(
    db, org_factory, monkeypatch
):
    org, user = org_factory("Broker Org", "broker_org", "broker_org@test.com")
    asset = Asset(organization_id=org.id, name="broker.example.com")
    db.add(asset)
    db.flush()
    _verify_domain(db, org.id, "broker.example.com")
    policy = ScanPolicy(
        organization_id=org.id,
        asset_id=asset.id,
        name="Broker policy",
        frequency=ScanFrequency.DAILY,
        scope="full",
        is_active=True,
        next_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    db.add(policy)
    db.commit()

    def boom(scan_id=None, **kw):
        raise ConnectionError("broker down")

    monkeypatch.setattr(dt.run_discovery, "delay", boom)

    result = process_due_scan_policies()

    assert result["failed"] == 1
    row = (
        db.query(ScanHistory)
        .filter(ScanHistory.organization_id == org.id)
        .one()
    )
    assert row.status == "failed", "scan stranded as pending after dispatch loss"
    assert row.error == "dispatch_failed"
    db.refresh(policy)
    assert policy.next_run_at > datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_api_dispatch_failure_marks_scan_failed(client, db, monkeypatch):
    headers = _register(client, "disp_fail")
    org_id = _org_id_for("disp_fail")
    _verify_domain(db, org_id, "example.com")

    def boom(scan_id=None, **kw):
        raise ConnectionError("broker down")

    monkeypatch.setattr(dt.run_discovery, "delay", boom)

    response = client.post(
        "/api/v1/scans", json={"domain": "example.com"}, headers=headers
    )

    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "scan_dispatch_failed"
    row = (
        db.query(ScanHistory)
        .filter(ScanHistory.organization_id == org_id)
        .one()
    )
    assert row.status == "failed", "scan stranded as pending after dispatch loss"
    assert row.error == "dispatch_failed"
