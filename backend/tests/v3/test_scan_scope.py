"""Task 1.2: scope mapping, pipeline gating, and scope recording (mocked)."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.scanning import scope as scope_policy
from app.scanning.registry import ScanPhase


class TestScopeMapping:
    def test_passive_is_discovery_only(self):
        assert scope_policy.phases_for_scope("passive") == frozenset({ScanPhase.DISCOVERY})
        assert not scope_policy.enrichment_allowed("passive")

    def test_active_adds_probing_but_no_enrichment(self):
        assert scope_policy.phases_for_scope("active") == frozenset({
            ScanPhase.DISCOVERY, ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
        })
        assert not scope_policy.enrichment_allowed("active")

    def test_full_adds_enrichment(self):
        assert scope_policy.phases_for_scope("full") == frozenset({
            ScanPhase.DISCOVERY, ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
        })
        assert scope_policy.enrichment_allowed("full")

    def test_nuclei_has_no_scope_slot_yet(self):
        # Phase 4 wires the nuclei template scanner into `full` as a new
        # registry phase; until then no scope may run it.
        phases = {p for s in scope_policy.SCOPES for p in scope_policy.phases_for_scope(s)}
        assert phases == frozenset({
            ScanPhase.DISCOVERY, ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
        })

    def test_normalize_defaults_and_rejects(self):
        assert scope_policy.normalize_scope(None) == "full"
        assert scope_policy.normalize_scope("Passive") == "passive"
        with pytest.raises(ValueError):
            scope_policy.normalize_scope("aggressive")


class TestPipelineGating:
    def _targets(self, db):
        import tasks.discovery_tasks as dt

        scan = SimpleNamespace(organization_id=1, id=1)
        persisted = {
            "subdomains": [SimpleNamespace(subdomain="x.example.com")],
        }
        return dt, scan, persisted

    def test_passive_makes_zero_target_calls(self, db, monkeypatch):
        import socket
        import tasks.discovery_tasks as dt

        def _boom(*a, **k):
            raise AssertionError("passive scope must not touch the network")

        monkeypatch.setattr(dt, "scan_ports", _boom)
        monkeypatch.setattr(dt, "analyze_ssl", _boom)
        monkeypatch.setattr(dt, "analyze_headers", _boom)
        monkeypatch.setattr(socket, "create_connection", _boom)
        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        monkeypatch.setattr(dt, "pinned_resolve", lambda host: "93.184.216.34")

        calls = []
        monkeypatch.setattr(
            dt, "_run_in_context",
            lambda ctx, modules: calls.append([m.phase for m in modules]) or {},
        )

        _, scan, persisted = self._targets(db)
        summary = dt._scan_targets(db, scan, persisted, "example.com", None, "passive")

        assert calls == []
        assert summary["ports_total"] == 0
        assert summary["ssl"] == {"scanned": 0, "issues": 0}
        assert summary["headers"] == {"scanned": 0, "issues": 0}

    def test_each_scope_runs_exactly_its_phases(self, db, monkeypatch):
        import tasks.discovery_tasks as dt

        seen = {}

        def fake_run(ctx, modules):
            for m in modules:
                seen.setdefault(ctx.scope, set()).add(m.phase)
            assert ctx.scope in ("active", "full")
            return {}

        monkeypatch.setattr(dt, "_run_in_context", fake_run)
        monkeypatch.setattr(dt, "pinned_resolve", lambda host: "93.184.216.34")
        monkeypatch.setattr(dt, "persist_port_results", lambda *a: None)
        monkeypatch.setattr(dt, "persist_ssl_result", lambda *a: None)

        for scope in ("active", "full"):
            seen.clear()
            _, scan, persisted = self._targets(db)
            dt._scan_targets(db, scan, persisted, "example.com", None, scope)
            assert seen[scope] == {ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER}

    def test_enrichment_dispatched_only_for_full(self, monkeypatch):
        import tasks.discovery_tasks as dt

        calls = []
        monkeypatch.setattr(
            "tasks.cve_tasks.enrich_asset_findings",
            SimpleNamespace(delay=lambda asset_id=None, **kw: calls.append(asset_id)),
        )
        scan = SimpleNamespace(id=7)

        dt._dispatch_enrichment(scan, 11, "passive")
        dt._dispatch_enrichment(scan, 11, "active")
        assert calls == []

        dt._dispatch_enrichment(scan, 11, "full")
        assert calls == [11]


class TestScopeRecording:
    def _register(self, client, username="scopeuser", org="Scope Org"):
        response = client.post(
            "/api/v1/auth/register",
            json={"username": username, "email": f"{username}@example.com",
                  "password": "password123", "organization": org},
        )
        assert response.status_code == 201, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def test_manual_scan_records_scope_and_forwards_it(
        self, client, db, org_factory, monkeypatch
    ):
        from models.user import User
        from models.verified_domain import VerifiedDomain

        headers = self._register(client)
        user = db.query(User).filter(User.username == "scopeuser").one()
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=user.organization_id, domain="scoped.example.com",
            method="dns_txt", status="verified", token="t",
            verified_at=now, expires_at=now + timedelta(days=90),
        ))
        db.commit()

        async def fake_resolve(domain):
            return {"domain": domain, "ip": "93.184.216.34"}

        monkeypatch.setattr(
            "services.discovery.domain_service.resolve_domain", fake_resolve
        )
        forwarded = {}
        import app.api.v1.scans as scans_api
        monkeypatch.setattr(
            scans_api.run_discovery, "delay",
            lambda scan_id=None, scope=None, **kw: forwarded.update(
                scan_id=scan_id, scope=scope),
        )

        response = client.post(
            "/api/v1/scans",
            json={"domain": "scoped.example.com", "scope": "passive"},
            headers=headers,
        )
        assert response.status_code == 202, response.text

        from models.scan_history import ScanHistory
        scan = db.query(ScanHistory).filter(
            ScanHistory.target == "scoped.example.com").one()
        assert scan.scope == "passive"
        assert forwarded == {"scan_id": scan.id, "scope": "passive"}

    def test_manual_scan_defaults_to_full(self, client, db, org_factory, monkeypatch):
        from models.user import User
        from models.verified_domain import VerifiedDomain

        headers = self._register(client, username="scopefull", org="ScopeFull Org")
        user = db.query(User).filter(User.username == "scopefull").one()
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=user.organization_id, domain="full.example.com",
            method="dns_txt", status="verified", token="t",
            verified_at=now, expires_at=now + timedelta(days=90),
        ))
        db.commit()

        async def fake_resolve(domain):
            return {"domain": domain, "ip": "93.184.216.34"}

        monkeypatch.setattr(
            "services.discovery.domain_service.resolve_domain", fake_resolve
        )
        import app.api.v1.scans as scans_api
        monkeypatch.setattr(
            scans_api.run_discovery, "delay", lambda scan_id=None, **kw: None
        )

        response = client.post(
            "/api/v1/scans", json={"domain": "full.example.com"}, headers=headers
        )
        assert response.status_code == 202, response.text

        from models.scan_history import ScanHistory
        scan = db.query(ScanHistory).filter(
            ScanHistory.target == "full.example.com").one()
        assert scan.scope == "full"

    def test_invalid_scope_rejected(self, client):
        headers = self._register(client, username="scopebad", org="ScopeBad Org")
        response = client.post(
            "/api/v1/scans",
            json={"domain": "x.example.com", "scope": "aggressive"},
            headers=headers,
        )
        assert response.status_code == 422

    def test_scheduled_scan_forwards_policy_scope(
        self, client, db, org_factory, monkeypatch
    ):
        from models import Asset, ScanPolicy
        from tasks.scheduler_tasks import process_due_scan_policies

        org, _ = org_factory("ScopePol Org", "scopepol", "scopepol@example.com")
        asset = Asset(organization_id=org.id, name="pol.example.com")
        db.add(asset)
        db.flush()
        db.add(ScanPolicy(
            organization_id=org.id, asset_id=asset.id, name="p",
            frequency="daily", scope="passive", is_active=True,
            next_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ))
        from models.verified_domain import VerifiedDomain
        now = datetime.now(timezone.utc)
        db.add(VerifiedDomain(
            organization_id=org.id, domain="pol.example.com",
            method="dns_txt", status="verified", token="t",
            verified_at=now, expires_at=now + timedelta(days=90),
        ))
        db.commit()

        import tasks.discovery_tasks as ddt
        forwarded = {}
        monkeypatch.setattr(
            ddt.run_discovery, "delay",
            lambda scan_id=None, scope=None, **kw: forwarded.update(
                scan_id=scan_id, scope=scope),
        )
        result = process_due_scan_policies()
        assert result["dispatched"] == 1
        assert forwarded["scope"] == "passive"

    def test_run_discovery_rejects_unknown_scope(self, db, org_factory):
        from models.scan_history import ScanHistory
        from tasks.discovery_tasks import run_discovery

        org, _ = org_factory("ScopeRun Org", "scoperun", "scoperun@example.com")
        scan = ScanHistory(organization_id=org.id, target="x.example.com",
                           status="pending")
        db.add(scan)
        db.commit()

        with pytest.raises(ValueError):
            run_discovery(scan.id, scope="aggressive")
        db.expire_all()
        assert db.get(ScanHistory, scan.id).status == "failed"
