from datetime import datetime, timezone, timedelta

from models.asset import Asset
from models.finding import Finding
from models.organization import Organization
from services.history.change_detector import (
    create_asset_snapshot,
    detect_changes,
    persist_alerts,
    _diff_subdomains,
    _diff_ports,
    _diff_ssl,
    _diff_findings,
)


def test_create_asset_snapshot(db):
    org = Organization(name="Snap Org")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="snap.example.com", criticality="prod")
    db.add(asset)
    db.flush()

    snapshot = create_asset_snapshot(db, asset.id)
    assert snapshot is not None
    assert snapshot.asset_id == asset.id
    assert snapshot.snapshot["asset_name"] == "snap.example.com"
    assert snapshot.snapshot["criticality"] == "prod"


def test_detect_changes_no_previous(db):
    org = Organization(name="Change Org 1")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change1.example.com")
    db.add(asset)
    db.flush()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    assert changes == []


def test_detect_changes_new_subdomain(db):
    org = Organization(name="Change Org 2")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change2.example.com")
    db.add(asset)
    db.flush()

    create_asset_snapshot(db, asset.id)

    from models.domain import Domain
    from models.subdomain import Subdomain

    domain = Domain(organization_id=org.id, asset_id=asset.id, domain="change2.example.com")
    db.add(domain)
    db.flush()

    sub = Subdomain(domain_id=domain.id, subdomain="new.change2.example.com", source="dns_brute")
    db.add(sub)
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    added = [c for c in changes if c["type"] == "subdomain_added"]
    assert len(added) == 1
    assert added[0]["title"] == "New subdomain discovered: new.change2.example.com"


def test_detect_changes_removed_subdomain(db):
    org = Organization(name="Change Org 3")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change3.example.com")
    db.add(asset)
    db.flush()

    from models.domain import Domain
    from models.subdomain import Subdomain

    domain = Domain(organization_id=org.id, asset_id=asset.id, domain="change3.example.com")
    db.add(domain)
    db.flush()

    sub = Subdomain(domain_id=domain.id, subdomain="old.change3.example.com", source="crt.sh")
    db.add(sub)
    db.commit()

    create_asset_snapshot(db, asset.id)

    db.delete(sub)
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    removed = [c for c in changes if c["type"] == "subdomain_removed"]
    assert len(removed) == 1
    assert removed[0]["title"] == "Subdomain no longer resolves: old.change3.example.com"


def test_detect_changes_port_opened(db):
    org = Organization(name="Change Org 4")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change4.example.com")
    db.add(asset)
    db.flush()

    from models.domain import Domain
    from models.subdomain import Subdomain
    from models.port import Port

    domain = Domain(organization_id=org.id, asset_id=asset.id, domain="change4.example.com")
    db.add(domain)
    db.flush()

    sub = Subdomain(domain_id=domain.id, subdomain="change4.example.com", source="primary")
    db.add(sub)
    db.flush()

    port = Port(subdomain_id=sub.id, port=8080, protocol="tcp", status="closed")
    db.add(port)
    db.commit()

    create_asset_snapshot(db, asset.id)

    port.status = "open"
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    opened = [c for c in changes if c["type"] == "port_opened"]
    assert len(opened) == 1
    assert "8080" in opened[0]["title"]


def test_detect_changes_port_closed(db):
    org = Organization(name="Change Org 5")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change5.example.com")
    db.add(asset)
    db.flush()

    from models.domain import Domain
    from models.subdomain import Subdomain
    from models.port import Port

    domain = Domain(organization_id=org.id, asset_id=asset.id, domain="change5.example.com")
    db.add(domain)
    db.flush()

    sub = Subdomain(domain_id=domain.id, subdomain="change5.example.com", source="primary")
    db.add(sub)
    db.flush()

    port = Port(subdomain_id=sub.id, port=22, protocol="tcp", status="open")
    db.add(port)
    db.commit()

    create_asset_snapshot(db, asset.id)

    port.status = "closed"
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    closed = [c for c in changes if c["type"] == "port_closed"]
    assert len(closed) == 1
    assert "22" in closed[0]["title"]


def test_detect_changes_ssl_risk_changed(db):
    org = Organization(name="Change Org 6")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change6.example.com")
    db.add(asset)
    db.flush()

    from models.domain import Domain
    from models.subdomain import Subdomain
    from models.ssl_result import SSLResult

    domain = Domain(organization_id=org.id, asset_id=asset.id, domain="change6.example.com")
    db.add(domain)
    db.flush()

    sub = Subdomain(domain_id=domain.id, subdomain="change6.example.com", source="primary")
    db.add(sub)
    db.flush()

    ssl = SSLResult(
        subdomain_id=sub.id,
        issuer="Test CA",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        expires_at=datetime.now(timezone.utc) + timedelta(days=100),
        self_signed=False,
        risk_level="low",
    )
    db.add(ssl)
    db.commit()

    create_asset_snapshot(db, asset.id)

    ssl.risk_level = "critical"
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    risk_changed = [c for c in changes if c["type"] == "ssl_risk_changed"]
    assert len(risk_changed) == 1
    assert risk_changed[0]["severity"] == "high"


def test_detect_changes_new_finding(db):
    org = Organization(name="Change Org 7")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change7.example.com")
    db.add(asset)
    db.flush()

    create_asset_snapshot(db, asset.id)

    db.add(Finding(
        organization_id=org.id,
        asset_id=asset.id,
        title="New Critical Finding",
        severity="critical",
        category="test",
    ))
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    new_finding = [c for c in changes if c["type"] == "finding_new"]
    assert len(new_finding) == 1
    assert new_finding[0]["severity"] == "critical"


def test_detect_changes_resolved_finding(db):
    org = Organization(name="Change Org 8")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="change8.example.com")
    db.add(asset)
    db.flush()

    finding = Finding(
        organization_id=org.id,
        asset_id=asset.id,
        title="Old Finding",
        severity="high",
        category="test",
    )
    db.add(finding)
    db.commit()

    create_asset_snapshot(db, asset.id)

    db.delete(finding)
    db.commit()

    create_asset_snapshot(db, asset.id)
    changes = detect_changes(db, asset.id)

    resolved = [c for c in changes if c["type"] == "finding_resolved"]
    assert len(resolved) == 1
    assert resolved[0]["severity"] == "info"


def test_persist_alerts(db):
    org = Organization(name="Alert Org")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="alert.example.com")
    db.add(asset)
    db.flush()

    changes = [
        {"type": "test", "asset_id": asset.id, "title": "Test Alert", "severity": "high", "details": "{}"},
        {"type": "test", "asset_id": asset.id, "title": "Test Alert 2", "severity": "medium", "details": "{}"},
    ]

    created = persist_alerts(db, changes, org.id)
    assert len(created) == 2

    from models.alert import Alert
    alerts = db.query(Alert).filter(Alert.organization_id == org.id).all()
    assert len(alerts) == 2
    assert alerts[0].title == "Test Alert"
    assert alerts[1].severity == "medium"