from models.asset import Asset
from models.finding import Finding


def _seed_org_data(db, org_factory, org_name, prefix):
    org, user = org_factory(org_name, prefix, f"{prefix}@example.com")

    asset = Asset(organization_id=org.id, name=f"{prefix}-asset.example.com")
    db.add(asset)
    db.flush()

    for severity in ("critical", "high", "medium", "low"):
        db.add(Finding(
            organization_id=org.id,
            asset_id=asset.id,
            title=f"{prefix} finding {severity}",
            severity=severity,
            category="test",
        ))
    db.commit()
    return org, user, asset


def test_tenant_isolation_findings(client, org_factory, auth_headers):
    _seed_org_data(db_factory(), org_factory, "OrgA", "alice_a")
    _seed_org_data(db_factory(), org_factory, "OrgB", "bob_b")

    headers_a = auth_headers("alice_a")
    headers_b = auth_headers("bob_b")

    findings_a = client.get("/findings/", headers=headers_a).json()
    findings_b = client.get("/findings/", headers=headers_b).json()

    assert findings_a["total"] == 4
    assert findings_b["total"] == 4

    for item in findings_a["items"]:
        assert "alice_a" in item["title"]
        assert "bob_b" not in item["title"]

    for item in findings_b["items"]:
        assert "bob_b" in item["title"]
        assert "alice_a" not in item["title"]


def test_tenant_isolation_dashboard(client, org_factory, auth_headers):
    _seed_org_data(db_factory(), org_factory, "OrgC", "carol_c")
    _seed_org_data(db_factory(), org_factory, "OrgD", "dave_d")

    dash_a = client.get(
        "/dashboard/",
        headers=auth_headers("carol_c"),
    ).json()
    dash_b = client.get(
        "/dashboard/",
        headers=auth_headers("dave_d"),
    ).json()

    assert dash_a["assets"] == 1
    assert dash_a["critical"] == 1
    assert dash_a["findings"] == 4
    assert dash_b["findings"] == 4
    assert dash_a["critical"] == dash_b["critical"]


def test_scan_status_is_org_scoped(client, org_factory, auth_headers, db):
    from models.scan_history import ScanHistory

    org_a, _ = _seed_org_data(db_factory(), org_factory, "OrgE", "erin_e")
    _, org_b_user = org_factory("OrgF", "frank_f", "frank_f@example.com")

    scan = ScanHistory(
        organization_id=org_a.id,
        target="scan-a.example.com",
        status="completed",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    own = client.get(
        f"/scan/{scan.id}",
        headers=auth_headers("erin_e"),
    )
    assert own.status_code == 200

    other = client.get(
        f"/scan/{scan.id}",
        headers=auth_headers("frank_f"),
    )
    assert other.status_code == 404


def db_factory():
    from tests.conftest import _unused
    return None