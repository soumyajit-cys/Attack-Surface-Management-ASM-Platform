from models.asset import Asset
from models.finding import Finding


def _seed(db, org_factory, username, count=5):
    org, _ = org_factory(f"Org-{username}", username, f"{username}@example.com")
    asset = Asset(organization_id=org.id, name=f"{username}.example.com")
    db.add(asset)
    db.flush()
    severities = ["critical", "high", "medium", "low", "info"]
    for i in range(count):
        db.add(Finding(
            organization_id=org.id,
            asset_id=asset.id,
            title=f"{username} finding {i}",
            severity=severities[i % len(severities)],
            category="test",
        ))
    db.commit()
    return org, asset


def test_findings_pagination(client, db, org_factory, auth_headers):
    _seed(db, org_factory, "pager")

    headers = auth_headers("pager")

    page1 = client.get(
        "/findings/?page=1&page_size=2",
        headers=headers,
    ).json()
    page2 = client.get(
        "/findings/?page=2&page_size=2",
        headers=headers,
    ).json()

    assert page1["total"] == 5
    assert page2["total"] == 5
    assert len(page1["items"]) == 2
    assert len(page2["items"]) == 2

    ids1 = {i["id"] for i in page1["items"]}
    ids2 = {i["id"] for i in page2["items"]}
    assert ids1.isdisjoint(ids2)


def test_findings_severity_filter(client, db, org_factory, auth_headers):
    _seed(db, org_factory, "severe")

    response = client.get(
        "/findings/?severity=critical",
        headers=auth_headers("severe"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert all(i["severity"] == "critical" for i in body["items"])


def test_dashboard_counts(client, db, org_factory, auth_headers):
    _seed(db, org_factory, "counter")

    response = client.get(
        "/dashboard/",
        headers=auth_headers("counter"),
    )
    assert response.status_code == 200
    body = response.json()

    assert body["assets"] == 1
    assert body["findings"] == 5
    assert body["critical"] == 1
    assert body["high"] == 1
    assert body["medium"] == 1
    assert body["low"] == 1
    assert body["info"] == 1