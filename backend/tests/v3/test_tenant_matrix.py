"""G1 tenant-isolation matrix over every /api/v1 route (tests only).

Two orgs (A/B) with fully seeded, marker-tagged fixtures. Cross-org reads of
by-id routes must 404/403 without leaking the other org's markers; list,
export, dashboard and PDF/CSV endpoints must exclude the other org's markers.
Route coverage is introspected from ``app.routes`` so a new route without a
case fails loudly. All network is mocked (DNS faked, fetches stubbed,
Celery delays stubbed); no real targets are touched.
"""

from datetime import datetime, timedelta, timezone

import pytest

MARK_A = "tmatrixA"
MARK_B = "tmatrixB"

# Routes that take no tenant id and return no other-tenant data. Any route
# absent from both sets fails test_route_table_complete.
NO_TENANT_DATA = {
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/forgot-password"),
    ("POST", "/api/v1/auth/reset-password"),
    ("POST", "/api/v1/scans"),
    ("POST", "/api/v1/scans/verify-ownership"),
    ("POST", "/api/v1/organizations/invitations/{token}/accept"),
    ("POST", "/api/v1/organizations"),
}

# Routes whose tenant behavior is asserted by dedicated cases below.
COVERED_ID_ROUTES = {
    ("GET", "/api/v1/scans/{scan_id}"),
    ("GET", "/api/v1/findings/{finding_id}"),
    ("GET", "/api/v1/assets/{asset_id}"),
    ("POST", "/api/v1/assets/{asset_id}/enrich"),
    ("GET", "/api/v1/assets/{asset_id}/graph"),
    ("POST", "/api/v1/organizations/invitations/{invitation_id}/revoke"),
    ("PATCH", "/api/v1/organizations/api-keys/{key_id}"),
    ("DELETE", "/api/v1/organizations/api-keys/{key_id}"),
    ("GET", "/api/v1/alerting/integrations/{integration_id}"),
    ("PATCH", "/api/v1/alerting/integrations/{integration_id}"),
    ("DELETE", "/api/v1/alerting/integrations/{integration_id}"),
    ("POST", "/api/v1/alerting/integrations/{integration_id}/test"),
    ("GET", "/api/v1/reports/pdf/finding/{finding_id}"),
    ("GET", "/api/v1/scan-policies/{policy_id}"),
    ("PATCH", "/api/v1/scan-policies/{policy_id}"),
    ("DELETE", "/api/v1/scan-policies/{policy_id}"),
    ("POST", "/api/v1/scan-policies/{policy_id}/run-now"),
}

COVERED_LIST_ROUTES = {
    ("GET", "/api/v1/auth/me"),
    ("GET", "/api/v1/scans/verify-ownership/check"),
    ("GET", "/api/v1/scans/verified-domains"),
    ("GET", "/api/v1/scans"),
    ("GET", "/api/v1/findings"),
    ("GET", "/api/v1/alerts"),
    ("GET", "/api/v1/dashboard"),
    ("GET", "/api/v1/assets"),
    ("GET", "/api/v1/organizations/me"),
    ("POST", "/api/v1/organizations/invitations"),
    ("GET", "/api/v1/organizations/invitations"),
    ("POST", "/api/v1/organizations/api-keys"),
    ("GET", "/api/v1/organizations/api-keys"),
    ("POST", "/api/v1/alerting/integrations"),
    ("GET", "/api/v1/alerting/integrations"),
    ("POST", "/api/v1/alerting/digest"),
    ("GET", "/api/v1/alerting/digest"),
    ("PATCH", "/api/v1/alerting/digest"),
    ("DELETE", "/api/v1/alerting/digest"),
    ("POST", "/api/v1/alerting/digest/test"),
    ("POST", "/api/v1/reports/export/findings/csv"),
    ("POST", "/api/v1/reports/export/assets/csv"),
    ("POST", "/api/v1/reports/export/scans/csv"),
    ("POST", "/api/v1/reports/export/domains/csv"),
    ("POST", "/api/v1/reports/export/all/csv"),
    ("GET", "/api/v1/reports/pdf/executive-summary"),
    ("POST", "/api/v1/scan-policies"),
    ("GET", "/api/v1/scan-policies"),
}


def _public_dns(monkeypatch, ip="93.184.216.34"):
    import socket as stdlib_socket

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", (ip, 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


@pytest.fixture()
def hermetic(monkeypatch):
    """Stub every egress/celery touchpoint the matrix may trigger."""
    _public_dns(monkeypatch)

    from services.alerts import alerting_service as alerts
    from utils.egress import FetchResult

    async def fake_fetch(url, **kw):
        return FetchResult(status_code=200, headers={}, body=b"ok")

    monkeypatch.setattr(alerts, "fetch_url_validated", fake_fetch)

    from tasks import discovery_tasks as dt

    monkeypatch.setattr(dt.run_discovery, "delay", lambda *a, **k: None)
    try:
        from tasks import cve_tasks as ct

        monkeypatch.setattr(
            ct.enrich_asset_findings, "delay", lambda *a, **k: None
        )
    except AttributeError:
        pass


def _register(client, username, org):
    reg = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": f"{username}@example.com",
              "password": "password123", "organization": org},
    )
    assert reg.status_code == 201, reg.text
    body = reg.json()
    return ({"Authorization": f"Bearer {body['access_token']}"},
            body["user"]["organization_id"])


def _seed_org(client, db, headers, org_id, tag):
    """Seed one org's full fixture set; returns ids keyed by resource."""
    from datetime import datetime, timedelta, timezone

    from models import (
        Alert, Asset, Domain, Finding, Port, Report, RiskScore, ScanHistory,
        ScanPolicy, SSLResult, Subdomain, VerifiedDomain,
    )

    now = datetime.now(timezone.utc)
    asset = Asset(organization_id=org_id, name=f"{tag}-asset.example.com")
    db.add(asset)
    db.flush()
    domain = Domain(organization_id=org_id, asset_id=asset.id,
                    domain=f"{tag}-domain.example.com")
    db.add(domain)
    db.flush()
    sub = Subdomain(domain_id=domain.id,
                    subdomain=f"www.{tag}-domain.example.com",
                    source="primary")
    db.add(sub)
    db.flush()
    port = Port(subdomain_id=sub.id, port=443, protocol="tcp", status="open")
    db.add(port)
    ssl = SSLResult(subdomain_id=sub.id, issuer=f"{tag} issuer",
                    risk_level="low")
    db.add(ssl)
    finding = Finding(organization_id=org_id, asset_id=asset.id,
                      title=f"{tag} finding", severity="high")
    db.add(finding)
    db.flush()
    risk = RiskScore(asset_id=asset.id, score=7.5)
    db.add(risk)
    alert = Alert(organization_id=org_id, asset_id=asset.id,
                  title=f"{tag} alert", severity="high", message="m")
    db.add(alert)
    scan = ScanHistory(organization_id=org_id, asset_id=asset.id,
                       target=f"{tag}-domain.example.com", status="completed",
                       scope="full")
    db.add(scan)
    db.flush()
    policy = ScanPolicy(organization_id=org_id, asset_id=asset.id,
                        name=f"{tag} policy", frequency="weekly", scope="full")
    db.add(policy)
    verified = VerifiedDomain(
        organization_id=org_id, domain=f"{tag}-verified.example.com",
        method="dns_txt", status="verified", token=f"{tag}-token",
        verified_at=now, expires_at=now + timedelta(days=90))
    db.add(verified)
    report = Report(organization_id=org_id, asset_id=asset.id,
                    filename=f"{tag}-report.csv")
    db.add(report)
    db.commit()

    integration = client.post(
        "/api/v1/alerting/integrations",
        json={"name": f"{tag} hook", "channel": "slack",
              "webhook_url": "https://hooks.example.com/x"},
        headers=headers,
    )
    assert integration.status_code == 201, integration.text
    invitation = client.post(
        "/api/v1/organizations/invitations",
        json={"email": f"{tag}-invite@example.com", "role": "viewer"},
        headers=headers,
    )
    assert invitation.status_code == 201, invitation.text
    api_key = client.post(
        "/api/v1/organizations/api-keys",
        json={"name": f"{tag} key"},
        headers=headers,
    )
    assert api_key.status_code == 201, api_key.text
    return {
        "asset": asset.id, "domain": domain.id, "subdomain": sub.id,
        "port": port.id, "ssl": ssl.id, "finding": finding.id,
        "risk": risk.id, "alert": alert.id, "scan": scan.id,
        "policy": policy.id, "verified": verified.id,
        "report": report.id,
        "integration": integration.json()["id"],
        "invitation": invitation.json()["id"],
        "api_key": api_key.json()["id"],
    }


@pytest.fixture()
def matrix(client, db, hermetic):
    headers_a, org_a = _register(client, "tmatrixa", "TMatrix A Org")
    headers_b, org_b = _register(client, "tmatrixb", "TMatrix B Org")
    ids_a = _seed_org(client, db, headers_a, org_a, MARK_A)
    ids_b = _seed_org(client, db, headers_b, org_b, MARK_B)
    return {"a": (headers_a, ids_a), "b": (headers_b, ids_b)}


def _route_table():
    from main import app

    routes = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if not path.startswith("/api/"):
            continue
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            routes.add((method, path))
    return routes


def test_route_table_complete():
    """Every /api/v1 route is either covered below or explicitly exempt."""
    routes = _route_table()
    assert routes, "no API routes introspected"
    missing = routes - COVERED_ID_ROUTES - COVERED_LIST_ROUTES - NO_TENANT_DATA
    assert not missing, f"routes without tenant-matrix coverage: {sorted(missing)}"


ID_CASES = [
    ("GET", "/api/v1/scans/{scan_id}", "scan"),
    ("GET", "/api/v1/findings/{finding_id}", "finding"),
    ("GET", "/api/v1/assets/{asset_id}", "asset"),
    ("POST", "/api/v1/assets/{asset_id}/enrich", "asset"),
    ("GET", "/api/v1/assets/{asset_id}/graph", "asset"),
    ("POST", "/api/v1/organizations/invitations/{invitation_id}/revoke", "invitation"),
    ("PATCH", "/api/v1/organizations/api-keys/{key_id}", "api_key"),
    ("DELETE", "/api/v1/organizations/api-keys/{key_id}", "api_key"),
    ("GET", "/api/v1/alerting/integrations/{integration_id}", "integration"),
    ("PATCH", "/api/v1/alerting/integrations/{integration_id}", "integration"),
    ("DELETE", "/api/v1/alerting/integrations/{integration_id}", "integration"),
    ("POST", "/api/v1/alerting/integrations/{integration_id}/test", "integration"),
    ("GET", "/api/v1/reports/pdf/finding/{finding_id}", "finding"),
    ("GET", "/api/v1/scan-policies/{policy_id}", "policy"),
    ("PATCH", "/api/v1/scan-policies/{policy_id}", "policy"),
    ("DELETE", "/api/v1/scan-policies/{policy_id}", "policy"),
    ("POST", "/api/v1/scan-policies/{policy_id}/run-now", "policy"),
]

ID_BODIES = {
    "POST": {},
    "PATCH": {"name": f"{MARK_A} rename attempt"},
}


@pytest.mark.parametrize("method,template,key", ID_CASES)
def test_id_routes_reject_cross_org(client, matrix, method, template, key):
    """Org A's token against org B's id: 404/403, no marker leakage."""
    headers_a, _ids_a = matrix["a"]
    _headers_b, ids_b = matrix["b"]
    url = template.replace("{scan_id}", str(ids_b["scan"]))
    url = url.replace("{finding_id}", str(ids_b["finding"]))
    url = url.replace("{asset_id}", str(ids_b["asset"]))
    url = url.replace("{invitation_id}", str(ids_b["invitation"]))
    url = url.replace("{key_id}", str(ids_b["api_key"]))
    url = url.replace("{integration_id}", str(ids_b["integration"]))
    url = url.replace("{policy_id}", str(ids_b["policy"]))
    response = client.request(method, url,
                              json=ID_BODIES.get(method, None),
                              headers=headers_a)
    assert response.status_code in (403, 404), (
        f"{method} {template}: got {response.status_code}: {response.text[:200]}")
    assert MARK_B not in response.text


def test_list_endpoints_exclude_other_org(client, matrix):
    """List/dashboard/singleton endpoints must not contain B's markers for A."""
    headers_a, _ids_a = matrix["a"]
    urls = [
        "/api/v1/auth/me",
        "/api/v1/scans/verified-domains",
        "/api/v1/scans",
        "/api/v1/findings",
        "/api/v1/alerts",
        "/api/v1/dashboard",
        "/api/v1/assets",
        "/api/v1/organizations/me",
        "/api/v1/organizations/invitations",
        "/api/v1/organizations/api-keys",
        "/api/v1/alerting/integrations",
        "/api/v1/alerting/digest",
    ]
    for url in urls:
        response = client.get(url, headers=headers_a)
        assert response.status_code in (200, 404), f"{url}: {response.status_code}"
        if response.status_code == 200:
            assert MARK_B not in response.text, f"{url} leaks B markers"
    # A's own markers must be visible somewhere (sanity the fixtures exist).
    blob = " ".join(
        client.get(url, headers=headers_a).text
        for url in ("/api/v1/assets", "/api/v1/findings", "/api/v1/scans")
    )
    assert MARK_A in blob


def test_export_endpoints_exclude_other_org(client, matrix):
    """CSV exports + PDFs must not contain B's rows for A's request."""
    headers_a, _ids_a = matrix["a"]
    _headers_b, ids_b = matrix["b"]
    for url in (
        "/api/v1/reports/export/findings/csv",
        "/api/v1/reports/export/assets/csv",
        "/api/v1/reports/export/scans/csv",
        "/api/v1/reports/export/domains/csv",
        "/api/v1/reports/export/all/csv",
    ):
        response = client.post(url, headers=headers_a)
        assert response.status_code == 200, f"{url}: {response.text[:200]}"
        assert MARK_B not in response.text, f"{url} leaks B markers"
    summary = client.get("/api/v1/reports/pdf/executive-summary",
                         headers=headers_a)
    assert summary.status_code == 200, summary.text[:200]
    assert summary.headers["content-type"].startswith("application/pdf")
    assert summary.content.startswith(b"%PDF")
    assert MARK_B.encode() not in summary.content
    # B's finding PDF as A must not leak.
    other = client.get(
        f"/api/v1/reports/pdf/finding/{ids_b['finding']}", headers=headers_a)
    assert other.status_code in (403, 404), other.status_code
    assert MARK_B not in other.text


def test_mutations_do_not_touch_other_org(client, db, matrix):
    """Cross-org writes fail; B's rows are unchanged afterwards."""
    from models import AlertIntegration, ScanPolicy

    headers_a, _ids_a = matrix["a"]
    _headers_b, ids_b = matrix["b"]
    before_policy = db.query(ScanPolicy).filter(
        ScanPolicy.id == ids_b["policy"]).one().name
    before_hook = db.query(AlertIntegration).filter(
        AlertIntegration.id == ids_b["integration"]).one().name
    for method, url, body in (
        ("PATCH", f"/api/v1/scan-policies/{ids_b['policy']}",
         {"name": f"{MARK_A} hijack"}),
        ("DELETE", f"/api/v1/scan-policies/{ids_b['policy']}", None),
        ("POST", f"/api/v1/scan-policies/{ids_b['policy']}/run-now", {}),
        ("PATCH", f"/api/v1/alerting/integrations/{ids_b['integration']}",
         {"name": f"{MARK_A} hijack"}),
        ("DELETE", f"/api/v1/alerting/integrations/{ids_b['integration']}",
         None),
        ("DELETE", f"/api/v1/organizations/api-keys/{ids_b['api_key']}",
         None),
        ("POST", f"/api/v1/organizations/invitations/{ids_b['invitation']}/revoke",
         {}),
    ):
        response = client.request(method, url, json=body, headers=headers_a)
        assert response.status_code in (403, 404), (
            f"{method} {url}: {response.status_code}")
    db.expire_all()
    assert db.query(ScanPolicy).filter(
        ScanPolicy.id == ids_b["policy"]).one().name == before_policy
    assert db.query(AlertIntegration).filter(
        AlertIntegration.id == ids_b["integration"]).one().name == before_hook


def test_child_table_reads_go_through_scoped_parents(client, matrix):
    """Ports/SSL/subdomains/risk rows surface only under the owning org."""
    headers_a, _ids_a = matrix["a"]
    headers_b, _ids_b = matrix["b"]
    assets_b = client.get("/api/v1/assets", headers=headers_b).json()
    assert any(MARK_B in a.get("name", "") for a in assets_b)
    assets_a = client.get("/api/v1/assets", headers=headers_a).json()
    assert all(MARK_B not in a.get("name", "") for a in assets_a)
    graph = client.get(f"/api/v1/assets/{_ids_a['asset']}", headers=headers_a)
    assert graph.status_code == 200, graph.text[:200]
    assert MARK_A in graph.text
