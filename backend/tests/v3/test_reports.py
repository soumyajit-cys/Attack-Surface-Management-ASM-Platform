"""G7 report characterization (tests only).

CSV (all five): header rows, org filtering, asset_id/since/severity filters,
no cross-tenant rows. PDF success bytes are covered by the strict-xfail
BUG-PDF-001 case in test_tenant_matrix.py (fpdf2 bytearray bug, unfixed by
design here); this file adds the PDF failure-path probe (BUG-PDF-002).
Hermetic: no network.
"""

from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def reports(client, db, org_factory):
    from models import Alert, Asset, Domain, Finding, ScanHistory

    org_a, _ = org_factory("Report Org A", "reporta", "reporta@example.com")
    org_b, _ = org_factory("Report Org B", "reportb", "reportb@example.com")

    def login(username):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "password123"},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    ids = {}
    for org, tag in ((org_a, "rptA"), (org_b, "rptB")):
        asset = Asset(organization_id=org.id, name=f"{tag}-asset.example.com")
        db.add(asset)
        db.flush()
        domain = Domain(organization_id=org.id, asset_id=asset.id,
                        domain=f"{tag}-domain.example.com")
        db.add(domain)
        db.flush()
        old = Finding(organization_id=org.id, asset_id=asset.id,
                      title=f"{tag} old info", severity="info")
        db.add(old)
        db.flush()
        old.created_at = datetime.now(timezone.utc) - timedelta(days=30)
        new = Finding(organization_id=org.id, asset_id=asset.id,
                      title=f"{tag} new critical", severity="critical")
        db.add(new)
        db.flush()
        scan = ScanHistory(organization_id=org.id, asset_id=asset.id,
                           target=f"{tag}-domain.example.com",
                           status="completed", scope="full")
        db.add(scan)
        db.flush()
        alert = Alert(organization_id=org.id, asset_id=asset.id,
                      title=f"{tag} alert", severity="high", message="m")
        db.add(alert)
        db.commit()
        ids[tag] = {"asset": asset.id, "old_finding": old.id,
                    "new_finding": new.id, "scan": scan.id}
    return {"a": login("reporta"), "b": login("reportb"), "ids": ids}


CSV_URLS = [
    "/api/v1/reports/export/findings/csv",
    "/api/v1/reports/export/assets/csv",
    "/api/v1/reports/export/scans/csv",
    "/api/v1/reports/export/domains/csv",
]


@pytest.mark.parametrize("url", CSV_URLS)
def test_csv_has_headers_and_org_rows_only(client, reports, url):
    response = client.post(url, json={}, headers=reports["a"])
    assert response.status_code == 200, response.text[:200]
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.strip().splitlines()
    assert len(lines) >= 2  # header + at least one data row
    assert "rptB" not in response.text
    assert "rptA" in response.text


def test_export_all_zip_contains_org_csvs_only(client, reports):
    """The bundle endpoint zips per-type CSVs; B's rows appear nowhere."""
    import io
    import zipfile

    response = client.post("/api/v1/reports/export/all/csv", json={},
                           headers=reports["a"])
    assert response.status_code == 200, response.text[:200]
    assert response.headers["content-type"].startswith("application/zip")
    assert response.content.startswith(b"PK")
    with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
        assert len(bundle.namelist()) >= 2
        blob = "\n".join(
            bundle.read(name).decode() for name in bundle.namelist())
    assert "rptB" not in blob
    assert "rptA" in blob


def test_csv_filters(client, reports):
    headers, ids = reports["a"], reports["ids"]["rptA"]
    asset_id = ids["asset"]
    # severity filter keeps only critical.
    critical = client.post(
        "/api/v1/reports/export/findings/csv",
        json={"severity": "critical"}, headers=headers).text
    assert "rptA new critical" in critical
    assert "rptA old info" not in critical
    # since filter drops the 30-day-old row.
    recent = client.post(
        "/api/v1/reports/export/findings/csv",
        json={"since": (datetime.now(timezone.utc)
                        - timedelta(days=7)).isoformat()},
        headers=headers).text
    assert "rptA new critical" in recent
    assert "rptA old info" not in recent
    # asset_id filter scopes rows; another org's asset id yields nothing.
    scoped = client.post(
        "/api/v1/reports/export/findings/csv",
        json={"asset_id": asset_id}, headers=headers).text
    assert "rptA" in scoped
    other_asset = reports["ids"]["rptB"]["asset"]
    empty = client.post(
        "/api/v1/reports/export/findings/csv",
        json={"asset_id": other_asset}, headers=headers).text
    assert "rptB" not in empty
    assert "rptA" not in empty


def test_pdf_failure_hides_internals(client, reports, monkeypatch):
    """Forced generator failure: static message, stable code, no echo."""
    import app.api.v1.reports as reports_api

    def boom(*a, **k):
        raise ValueError("Simulated failure at /tmp/secret-path/x.pdf")

    monkeypatch.setattr(reports_api, "generate_executive_summary", boom)
    response = client.get("/api/v1/reports/pdf/executive-summary",
                          headers=reports["a"])
    assert response.status_code == 500
    body = response.json()["error"]
    assert body["code"] == "report_generation_failed"
    assert "/tmp/secret-path" not in response.text
    assert "Simulated failure" not in response.text
