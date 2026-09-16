"""Item 2: CVE enrichment (OSV.dev) contract tests.

Covers banner parsing, the CVSS v3.1 calculator, CVSS→severity mapping,
CVSS feed into risk scoring, SSRF fail-closed behavior, the Celery
enrichment task (creation, idempotency, retry, tenant isolation), and the
``POST /assets/{id}/enrich`` + findings API surface.
"""

import pytest
from celery.exceptions import Retry

from models import Asset, Finding
from services.enrichment import cve_service
from services.enrichment.cve_service import (
    assert_feed_host_safe,
    cvss_to_severity,
    cvss_v31_base_score,
    enrich_service_banner,
    extract_software,
    parse_osv_response,
    query_osv,
)
from services.scoring.risk_engine import calculate_risk


def _register(client, org, username):
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "organization": org,
        },
    )


def _login(client, username):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _seed_asset_with_banner(db, org_id, asset_name, banner, service="http", port=80):
    from models.domain import Domain
    from models.subdomain import Subdomain
    from models.port import Port

    asset = Asset(organization_id=org_id, name=asset_name)
    db.add(asset)
    db.flush()
    domain = Domain(organization_id=org_id, asset_id=asset.id, domain=asset_name)
    db.add(domain)
    db.flush()
    sub = Subdomain(domain_id=domain.id, subdomain=f"www.{asset_name}", source="primary")
    db.add(sub)
    db.flush()
    db.add(Port(
        subdomain_id=sub.id, port=port, protocol="tcp",
        service=service, status="open", banner=banner,
    ))
    db.commit()
    return asset


# ── Banner parsing ────────────────────────────────────────────────────────

@pytest.mark.parametrize("banner,product,version", [
    ("Server: nginx/1.18.0", "nginx", "1.18.0"),
    ("nginx/1.25.3 (Ubuntu)", "nginx", "1.25.3"),
    ("Apache/2.4.49 (Unix)", "apache", "2.4.49"),
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "openssh", "8.9p1"),
    ("220 (vsFTPd 3.0.3)", "vsftpd", "3.0.3"),
    ("220 mail.example.com ESMTP Exim 4.94", "exim", "4.94"),
    ("5.7.33-log MySQL Community Server", "mysql", "5.7.33"),
    ("INFO\r\nredis_version:7.0.11\r\n", "redis", "7.0.11"),
])
def test_extract_software_known_banners(banner, product, version):
    found = extract_software(banner)
    assert found is not None
    assert found["product"] == product
    assert found["version"] == version
    assert found["packages"]


@pytest.mark.parametrize("banner", [
    None,
    "",
    "   ",
    "220 mail.example.com ESMTP Postfix",  # no version → not queryable
    "SSH-2.0-OpenSSH",  # no version
    "some random banner without versions",
    "Microsoft-IIS/10.0",  # known but no OSV ecosystem mapping
])
def test_extract_software_returns_none_when_not_queryable(banner):
    assert extract_software(banner) is None


# ── CVSS v3.1 calculator (vectors with NVD-published scores) ─────────────

@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # Heartbleed
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),  # EternalBlue
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),  # no impact
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),  # scope-changed
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # v3.0 accepted
])
def test_cvss_v31_known_vectors(vector, expected):
    assert cvss_v31_base_score(vector) == expected


@pytest.mark.parametrize("vector", [
    "",
    "not-a-vector",
    "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C",  # v2 unsupported
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad metric value
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",  # missing scope
])
def test_cvss_v31_malformed_returns_none(vector):
    assert cvss_v31_base_score(vector) is None


@pytest.mark.parametrize("score,severity", [
    (10.0, "critical"), (9.0, "critical"),
    (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"),
    (3.9, "low"), (0.1, "low"),
    (0.0, "info"),
])
def test_cvss_to_severity_boundaries(score, severity):
    assert cvss_to_severity(score) == severity


# ── Risk scoring feed ─────────────────────────────────────────────────────

def test_calculate_risk_without_cvss_unchanged():
    assert calculate_risk("high", "internet", "prod", 0, False, 1.0) == \
        calculate_risk("high", "internet", "prod", 0, False, 1.0, None)


def test_calculate_risk_cvss_raises_base():
    plain = calculate_risk("low", "internet", "prod", 0, False, 1.0)
    boosted = calculate_risk("low", "internet", "prod", 0, False, 1.0, 9.8)
    assert boosted > plain
    assert boosted <= 10.0


def test_calculate_risk_low_cvss_does_not_lower():
    plain = calculate_risk("high", "internet", "prod", 0, False, 1.0)
    assert calculate_risk("high", "internet", "prod", 0, False, 1.0, 2.0) == plain


def test_calculate_risk_invalid_cvss_ignored():
    plain = calculate_risk("high", "internet", "prod", 0, False, 1.0)
    assert calculate_risk("high", "internet", "prod", 0, False, 1.0, "nonsense") == plain


# ── OSV response parsing ──────────────────────────────────────────────────

def test_parse_osv_response_extracts_cves_and_max_cvss():
    payload = {
        "vulns": [
            {
                "id": "CVE-2022-1234",
                "summary": "Buffer overflow in nginx",
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                ],
            },
            {
                "id": "GHSA-abcd-efgh-ijkl",
                "aliases": ["CVE-2021-9999"],
                "summary": "DoS",
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                ],
            },
            {"id": "GHSA-no-cve", "summary": "no CVE alias → skipped", "severity": []},
        ]
    }
    results = parse_osv_response(payload)
    by_cve = {r["cve_id"]: r for r in results}
    assert set(by_cve) == {"CVE-2022-1234", "CVE-2021-9999"}
    assert by_cve["CVE-2022-1234"]["cvss"] == 9.8
    assert by_cve["CVE-2022-1234"]["severity"] == "critical"
    assert by_cve["CVE-2021-9999"]["severity"] == "high"


def test_parse_osv_response_missing_cvss_defaults_medium():
    payload = {"vulns": [{"id": "CVE-2020-1111", "summary": "x", "severity": []}]}
    results = parse_osv_response(payload)
    assert len(results) == 1
    assert results[0]["cvss"] is None
    assert results[0]["severity"] == "medium"


# ── SSRF fail-closed ──────────────────────────────────────────────────────

def test_feed_url_rejects_plain_http(monkeypatch):
    monkeypatch.setattr(cve_service._settings(), "osv_api_url", "http://api.osv.dev/v1/query")
    with pytest.raises(ValueError, match="https"):
        assert_feed_host_safe(cve_service.feed_url())


def test_feed_host_blocked_ip_fails_closed(monkeypatch):
    monkeypatch.setattr("socket.gethostbyname", lambda host: "169.254.169.254")
    with pytest.raises(ValueError, match="blocked IP"):
        assert_feed_host_safe("https://api.osv.dev/v1/query")


def test_query_osv_blocks_before_request(monkeypatch):
    monkeypatch.setattr("socket.gethostbyname", lambda host: "10.0.0.5")

    def _boom(*args, **kwargs):
        raise AssertionError("no HTTP request must be issued to a blocked IP")

    monkeypatch.setattr("requests.post", _boom)
    with pytest.raises(ValueError, match="blocked IP"):
        query_osv("nginx", "Debian", "1.18.0")


def test_query_osv_success(monkeypatch):
    monkeypatch.setattr("socket.gethostbyname", lambda host: "8.8.8.8")

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulns": [{"id": "CVE-2022-1234", "summary": "x", "severity": []}]}

    captured = {}

    def _post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr("requests.post", _post)
    results = query_osv("nginx", "Debian", "1.18.0")
    assert captured["url"].startswith("https://")
    assert captured["json"]["version"] == "1.18.0"
    assert results[0]["cve_id"] == "CVE-2022-1234"


# ── Celery task ───────────────────────────────────────────────────────────

def _vuln(cve="CVE-2022-1234", cvss=9.8, severity="critical"):
    return {
        "cve_id": cve, "cvss": cvss, "severity": severity,
        "summary": "Test vuln", "product": "nginx", "version": "1.18.0",
    }


def test_enrich_task_creates_cve_findings(db, monkeypatch, org_factory):
    from tasks.cve_tasks import enrich_asset_findings

    org, _ = org_factory("CVE Org", "cveuser", "cve@example.com")
    asset = _seed_asset_with_banner(db, org.id, "cve.example.com", "Server: nginx/1.18.0")

    monkeypatch.setattr(
        "tasks.cve_tasks.enrich_service_banner", lambda service, banner: [_vuln()]
    )
    result = enrich_asset_findings.apply(args=[asset.id]).get()
    assert result["status"] == "completed"
    assert result["created"] == 1

    db.expire_all()
    finding = db.query(Finding).filter(
        Finding.organization_id == org.id, Finding.asset_id == asset.id
    ).first()
    assert finding is not None
    assert finding.category == "vulnerability"
    assert finding.severity == "critical"
    assert finding.cve_ids == ["CVE-2022-1234"]
    assert finding.cvss_score == 9.8
    assert "CVE-2022-1234" in finding.title


def test_enrich_task_idempotent(db, monkeypatch, org_factory):
    from tasks.cve_tasks import enrich_asset_findings

    org, _ = org_factory("CVE Idem Org", "cveidem", "cveidem@example.com")
    asset = _seed_asset_with_banner(db, org.id, "idem.example.com", "Server: nginx/1.18.0")
    monkeypatch.setattr(
        "tasks.cve_tasks.enrich_service_banner", lambda service, banner: [_vuln()]
    )

    first = enrich_asset_findings.apply(args=[asset.id]).get()
    second = enrich_asset_findings.apply(args=[asset.id]).get()
    assert first["created"] == 1
    assert second["created"] == 0

    db.expire_all()
    count = db.query(Finding).filter(
        Finding.organization_id == org.id, Finding.asset_id == asset.id
    ).count()
    assert count == 1


def test_enrich_task_tenant_isolation(db, monkeypatch, org_factory):
    from tasks.cve_tasks import enrich_asset_findings

    org_a, _ = org_factory("CVE Org A", "cvea", "cvea@example.com")
    org_b, _ = org_factory("CVE Org B", "cveb", "cveb@example.com")
    asset_a = _seed_asset_with_banner(db, org_a.id, "a-cve.example.com", "Server: nginx/1.18.0")
    asset_b = _seed_asset_with_banner(db, org_b.id, "b-cve.example.com", "Server: nginx/1.18.0")
    monkeypatch.setattr(
        "tasks.cve_tasks.enrich_service_banner", lambda service, banner: [_vuln()]
    )

    enrich_asset_findings.apply(args=[asset_a.id]).get()

    db.expire_all()
    assert db.query(Finding).filter(Finding.organization_id == org_a.id).count() == 1
    assert db.query(Finding).filter(Finding.organization_id == org_b.id).count() == 0
    other = db.query(Finding).filter(Finding.asset_id == asset_b.id).count()
    assert other == 0


def test_enrich_task_retries_transient_errors(db, monkeypatch, org_factory):
    from tasks.cve_tasks import enrich_asset_findings
    import requests

    org, _ = org_factory("CVE Retry Org", "cveretry", "cveretry@example.com")
    asset = _seed_asset_with_banner(db, org.id, "retry.example.com", "Server: nginx/1.18.0")

    def _boom(service, banner):
        raise requests.ConnectionError("osv down")

    monkeypatch.setattr("tasks.cve_tasks.enrich_service_banner", _boom)
    with pytest.raises(Retry):
        enrich_asset_findings.apply(args=[asset.id]).get()


def test_enrich_task_no_banners_noop(db, org_factory):
    from tasks.cve_tasks import enrich_asset_findings

    org, _ = org_factory("CVE Noop Org", "cvenoop", "cvenoop@example.com")
    asset = Asset(organization_id=org.id, name="noop.example.com")
    db.add(asset)
    db.commit()

    result = enrich_asset_findings.apply(args=[asset.id]).get()
    assert result["status"] == "completed"
    assert result["created"] == 0


def test_enrich_task_missing_asset(db):
    from tasks.cve_tasks import enrich_asset_findings

    result = enrich_asset_findings.apply(args=[999999]).get()
    assert result["status"] == "not_found"


# ── API surface ───────────────────────────────────────────────────────────

def test_enrich_endpoint_queues_and_scopes_to_org(client, db, monkeypatch):
    from models.user import User

    _register(client, "Enrich Org", "enrichu")
    headers = _login(client, "enrichu")
    user = db.query(User).filter(User.username == "enrichu").first()
    asset = _seed_asset_with_banner(db, user.organization_id, "enr.example.com", "nginx/1.18.0")

    calls = []
    monkeypatch.setattr(
        "tasks.cve_tasks.enrich_asset_findings.delay",
        lambda asset_id: calls.append(asset_id),
    )
    response = client.post(f"/api/v1/assets/{asset.id}/enrich", headers=headers)
    assert response.status_code == 202, response.text
    assert response.json() == {"asset_id": asset.id, "status": "queued"}
    assert calls == [asset.id]

    _register(client, "Enrich Other Org", "enrichother")
    other = _login(client, "enrichother")
    response = client.post(f"/api/v1/assets/{asset.id}/enrich", headers=other)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "asset_not_found"


def test_enrich_endpoint_requires_scan_create(client, db):
    from models.user import User

    _register(client, "Enrich Viewer Org", "enrichviewer")
    headers = _login(client, "enrichviewer")
    user = db.query(User).filter(User.username == "enrichviewer").first()
    user.role = "viewer"
    db.commit()
    asset = _seed_asset_with_banner(db, user.organization_id, "view.example.com", "nginx/1.18.0")

    response = client.post(f"/api/v1/assets/{asset.id}/enrich", headers=headers)
    assert response.status_code == 403


def test_findings_api_exposes_cve_fields(client, db):
    from models.user import User

    _register(client, "CVE API Org", "cveapi")
    headers = _login(client, "cveapi")
    user = db.query(User).filter(User.username == "cveapi").first()
    asset = Asset(organization_id=user.organization_id, name="cveapi.example.com")
    db.add(asset)
    db.flush()
    db.add(Finding(
        organization_id=user.organization_id,
        asset_id=asset.id,
        title="CVE-2022-1234 in nginx",
        severity="critical",
        category="vulnerability",
        cve_ids=["CVE-2022-1234"],
        cvss_score=9.8,
    ))
    db.commit()

    body = client.get("/api/v1/findings", headers=headers).json()
    assert body["items"][0]["cve_ids"] == ["CVE-2022-1234"]
    assert body["items"][0]["cvss_score"] == 9.8

    finding_id = body["items"][0]["id"]
    detail = client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    assert detail["cve_ids"] == ["CVE-2022-1234"]
    assert detail["cvss_score"] == 9.8
