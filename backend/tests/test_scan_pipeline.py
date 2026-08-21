from datetime import datetime, timedelta, timezone

import pytest


def _register(client, username, role=None):
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "supersecret1",
        "organization": f"Org-{username}",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201, response.text
    access = response.json()["access_token"]

    from models.user import User
    from utils.database import SessionLocal

    if role:
        db = SessionLocal()
        user = db.query(User).filter(User.username == username).first()
        user.role = role
        db.commit()
        db.close()

    return {"Authorization": f"Bearer {access}"}


@pytest.fixture()
def mock_scan_pipeline(monkeypatch):
    import tasks.discovery_tasks as tasks

    async def fake_resolve(domain):
        return {"domain": domain, "ip": "93.184.216.34"}

    async def fake_dns(domain):
        return [
            {"type": "A", "value": "93.184.216.34"},
            {"type": "MX", "value": "10 mx.example.com."},
        ]

    async def fake_subdomains(domain):
        return [
            "www.example.com",
            "mail.example.com",
            "api.example.com",
        ]

    async def fake_whois(domain):
        return {"registrar": "Test Registrar", "asn": "AS15133"}

    async def fake_ports(host):
        return [
            {"port": 22, "status": "closed", "protocol": "tcp"},
            {"port": 80, "status": "open", "protocol": "tcp",
             "service": "http"},
            {"port": 443, "status": "open", "protocol": "tcp",
             "service": "https"},
        ]

    async def fake_ssl(host):
        return {
            "issuer": "CN=Test CA",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "expires_at": datetime.now(timezone.utc) + timedelta(days=200),
            "self_signed": False,
        }

    async def fake_headers(url):
        return [{
            "title": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "category": "security_headers",
            "description": "Content Security Policy not set",
            "recommendation": "Implement a restrictive Content-Security-Policy header",
        }]

    monkeypatch.setattr(tasks, "resolve_domain", fake_resolve)
    monkeypatch.setattr(tasks, "enumerate_dns", fake_dns)
    monkeypatch.setattr(tasks, "discover_subdomains", fake_subdomains)
    monkeypatch.setattr(tasks, "get_whois", fake_whois)
    monkeypatch.setattr(tasks, "scan_ports", fake_ports)
    monkeypatch.setattr(tasks, "analyze_ssl", fake_ssl)
    monkeypatch.setattr(tasks, "analyze_headers", fake_headers)


def test_full_scan_pipeline(client, db, mock_scan_pipeline):
    headers = _register(client, "scanner")

    response = client.post(
        "/scan/",
        json={"domain": "example.com"},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]

    status = client.get(
        f"/scan/{scan_id}",
        headers=headers,
    )
    assert status.status_code == 200
    body = status.json()
    assert body["status"] == "completed", body

    from models.asset import Asset
    from models.domain import Domain
    from models.dns_record import DNSRecord
    from models.finding import Finding
    from models.port import Port
    from models.risk_score import RiskScore
    from models.subdomain import Subdomain

    domain = db.query(Domain).filter(Domain.domain == "example.com").first()
    assert domain is not None
    assert domain.registrar == "Test Registrar"

    dns_count = db.query(DNSRecord).filter(
        DNSRecord.domain_id == domain.id
    ).count()
    assert dns_count == 2

    subdomains = db.query(Subdomain).filter(
        Subdomain.domain_id == domain.id
    ).all()
    assert len(subdomains) == 4  # example.com + 3 crt.sh results

    assert db.query(Port).filter(
        Port.status == "open"
    ).count() >= 2

    assert db.query(Finding).filter(
        Finding.organization_id == domain.organization_id
    ).count() >= 1

    assert db.query(RiskScore).count() >= 1

    dashboard = client.get("/dashboard/", headers=headers).json()
    assert dashboard["assets"] == 1
    assert dashboard["findings"] > 0


def test_viewer_cannot_trigger_scan(client, db, mock_scan_pipeline):
    headers = _register(client, "viewer1", role="viewer")

    response = client.post(
        "/scan/",
        json={"domain": "example.com"},
        headers=headers,
    )
    assert response.status_code == 403


def test_invalid_domain_rejected(client, db):
    headers = _register(client, "validator")

    response = client.post(
        "/scan/",
        json={"domain": "not a domain!!"},
        headers=headers,
    )
    assert response.status_code == 400