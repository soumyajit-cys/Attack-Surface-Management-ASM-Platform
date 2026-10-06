"""Task 0.5 correctness: boolean alert flags, tz-aware SSL expiry, log redaction."""

from datetime import datetime, timedelta, timezone

from models.alert import Alert
from models.asset import Asset
from models.domain import Domain
from models.ssl_result import SSLResult
from models.subdomain import Subdomain

from services.history.change_detector import persist_alerts
from utils.rate_limiter import redact_redis_url


def _login(client, username):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_alert_read_roundtrips_as_native_boolean(client, db, org_factory):
    org, _ = org_factory("Read Bool Org", "readbool", "readbool@example.com")
    asset = Asset(organization_id=org.id, name="readbool.example.com")
    db.add(asset)
    db.flush()
    persist_alerts(db, [
        {"type": "port_opened", "asset_id": asset.id, "title": "Unread",
         "severity": "medium", "details": "{}"},
    ], org.id)
    db.add(Alert(organization_id=org.id, asset_id=asset.id, title="Read",
                 severity="low", message="{}", read=True))
    db.commit()

    body = client.get("/api/v1/alerts", headers=_login(client, "readbool")).json()
    assert body["total"] == 2
    by_title = {i["title"]: i["read"] for i in body["items"]}
    assert by_title["Unread"] is False
    assert by_title["Read"] is True


def test_ssl_expires_at_column_is_timezone_aware(db, org_factory):
    assert SSLResult.__table__.c.expires_at.type.timezone is True

    org, _ = org_factory("SSL TZ Org", "ssltz", "ssltz@example.com")
    asset = Asset(organization_id=org.id, name="ssltz.example.com")
    db.add(asset)
    db.flush()
    domain = Domain(organization_id=org.id, asset_id=asset.id, domain="ssltz.example.com")
    db.add(domain)
    db.flush()
    sub = Subdomain(domain_id=domain.id, subdomain="www.ssltz.example.com")
    db.add(sub)
    db.flush()

    stamp = datetime.now(timezone.utc) + timedelta(days=90)
    db.add(SSLResult(subdomain_id=sub.id, expires_at=stamp))
    db.commit()
    db.expire_all()

    row = db.query(SSLResult).filter(SSLResult.subdomain_id == sub.id).one()
    assert row.expires_at.tzinfo is not None
    assert abs((row.expires_at - stamp).total_seconds()) < 1


def test_redact_redis_url_drops_credentials_and_query():
    assert redact_redis_url("redis://localhost:6379/0") == "redis://localhost:6379/0"
    assert redact_redis_url("redis://:s3cret@redis:6379/0") == "redis://redis:6379/0"
    assert redact_redis_url("redis://user:s3cret@h:6380/2?ssl=true") == "redis://h:6380/2"
    assert redact_redis_url("not a url at all") == "redis://unknown"
