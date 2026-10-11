"""Task 1.4: Fernet secrets at rest (TESTS FIRST).

Committed red: ``app.core.crypto`` does not exist yet. No real secrets are
used here except clearly-marked distinctive strings asserted ABSENT from
outputs. All network touching is mocked.
"""

import logging

import pytest

from app.core.crypto import (
    DecryptFailedError,
    decrypt_value,
    encrypt_value,
    is_encrypted,
    make_fernet,
)
from models import AlertIntegration, Asset, Finding


@pytest.fixture()
def sentinel_caplog(caplog):
    """Capture the app's non-propagating logger in tests."""
    app_logger = logging.getLogger("sentinelasm")
    app_logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        app_logger.removeHandler(caplog.handler)


def _key(seed: int = 1) -> str:
    """Deterministic valid Fernet key for tests (never production)."""
    import base64

    return base64.urlsafe_b64encode(bytes([seed]) * 32).decode()


KEY_A = _key(1)
KEY_B = _key(2)


def _public_dns(monkeypatch, ip="93.184.216.34"):
    """Spoof public DNS answers, but leave localhost alone (Redis!)."""
    import socket as stdlib_socket

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", (ip, 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


class TestRoundTrip:
    def test_encrypt_decrypt_round_trip(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.secrets_encryption_key", KEY_A)
        stored = encrypt_value("s3cret-token")
        assert stored != "s3cret-token"
        assert stored.startswith("enc:v1:")
        assert decrypt_value(stored) == "s3cret-token"
        assert is_encrypted(stored) is True
        assert is_encrypted("s3cret-token") is False

    def test_none_passthrough(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.secrets_encryption_key", KEY_A)
        assert encrypt_value(None) is None
        assert decrypt_value(None) is None

    def test_idempotent_double_encrypt(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.secrets_encryption_key", KEY_A)
        once = encrypt_value("s3cret-token")
        assert encrypt_value(once) == once


class TestRotation:
    def test_old_rows_decrypt_after_prepend(self, monkeypatch):
        import app.core.config as config_mod

        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        stored = encrypt_value("s3cret-token")
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", f"{KEY_B},{KEY_A}")
        assert decrypt_value(stored) == "s3cret-token"

    def test_rotate_reencrypts_under_first_key(self, monkeypatch, db, org_factory):
        import app.core.config as config_mod
        from app.core.crypto import rotate_existing_rows
        from sqlalchemy import text

        org, _ = org_factory("Rot Org", "rotuser", "rot@example.com")
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        db.execute(text(
            "INSERT INTO alert_integrations "
            "(organization_id, name, channel, min_severity, is_active, secret) "
            "VALUES (:org, 'rot', 'SLACK', 'HIGH', true, 'plain-secret')"
        ), {"org": org.id})
        from app.core.crypto import encrypt_existing_rows
        encrypt_existing_rows(db.connection())
        db.commit()
        before = db.execute(text(
            "SELECT secret FROM alert_integrations WHERE name = 'rot'")).scalar()
        assert before.startswith("enc:v1:")

        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", f"{KEY_B},{KEY_A}")
        rotate_existing_rows(db.connection())
        db.commit()
        raw = db.execute(text(
            "SELECT secret FROM alert_integrations WHERE name = 'rot'")).scalar()
        assert raw.startswith("enc:v1:")
        # B-only decrypts (A can be dropped); A-only cannot.
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_B)
        assert decrypt_value(raw) == "plain-secret"
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        with pytest.raises(DecryptFailedError):
            decrypt_value(raw)


class TestWrongKey:
    def test_wrong_key_fails_safely_without_leak(self, monkeypatch):
        import app.core.config as config_mod

        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        stored = encrypt_value("s3cret-token")
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_B)
        with pytest.raises(DecryptFailedError) as excinfo:
            decrypt_value(stored)
        assert "s3cret-token" not in str(excinfo.value)


class TestStartupValidation:
    def test_placeholder_key_rejected(self, monkeypatch):
        from app.core.config import ConfigError, Settings

        monkeypatch.setenv("SECRETS_ENCRYPTION_KEY", "change-me")
        with pytest.raises(ConfigError):
            Settings()

    def test_invalid_key_rejected(self, monkeypatch):
        from app.core.config import ConfigError, Settings

        monkeypatch.setenv("SECRETS_ENCRYPTION_KEY", "not-a-key")
        with pytest.raises(ConfigError):
            Settings()

    def test_missing_key_fails_fast_with_command(self, monkeypatch, tmp_path):
        from app.core.config import ConfigError, Settings

        # No key anywhere: not in env and no .env file to fall back to.
        monkeypatch.delenv("SECRETS_ENCRYPTION_KEY", raising=False)
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ConfigError, match="Fernet.generate_key"):
            Settings()

    def test_production_requires_key(self, monkeypatch):
        from app.core.config import ConfigError, Settings

        monkeypatch.delenv("SECRETS_ENCRYPTION_KEY", raising=False)
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("DEBUG", "False")
        with pytest.raises(ConfigError):
            Settings()


class TestMigrationFunctions:
    def _seed_plaintext(self, db, org_id):
        from sqlalchemy import text

        db.execute(text(
            "INSERT INTO alert_integrations "
            "(organization_id, name, channel, min_severity, is_active, secret, "
            "jira_api_token) "
            "VALUES (:org, 'mig', 'SLACK', 'HIGH', true, 'plain-secret', 'plain-token')"
        ), {"org": org_id})
        db.commit()

    def _raw(self, db):
        from sqlalchemy import text

        return db.execute(text(
            "SELECT secret, jira_api_token FROM alert_integrations "
            "WHERE name = 'mig'")).one()

    def test_encrypt_skips_prefixed_and_decrypt_restores(
        self, db, monkeypatch, org_factory
    ):
        import app.core.config as config_mod
        from app.core.crypto import decrypt_existing_rows, encrypt_existing_rows

        org, _ = org_factory("Mig Org", "miguser", "mig@example.com")
        self._seed_plaintext(db, org.id)
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)

        counts = encrypt_existing_rows(db.connection())
        db.commit()
        assert counts["alert_integrations.secret"] == 1
        assert counts["alert_integrations.jira_api_token"] == 1
        secret, token = self._raw(db)
        assert secret.startswith("enc:v1:") and token.startswith("enc:v1:")

        # Second run changes nothing.
        counts = encrypt_existing_rows(db.connection())
        db.commit()
        assert counts == {"alert_integrations.secret": 0,
                          "alert_integrations.jira_api_token": 0,
                          "alert_integrations.webhook_url": 0}
        assert self._raw(db) == (secret, token)

        # Downgrade restores byte-for-byte.
        counts = decrypt_existing_rows(db.connection())
        db.commit()
        assert self._raw(db) == ("plain-secret", "plain-token")

    def test_downgrade_without_key_fails_untouched(
        self, db, monkeypatch, org_factory
    ):
        import app.core.config as config_mod
        from app.core.crypto import decrypt_existing_rows, encrypt_existing_rows

        org, _ = org_factory("Mig Org2", "miguser2", "mig2@example.com")
        self._seed_plaintext(db, org.id)
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        encrypt_existing_rows(db.connection())
        db.commit()
        before = self._raw(db)

        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_B)
        with pytest.raises(DecryptFailedError):
            decrypt_existing_rows(db.connection())
        db.rollback()
        assert self._raw(db) == before


class TestApiAndLogsSecretFree:
    DISTINCTIVE = "zz-distinctive-secret-9f8e7d6c5b4a"

    def _headers(self, client, username="secowner", org="Sec Org"):
        client.post(
            "/api/v1/auth/register",
            json={"username": username, "email": f"{username}@example.com",
                  "password": "password123", "organization": org},
        )
        login = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "password123"},
        )
        return {"Authorization": f"Bearer {login.json()['access_token']}"}

    def test_api_never_returns_secrets(self, client, db, sentinel_caplog, monkeypatch):
        import logging
        import socket as stdlib_socket

        _public_dns(monkeypatch)
        headers = self._headers(client)
        created = client.post(
            "/api/v1/alerting/integrations",
            json={"name": "sec", "channel": "slack",
                  "webhook_url": "https://hooks.example.com/x",
                  "secret": self.DISTINCTIVE},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        with sentinel_caplog.at_level(logging.INFO):
            listed = client.get("/api/v1/alerting/integrations", headers=headers)
            detail = client.get(
                f"/api/v1/alerting/integrations/{created.json()['id']}",
                headers=headers,
            )
        assert listed.status_code == 200 and detail.status_code == 200
        assert self.DISTINCTIVE not in listed.text
        assert self.DISTINCTIVE not in detail.text
        assert self.DISTINCTIVE not in sentinel_caplog.text

    def test_send_failure_avoids_logs_and_records_last_error(
        self, client, db, monkeypatch, sentinel_caplog
    ):
        import logging
        import socket as stdlib_socket

        from models import AlertIntegration
        from services.alerts import alerting_service as alerts

        _public_dns(monkeypatch)
        headers = self._headers(client, username="secowner2", org="Sec Org 2")
        created = client.post(
            "/api/v1/alerting/integrations",
            json={"name": "sec2", "channel": "slack",
                  "webhook_url": "https://hooks.example.com/x",
                  "secret": self.DISTINCTIVE},
            headers=headers,
        )
        integration_id = created.json()["id"]

        async def _boom(*a, **k):
            raise RuntimeError("delivery exploded")

        monkeypatch.setattr(alerts, "fetch_url_validated", _boom)
        with sentinel_caplog.at_level(logging.INFO):
            result = client.post(
                f"/api/v1/alerting/integrations/{integration_id}/test",
                headers=headers,
            )
        # Failed delivery surfaces loudly, never silently, and the secret
        # appears neither in the response nor in the logs. The manual test
        # button also stamps last_error like the dispatch loops do.
        assert result.status_code == 500
        assert result.json()["error"]["code"] == "test_alert_failed"
        assert self.DISTINCTIVE not in result.text
        assert self.DISTINCTIVE not in sentinel_caplog.text
        db.expire_all()
        row = db.get(AlertIntegration, integration_id)
        assert row.last_error is not None
        assert self.DISTINCTIVE not in (row.last_error or "")


class TestSendTimeDecryptFailure:
    DISTINCTIVE = "zz-distinctive-jira-1a2b3c4d5e6f"

    def test_wrong_key_records_last_error_without_raising(
        self, db, monkeypatch, org_factory, sentinel_caplog
    ):
        import logging
        import socket as stdlib_socket

        import app.core.config as config_mod
        from models import AlertIntegration, AlertChannel, AlertSeverity
        from services.alerts import alerting_service as alerts

        _public_dns(monkeypatch)
        org, _ = org_factory("Jira Key Org", "jirakey", "jirakey@example.com")
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        integration = AlertIntegration(
            organization_id=org.id, name="Jira K", channel=AlertChannel.JIRA,
            min_severity=AlertSeverity.LOW, is_active=True,
            jira_base_url="https://jira.example.com",
            jira_project_key="SEC", jira_email="e@example.com",
            jira_api_token=self.DISTINCTIVE,
        )
        db.add(integration)
        db.commit()

        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_B)
        db.expire_all()
        with sentinel_caplog.at_level(logging.INFO):
            result = _aio(alerts.send_jira_alert(
                integration,
                Finding(organization_id=org.id, asset_id=1, title="T", severity="high"),
                Asset(organization_id=org.id, name="k.example.com"),
            ))
        assert result is False
        assert self.DISTINCTIVE not in sentinel_caplog.text
        # Recording happens in the dispatch loops (covered by the dispatch
        # test); the direct send only fails closed without raising or leaking.

def _aio(coro):
    import asyncio
    return asyncio.run(coro)


def test_make_fernet_rejects_garbage():
    with pytest.raises(ValueError):
        make_fernet(["not-a-key"])


class TestWebhookUrlSecrecy:
    TOKEN = "tok-UNIQUE-7f3a9c2e1b"

    def _url(self):
        return f"https://hooks.example.com/services/T/B/{self.TOKEN}"

    def test_api_never_returns_full_url(self, client, db, monkeypatch):
        _public_dns(monkeypatch)
        reg = client.post(
            "/api/v1/auth/register",
            json={"username": "wuser", "email": "wuser@example.com",
                  "password": "password123", "organization": "W Org"},
        )
        assert reg.status_code == 201, reg.text
        headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}
        created = client.post(
            "/api/v1/alerting/integrations",
            json={"name": "w", "channel": "slack", "webhook_url": self._url()},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert self.TOKEN not in body.get("webhook_url_masked", "")
        assert body["has_webhook_url"] is True

        listed = client.get("/api/v1/alerting/integrations", headers=headers).json()
        assert self.TOKEN not in str(listed)
        one = client.get(
            f"/api/v1/alerting/integrations/{body['id']}", headers=headers).json()
        assert self.TOKEN not in str(one)
        assert one["webhook_url_masked"].endswith(self.TOKEN[-4:])

    def _dispatch_with_fetch(self, db, org_factory, monkeypatch, fetch_behavior, tag=""):
        import socket as stdlib_socket

        from models import AlertIntegration, AlertChannel, AlertSeverity, Asset, Finding
        from services.alerts import alerting_service as alerts

        real_getaddrinfo = stdlib_socket.getaddrinfo

        def fake_getaddrinfo(host, *a, **k):
            if host in ("localhost", "127.0.0.1", "::1"):
                return real_getaddrinfo(host, *a, **k)
            return [(stdlib_socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))]

        monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
        org, _ = org_factory(f"W Org {tag}", f"wuser{tag}", f"w{tag}@example.com")
        asset = Asset(organization_id=org.id, name=f"w{tag}.example.com")
        db.add(asset)
        db.flush()
        db.add(AlertIntegration(
            organization_id=org.id, name="w", channel=AlertChannel.SLACK,
            webhook_url=self._url(), min_severity=AlertSeverity.LOW,
            is_active=True))
        db.commit()
        monkeypatch.setattr(alerts, "fetch_url_validated", fetch_behavior)
        finding = Finding(organization_id=org.id, asset_id=asset.id,
                          title="T", severity="high")
        return org, asset, finding

    def _assert_clean(self, db, org, caplog_text):
        from models import AlertIntegration

        assert self.TOKEN not in caplog_text
        db.expire_all()
        for row in db.query(AlertIntegration).filter(
                AlertIntegration.organization_id == org.id).all():
            assert self.TOKEN not in (row.last_error or "")

    def test_conn_error_leaks_nothing(self, db, monkeypatch, org_factory,
                                      sentinel_caplog):
        import logging

        import httpx

        from services.alerts import alerting_service as alerts

        org, asset, finding = self._dispatch_with_fetch(
            db, org_factory, monkeypatch, None)

        async def _boom(*a, **k):
            raise httpx.ConnectError(f"dial {self._url()} refused")

        monkeypatch.setattr(alerts, "fetch_url_validated", _boom)
        with sentinel_caplog.at_level(logging.DEBUG):
            import asyncio
            asyncio.run(alerts.process_finding_alerts(db, finding, asset))
        self._assert_clean(db, org, sentinel_caplog.text)

    def test_http_error_statuses_leak_nothing(
        self, db, monkeypatch, org_factory, sentinel_caplog
    ):
        import logging

        from services.alerts import alerting_service as alerts
        from utils.egress import FetchResult

        for status in (400, 500):
            org, asset, finding = self._dispatch_with_fetch(
                db, org_factory, monkeypatch, None, tag=str(status))

            async def fake_fetch(url, status_code=status, **kw):
                return FetchResult(status_code=status_code, headers={}, body=b"e")

            monkeypatch.setattr(alerts, "fetch_url_validated", fake_fetch)
            with sentinel_caplog.at_level(logging.DEBUG):
                import asyncio
                asyncio.run(alerts.process_finding_alerts(db, finding, asset))
            self._assert_clean(db, org, sentinel_caplog.text)


class TestUndecryptableSentinel:
    def test_read_failure_returns_sentinel(self):
        from app.core.crypto import EncryptedText, UndecryptableSecret

        sentinel = EncryptedText().process_result_value("enc:v1:garbage!!", None)
        assert isinstance(sentinel, UndecryptableSecret)
        assert not sentinel
        assert "garbage" not in repr(sentinel)
        assert "garbage" not in str(sentinel)
        assert "enc:v1" not in repr(sentinel)

    def test_binding_sentinel_raises(self, db, org_factory):
        from sqlalchemy.exc import StatementError

        from app.core.crypto import EncryptedText, UndecryptableSecret
        from models import AlertIntegration, AlertChannel, AlertSeverity

        org, _ = org_factory("Sent Org", "sentuser", "sent@example.com")
        row = AlertIntegration(
            organization_id=org.id, name="Sentinel W", channel=AlertChannel.SLACK,
            webhook_url="https://hooks.example.com/x",
            min_severity=AlertSeverity.LOW, is_active=True,
        )
        db.add(row)
        db.commit()

        row.secret = EncryptedText().process_result_value("enc:v1:garbage!!", None)
        # SQLAlchemy wraps bind-time failures; the original error stays a
        # ValueError and nothing reaches the database.
        with pytest.raises(StatementError) as excinfo:
            db.flush()
        assert isinstance(excinfo.value.orig, ValueError)
        db.rollback()
        db.expire_all()
        assert db.get(AlertIntegration, row.id).secret is None

    def test_list_reports_unreadable_status(self, client, db, monkeypatch):
        from models import AlertIntegration

        _public_dns(monkeypatch)
        # Build auth directly to avoid depending on other test classes.
        reg = client.post(
            "/api/v1/auth/register",
            json={"username": "statuser", "email": "statuser@example.com",
                  "password": "password123", "organization": "Stat Org"},
        )
        assert reg.status_code == 201, reg.text
        token = reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        good_id = client.post(
            "/api/v1/alerting/integrations",
            json={"name": "stat-good", "channel": "slack",
                  "webhook_url": "https://hooks.example.com/x"},
            headers=headers,
        ).json()["id"]
        bad_id = client.post(
            "/api/v1/alerting/integrations",
            json={"name": "stat-bad", "channel": "slack",
                  "webhook_url": "https://hooks.example.com/x"},
            headers=headers,
        ).json()["id"]

        from sqlalchemy import text
        db.execute(text(
            "UPDATE alert_integrations SET secret = 'enc:v1:garbage!!' "
            "WHERE id = :id"), {"id": bad_id})
        db.commit()

        body = client.get("/api/v1/alerting/integrations", headers=headers)
        assert body.status_code == 200, body.text
        rows = {i["name"]: i for i in body.json()}
        assert rows["stat-good"]["secret_status"] == "ok"
        assert rows["stat-bad"]["secret_status"] == "unreadable"
        assert "secret" not in rows["stat-bad"] and "jira_api_token" not in rows["stat-bad"]

        for name, expected in (("stat-good", "ok"), ("stat-bad", "unreadable")):
            row_id = good_id if name == "stat-good" else bad_id
            one = client.get(
                f"/api/v1/alerting/integrations/{row_id}", headers=headers)
            assert one.status_code == 200, one.text
            assert one.json()["secret_status"] == expected

        # The bad row still allows delete and re-entering the secret.
        reenter = client.patch(
            f"/api/v1/alerting/integrations/{bad_id}",
            json={"secret": "fresh-secret"}, headers=headers)
        assert reenter.status_code == 200, reenter.text
        assert reenter.json()["secret_status"] == "ok"
        deleted = client.delete(
            f"/api/v1/alerting/integrations/{bad_id}", headers=headers)
        assert deleted.status_code in (200, 204), deleted.text

    def test_dispatch_skips_unreadable_and_delivers_good(
        self, db, monkeypatch, org_factory
    ):
        import socket as stdlib_socket

        from models import AlertIntegration, AlertChannel, AlertSeverity, Asset, Finding
        from services.alerts import alerting_service as alerts
        from sqlalchemy import text
        from utils.egress import FetchResult

        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *a, **k: [(stdlib_socket.AF_INET, 1, 6, "", ("93.184.216.34", 443))],
        )
        org, _ = org_factory("Mix Org", "mixuser", "mix@example.com")
        asset = Asset(organization_id=org.id, name="mix.example.com")
        db.add(asset)
        db.flush()
        for name, base in (("good-jira", "https://good-jira.example"),
                           ("bad-jira", "https://bad-jira.example")):
            db.add(AlertIntegration(
                organization_id=org.id, name=name, channel=AlertChannel.JIRA,
                min_severity=AlertSeverity.LOW, is_active=True,
                jira_base_url=base, jira_project_key="SEC",
                jira_email="e@example.com", jira_api_token="real-token"))
        db.commit()
        bad_id = db.query(AlertIntegration).filter(
            AlertIntegration.name == "bad-jira").one().id
        db.execute(text(
            "UPDATE alert_integrations SET jira_api_token = 'enc:v1:garbage!!' "
            "WHERE id = :id"), {"id": bad_id})
        db.commit()

        delivered = []

        async def fake_fetch(url, **kw):
            delivered.append(url)
            return FetchResult(status_code=201, headers={}, body=b'{"id":"1"}')

        monkeypatch.setattr(alerts, "fetch_url_validated", fake_fetch)
        finding = Finding(organization_id=org.id, asset_id=asset.id,
                          title="T", severity="high")

        import asyncio
        asyncio.run(alerts.process_finding_alerts(db, finding, asset))
        db.expire_all()

        assert delivered == ["https://good-jira.example/rest/api/3/issue"]
        bad = db.get(AlertIntegration, bad_id)
        assert "check SECRETS_ENCRYPTION_KEY" in (bad.last_error or "")


def test_model_repr_never_includes_secrets():
    from models import AlertChannel, AlertSeverity, AlertIntegration

    row = AlertIntegration(
        id=1, organization_id=2, name="x", channel=AlertChannel.SLACK,
        min_severity=AlertSeverity.HIGH, secret="super-secret",
        jira_api_token="token-secret",
    )
    assert "super-secret" not in repr(row)
    assert "token-secret" not in repr(row)
    assert "super-secret" not in str(row)
