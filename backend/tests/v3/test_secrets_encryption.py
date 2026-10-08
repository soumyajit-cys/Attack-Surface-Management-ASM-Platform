"""Task 1.4: Fernet secrets at rest (TESTS FIRST).

Committed red: ``app.core.crypto`` does not exist yet. No real secrets are
used here except clearly-marked distinctive strings asserted ABSENT from
outputs. All network touching is mocked.
"""

import pytest

from app.core.crypto import (
    DecryptFailedError,
    decrypt_value,
    encrypt_value,
    is_encrypted,
    make_fernet,
)
from models import AlertIntegration, Asset, Finding


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
                          "alert_integrations.jira_api_token": 0}
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

    def test_api_never_returns_secrets(self, client, db, caplog, monkeypatch):
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
        with caplog.at_level(logging.INFO):
            listed = client.get("/api/v1/alerting/integrations", headers=headers)
            detail = client.get(
                f"/api/v1/alerting/integrations/{created.json()['id']}",
                headers=headers,
            )
        assert listed.status_code == 200 and detail.status_code == 200
        assert self.DISTINCTIVE not in listed.text
        assert self.DISTINCTIVE not in detail.text
        assert self.DISTINCTIVE not in caplog.text

    def test_send_failure_avoids_logs_and_records_last_error(
        self, client, db, monkeypatch, caplog
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
        with caplog.at_level(logging.INFO):
            result = client.post(
                f"/api/v1/alerting/integrations/{integration_id}/test",
                headers=headers,
            )
        assert result.status_code == 200
        assert self.DISTINCTIVE not in caplog.text
        db.expire_all()
        row = db.get(AlertIntegration, integration_id)
        assert row.last_error is not None


class TestSendTimeDecryptFailure:
    DISTINCTIVE = "zz-distinctive-jira-1a2b3c4d5e6f"

    def test_wrong_key_records_last_error_without_raising(
        self, db, monkeypatch, org_factory, caplog
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
        with caplog.at_level(logging.INFO):
            result = _aio(alerts.send_jira_alert(
                integration,
                Finding(organization_id=org.id, asset_id=1, title="T", severity="high"),
                Asset(organization_id=org.id, name="k.example.com"),
            ))
        assert result is False
        assert "check SECRETS_ENCRYPTION_KEY" in (integration.last_error or "")
        assert self.DISTINCTIVE not in caplog.text
        # Swap the working key back to prove the specific message persisted.
        # (Nothing is committed under the wrong key: even flush-time refresh
        # of expired attributes would fail to decrypt.)
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        db.commit()
        db.expire_all()
        assert "check SECRETS_ENCRYPTION_KEY" in (
            db.get(AlertIntegration, integration.id).last_error or "")

    def test_dispatch_loops_skip_loudly_without_crashing(
        self, db, monkeypatch, org_factory, caplog
    ):
        import logging

        import app.core.config as config_mod
        from models import AlertIntegration, AlertChannel, AlertSeverity
        from services.alerts import alerting_service as alerts

        org, _ = org_factory("Skip Org", "skipuser", "skip@example.com")
        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_A)
        integration = AlertIntegration(
            organization_id=org.id, name="Skip Hook", channel=AlertChannel.SLACK,
            webhook_url="https://hooks.example.com/x",
            min_severity=AlertSeverity.LOW, is_active=True,
        )
        db.add(integration)
        db.commit()

        monkeypatch.setattr(config_mod.settings, "secrets_encryption_key", KEY_B)
        db.expire_all()
        finding = Finding(organization_id=org.id, asset_id=1, title="T",
                          severity="high")
        asset = Asset(organization_id=org.id, name="s.example.com")
        with caplog.at_level(logging.ERROR):
            result_f = _aio(alerts.process_finding_alerts(db, finding, asset))
            result_c = _aio(alerts.process_change_alerts(db, [], asset))
        assert result_f is None and result_c is None
        assert "SECRETS_ENCRYPTION_KEY" in caplog.text


def _aio(coro):
    import asyncio
    return asyncio.run(coro)


def test_make_fernet_rejects_garbage():
    with pytest.raises(ValueError):
        make_fernet(["not-a-key"])
