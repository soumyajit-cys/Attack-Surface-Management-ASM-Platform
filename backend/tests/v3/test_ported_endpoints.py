"""Task 0.4: tests for endpoints ported from the legacy surface to v1."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from models import Invitation


def _register(client, org="Port Org", username="portuser", email="portuser@example.com"):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": email,
            "password": "password123",
            "organization": org,
        },
    )
    assert response.status_code == 201, response.text
    return response


def _login(client, username="portuser"):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _invite(client, headers, email="guest@example.com", role="viewer"):
    response = client.post(
        "/api/v1/organizations/invitations",
        json={"email": email, "role": role},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


class TestInvitationAcceptV1:
    def test_full_invite_accept_login_flow(self, client, db):
        _register(client)
        headers = _login(client)
        _invite(client, headers)

        token = db.query(Invitation).filter(
            Invitation.email == "guest@example.com"
        ).one().token

        accepted = client.post(
            f"/api/v1/organizations/invitations/{token}/accept",
            json={"username": "guest", "password": "password123"},
        )
        assert accepted.status_code == 200, accepted.text

        login = client.post(
            "/api/v1/auth/login",
            json={"username": "guest", "password": "password123"},
        )
        assert login.status_code == 200, login.text

    def test_accept_unknown_token_404(self, client):
        response = client.post(
            "/api/v1/organizations/invitations/nope/accept",
            json={"username": "ghost", "password": "password123"},
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "invitation_invalid"

    def test_accept_expired_token_400(self, client, db):
        _register(client, username="expadmin", email="expadmin@example.com")
        headers = _login(client, username="expadmin")
        _invite(client, headers, email="old@example.com")

        invitation = db.query(Invitation).filter(
            Invitation.email == "old@example.com"
        ).one()
        invitation.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()

        response = client.post(
            f"/api/v1/organizations/invitations/{invitation.token}/accept",
            json={"username": "oldguest", "password": "password123"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invitation_expired"


class TestOrganizationCreateV1:
    def test_create_moves_caller_to_new_org(self, client):
        _register(client)
        headers = _login(client)

        created = client.post(
            "/api/v1/organizations",
            json={"name": "Second Org"},
            headers=headers,
        )
        assert created.status_code == 201, created.text

        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.json()["organization_name"] == "Second Org"

    def test_create_duplicate_name_409(self, client):
        _register(client, org="Taken Org")
        headers = _login(client)

        response = client.post(
            "/api/v1/organizations",
            json={"name": "Taken Org"},
            headers=headers,
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "organization_taken"


class TestDigestTestV1:
    def _seed_config(self, client, headers):
        response = client.post(
            "/api/v1/alerting/digest",
            json={
                "frequency": "weekly",
                "day_of_week": 1,
                "hour_utc": 9,
                "recipient_emails": "a@b.com",
                "min_severity": "medium",
            },
            headers=headers,
        )
        assert response.status_code == 201, response.text

    def test_digest_test_without_config_404(self, client):
        _register(client, username="dtest", email="dtest@example.com")
        headers = _login(client, username="dtest")

        response = client.post("/api/v1/alerting/digest/test", headers=headers)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "digest_config_not_found"

    def test_digest_test_sends_when_delivery_succeeds(self, client):
        _register(client, username="dtest2", email="dtest2@example.com")
        headers = _login(client, username="dtest2")
        self._seed_config(client, headers)

        with patch(
            "services.alerts.alerting_service.send_email_digest",
            new=AsyncMock(return_value=True),
        ):
            response = client.post("/api/v1/alerting/digest/test", headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["message"] == "Test digest sent successfully"

    def test_digest_test_500_when_delivery_fails(self, client):
        _register(client, username="dtest3", email="dtest3@example.com")
        headers = _login(client, username="dtest3")
        self._seed_config(client, headers)

        with patch(
            "services.alerts.alerting_service.send_email_digest",
            new=AsyncMock(return_value=False),
        ):
            response = client.post("/api/v1/alerting/digest/test", headers=headers)
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "digest_send_failed"
