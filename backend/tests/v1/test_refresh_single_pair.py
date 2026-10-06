"""Task 0.4: refresh mints exactly one live pair (no orphaned refresh token)."""

from utils.redis_client import get_redis


def _register(client, username="refreshuser", org="Refresh Org"):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "organization": org,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _live_refresh_keys():
    return get_redis().keys("refresh:*")


def test_refresh_returns_the_stored_pair_without_orphans(client):
    body = _register(client)
    assert len(_live_refresh_keys()) == 1

    first = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": body["refresh_token"]},
    )
    assert first.status_code == 200, first.text
    new_refresh = first.json()["refresh_token"]

    # Exactly one live refresh key: the returned one. The pre-fix code left
    # the rotated-in token orphaned in Redis (two live keys).
    assert len(_live_refresh_keys()) == 1

    # The returned pair is the live pair: it refreshes again.
    second = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": new_refresh}
    )
    assert second.status_code == 200, second.text
    assert len(_live_refresh_keys()) == 1

    # The original token stays rejected (rotation preserved).
    replay = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}
    )
    assert replay.status_code == 401
