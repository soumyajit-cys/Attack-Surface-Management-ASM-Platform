"""G2 RBAC matrix: roles x routes, generated from permission deps (tests only).

The required permissions for every route are extracted from the actual
``require_permissions_dep`` closures on ``app.routes`` so the matrix cannot
drift from the code: ``test_required_permissions_match_expectations`` fails
if any route's deps change without updating EXPECTED. Behavior tests then
assert viewer/analyst/admin outcomes equal ``ROLE_PERMISSIONS`` predictions,
plus the full API-key auth matrix (scopes, expiry, revocation, prefix).
All network mocked; no real targets touched.
"""

import pytest

from app.core.permissions import (
    Permission,
    ROLE_PERMISSIONS,
    effective_permissions,
)


def _required_permissions(route):
    """Extract Permission set from require_permissions_dep closures."""
    found = set()
    stack = list(getattr(route.dependant, "dependencies", []) or [])
    seen = set()
    while stack:
        dep = stack.pop()
        if id(dep) in seen:
            continue
        seen.add(id(dep))
        call = getattr(dep, "call", None)
        qualname = getattr(call, "__qualname__", "") or ""
        if (getattr(call, "__name__", "") == "dependency"
                and "require_permissions_dep" in qualname):
            freevars = getattr(call, "__code__", None)
            closure = getattr(call, "__closure__", None) or ()
            if freevars:
                for var, cell in zip(freevars.co_freevars, closure):
                    if var == "needed":
                        found.update(cell.cell_contents)
        sub = getattr(dep, "dependant", None)
        if sub is not None:
            stack.extend(getattr(sub, "dependencies", []) or [])
    return frozenset(found)


def _route_table():
    from main import app

    table = {}
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if not path.startswith("/api/"):
            continue
        needed = _required_permissions(route)
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            table[(method, path)] = needed
    return table


# Expected required permissions per route, mirroring the *_DEP aliases.
# test_required_permissions_match_expectations enforces this against the code.
EXPECTED = {
    ("POST", "/api/v1/auth/register"): frozenset(),
    ("POST", "/api/v1/auth/login"): frozenset(),
    ("POST", "/api/v1/auth/refresh"): frozenset(),
    ("POST", "/api/v1/auth/logout"): frozenset(),
    ("POST", "/api/v1/auth/forgot-password"): frozenset(),
    ("POST", "/api/v1/auth/reset-password"): frozenset(),
    ("GET", "/api/v1/auth/me"): frozenset(),
    ("POST", "/api/v1/scans"): frozenset({Permission.SCAN_CREATE}),
    ("POST", "/api/v1/scans/verify-ownership"): frozenset({Permission.SCAN_CREATE}),
    ("GET", "/api/v1/scans/verify-ownership/check"): frozenset({Permission.SCAN_CREATE}),
    ("GET", "/api/v1/scans/verified-domains"): frozenset({Permission.SCAN_READ}),
    ("GET", "/api/v1/scans"): frozenset({Permission.SCAN_READ}),
    ("GET", "/api/v1/scans/{scan_id}"): frozenset({Permission.SCAN_READ}),
    ("GET", "/api/v1/findings"): frozenset({Permission.FINDING_READ}),
    ("GET", "/api/v1/findings/{finding_id}"): frozenset({Permission.FINDING_READ}),
    ("GET", "/api/v1/alerts"): frozenset({Permission.FINDING_READ}),
    ("GET", "/api/v1/dashboard"): frozenset({Permission.FINDING_READ}),
    ("GET", "/api/v1/assets"): frozenset({Permission.FINDING_READ}),
    ("GET", "/api/v1/assets/{asset_id}"): frozenset({Permission.FINDING_READ}),
    ("POST", "/api/v1/assets/{asset_id}/enrich"): frozenset({Permission.SCAN_CREATE}),
    ("GET", "/api/v1/assets/{asset_id}/graph"): frozenset({Permission.FINDING_READ}),
    ("POST", "/api/v1/organizations"): frozenset({Permission.ORG_MANAGE}),
    ("GET", "/api/v1/organizations/me"): frozenset(),
    ("POST", "/api/v1/organizations/invitations"): frozenset({Permission.ORG_MANAGE}),
    ("GET", "/api/v1/organizations/invitations"): frozenset({Permission.ORG_MANAGE}),
    ("POST", "/api/v1/organizations/invitations/{token}/accept"): frozenset(),
    ("POST", "/api/v1/organizations/invitations/{invitation_id}/revoke"): frozenset({Permission.ORG_MANAGE}),
    ("POST", "/api/v1/organizations/api-keys"): frozenset({Permission.ORG_MANAGE}),
    ("GET", "/api/v1/organizations/api-keys"): frozenset({Permission.ORG_MANAGE}),
    ("PATCH", "/api/v1/organizations/api-keys/{key_id}"): frozenset({Permission.ORG_MANAGE}),
    ("DELETE", "/api/v1/organizations/api-keys/{key_id}"): frozenset({Permission.ORG_MANAGE}),
    ("POST", "/api/v1/alerting/integrations"): frozenset({Permission.ALERT_MANAGE}),
    ("GET", "/api/v1/alerting/integrations"): frozenset({Permission.ALERT_MANAGE}),
    ("GET", "/api/v1/alerting/integrations/{integration_id}"): frozenset({Permission.ALERT_MANAGE}),
    ("PATCH", "/api/v1/alerting/integrations/{integration_id}"): frozenset({Permission.ALERT_MANAGE}),
    ("DELETE", "/api/v1/alerting/integrations/{integration_id}"): frozenset({Permission.ALERT_MANAGE}),
    ("POST", "/api/v1/alerting/integrations/{integration_id}/test"): frozenset({Permission.ALERT_MANAGE}),
    ("POST", "/api/v1/alerting/digest"): frozenset({Permission.ALERT_MANAGE}),
    ("GET", "/api/v1/alerting/digest"): frozenset({Permission.ALERT_MANAGE}),
    ("PATCH", "/api/v1/alerting/digest"): frozenset({Permission.ALERT_MANAGE}),
    ("DELETE", "/api/v1/alerting/digest"): frozenset({Permission.ALERT_MANAGE}),
    ("POST", "/api/v1/alerting/digest/test"): frozenset({Permission.ALERT_MANAGE}),
    ("POST", "/api/v1/reports/export/findings/csv"): frozenset({Permission.REPORT_EXPORT}),
    ("POST", "/api/v1/reports/export/assets/csv"): frozenset({Permission.REPORT_EXPORT}),
    ("POST", "/api/v1/reports/export/scans/csv"): frozenset({Permission.REPORT_EXPORT}),
    ("POST", "/api/v1/reports/export/domains/csv"): frozenset({Permission.REPORT_EXPORT}),
    ("POST", "/api/v1/reports/export/all/csv"): frozenset({Permission.REPORT_EXPORT}),
    ("GET", "/api/v1/reports/pdf/executive-summary"): frozenset({Permission.REPORT_EXPORT}),
    ("GET", "/api/v1/reports/pdf/finding/{finding_id}"): frozenset({Permission.REPORT_EXPORT}),
    ("POST", "/api/v1/scan-policies"): frozenset({Permission.POLICY_MANAGE}),
    ("GET", "/api/v1/scan-policies"): frozenset({Permission.SCAN_READ}),
    ("GET", "/api/v1/scan-policies/{policy_id}"): frozenset({Permission.SCAN_READ}),
    ("PATCH", "/api/v1/scan-policies/{policy_id}"): frozenset({Permission.POLICY_MANAGE}),
    ("DELETE", "/api/v1/scan-policies/{policy_id}"): frozenset({Permission.POLICY_MANAGE}),
    ("POST", "/api/v1/scan-policies/{policy_id}/run-now"): frozenset({Permission.POLICY_MANAGE}),
    ("POST", "/api/v1/auth/admin/unlock-account"): frozenset({Permission.ORG_MANAGE}),
    ("POST", "/api/v1/auth/2fa/enroll"): frozenset(),
    ("POST", "/api/v1/auth/2fa/confirm"): frozenset(),
    ("POST", "/api/v1/auth/2fa/disable"): frozenset(),
    ("POST", "/api/v1/auth/2fa/regenerate-codes"): frozenset(),
    ("POST", "/api/v1/auth/login/2fa"): frozenset(),
    ("POST", "/api/v1/organizations/2fa-requirement"): frozenset({Permission.ORG_MANAGE}),
    ("POST", "/api/v1/auth/admin/reset-2fa"): frozenset({Permission.ORG_MANAGE}),
}


def test_required_permissions_match_expectations():
    """The EXPECTED map below must equal the code's actual dep closures."""
    table = _route_table()
    assert table, "no routes introspected"
    missing = set(table) - set(EXPECTED)
    assert not missing, f"routes without EXPECTED entry: {sorted(missing)}"
    extra = set(EXPECTED) - set(table)
    assert not extra, f"stale EXPECTED entries: {sorted(extra)}"
    mismatched = {
        key: (sorted(table[key]), sorted(EXPECTED[key]))
        for key in table if table[key] != EXPECTED[key]
    }
    assert not mismatched, f"dep drift: {mismatched}"


def _public_dns(monkeypatch, ip="93.184.216.34"):
    import socket as stdlib_socket

    real_getaddrinfo = stdlib_socket.getaddrinfo

    def fake_getaddrinfo(host, *a, **k):
        if host in ("localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, *a, **k)
        return [(stdlib_socket.AF_INET, 1, 6, "", (ip, 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


@pytest.fixture()
def rbac(client, db, monkeypatch, org_factory):
    """One org with viewer/analyst/admin users plus minimal rows."""
    _public_dns(monkeypatch)
    from models import AlertIntegration, Asset, Finding, ScanHistory, ScanPolicy

    org, _admin = org_factory("RBAC Org", "rbacadmin", "rbacadmin@example.com")
    db.expire_all()

    def login(username, password="password123"):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    # org_factory creates the admin; add viewer + analyst via register-then-fix.
    for username, role in (("rbacviewer", "viewer"), ("rbacanalyst", "analyst")):
        reg = client.post(
            "/api/v1/auth/register",
            json={"username": username,
                  "email": f"{username}@example.com",
                  "password": "password123",
                  "organization": f"RBAC Tmp {username}"},
        )
        assert reg.status_code == 201, reg.text
        from models.user import User

        user = db.query(User).filter(User.username == username).one()
        user.organization_id = org.id
        user.role = role
        db.commit()
    headers = {role: login(f"rbac{role if role != 'admin' else 'admin'}")
               for role in ("viewer", "analyst", "admin")}
    # NOTE: admin username is rbacadmin (created by org_factory).
    headers["admin"] = login("rbacadmin")

    asset = Asset(organization_id=org.id, name="rbac.example.com")
    db.add(asset)
    db.flush()
    finding = Finding(organization_id=org.id, asset_id=asset.id,
                      title="RBAC finding", severity="low")
    db.add(finding)
    scan = ScanHistory(organization_id=org.id, asset_id=asset.id,
                       target="rbac.example.com", status="completed",
                       scope="full")
    db.add(scan)
    policy = ScanPolicy(organization_id=org.id, asset_id=asset.id,
                        name="RBAC policy", frequency="weekly", scope="full")
    db.add(policy)
    hook = AlertIntegration(
        organization_id=org.id, name="RBAC hook", channel="slack",
        webhook_url="https://hooks.example.com/x", min_severity="low",
        is_active=True)
    from models import AlertChannel, AlertSeverity

    hook.channel = AlertChannel.SLACK
    hook.min_severity = AlertSeverity.LOW
    db.add(hook)
    db.commit()
    return {"headers": headers, "org_id": org.id,
            "ids": {"asset": asset.id, "finding": finding.id,
                    "scan": scan.id, "policy": policy.id,
                    "integration": hook.id}}


READ_CASES = [
    ("GET", "/api/v1/auth/me", None),
    ("GET", "/api/v1/scans/verified-domains", None),
    ("GET", "/api/v1/scans", None),
    ("GET", "/api/v1/findings", None),
    ("GET", "/api/v1/alerts", None),
    ("GET", "/api/v1/dashboard", None),
    ("GET", "/api/v1/assets", None),
    ("GET", "/api/v1/organizations/me", None),
    ("GET", "/api/v1/organizations/invitations", None),
    ("GET", "/api/v1/organizations/api-keys", None),
    ("GET", "/api/v1/alerting/integrations", None),
    ("GET", "/api/v1/scan-policies", None),
    ("GET", "/api/v1/scans/{scan_id}", "scan"),
    ("GET", "/api/v1/findings/{finding_id}", "finding"),
    ("GET", "/api/v1/assets/{asset_id}", "asset"),
    ("GET", "/api/v1/scan-policies/{policy_id}", "policy"),
    ("GET", "/api/v1/alerting/integrations/{integration_id}", "integration"),
    ("GET", "/api/v1/assets/{asset_id}/graph", "asset"),
]


@pytest.mark.parametrize("method,template,key", READ_CASES)
def test_role_matrix_reads(client, rbac, method, template, key):
    """Viewer/analyst/admin outcomes must equal ROLE_PERMISSIONS predictions."""
    needed = EXPECTED[(method, template)]
    url = template
    if key:
        url = url.replace("{scan_id}", str(rbac["ids"]["scan"]))
        url = url.replace("{finding_id}", str(rbac["ids"]["finding"]))
        url = url.replace("{asset_id}", str(rbac["ids"]["asset"]))
        url = url.replace("{policy_id}", str(rbac["ids"]["policy"]))
        url = url.replace("{integration_id}", str(rbac["ids"]["integration"]))
    for role in ("viewer", "analyst", "admin"):
        response = client.request(method, url, headers=rbac["headers"][role])
        allowed = needed <= ROLE_PERMISSIONS[role]
        if allowed:
            assert response.status_code != 403, (
                f"{role} {method} {template}: unexpected 403: "
                f"{response.text[:200]}")
        else:
            assert response.status_code == 403, (
                f"{role} {method} {template}: expected 403, got "
                f"{response.status_code}")


def test_role_matrix_writes(client, db, rbac, monkeypatch):
    """Write routes: viewer 403 everywhere; analyst only where granted."""
    from tasks import discovery_tasks as dt

    monkeypatch.setattr(dt.run_discovery, "delay", lambda *a, **k: None)
    headers = rbac["headers"]
    # Viewer is denied on every write route.
    denied = [
        ("POST", "/api/v1/organizations/invitations",
         {"email": "x@example.com", "role": "viewer"}),
        ("POST", "/api/v1/auth/admin/unlock-account",
         {"username": "x"}),
        ("POST", "/api/v1/organizations/api-keys", {"name": "k"}),
        ("POST", "/api/v1/alerting/integrations",
         {"name": "h", "channel": "slack",
          "webhook_url": "https://hooks.example.com/x"}),
        ("POST", "/api/v1/scan-policies",
         {"name": "p", "asset_id": rbac["ids"]["asset"]}),
        ("POST", "/api/v1/reports/export/findings/csv", {}),
    ]
    for method, url, body in denied:
        response = client.request(method, url, json=body,
                                  headers=headers["viewer"])
        assert response.status_code == 403, f"viewer {method} {url}"
    # Analyst: policy manage yes, alert manage no, report export yes.
    response = client.post(
        "/api/v1/scan-policies",
        json={"name": "analyst policy", "asset_id": rbac["ids"]["asset"]},
        headers=headers["analyst"])
    assert response.status_code == 201, response.text
    response = client.post(
        "/api/v1/alerting/integrations",
        json={"name": "h", "channel": "slack",
              "webhook_url": "https://hooks.example.com/x"},
        headers=headers["analyst"])
    assert response.status_code == 403
    response = client.post(
        "/api/v1/reports/export/findings/csv", json={},
        headers=headers["analyst"])
    assert response.status_code == 200, response.text[:200]
    # Admin: full access (integration create exercises webhook validation).
    response = client.post(
        "/api/v1/alerting/integrations",
        json={"name": "admin hook", "channel": "slack",
              "webhook_url": "https://hooks.example.com/x"},
        headers=headers["admin"])
    assert response.status_code == 201, response.text


def _make_key(client, headers, scopes="read", name="k"):
    created = client.post(
        "/api/v1/organizations/api-keys", json={"name": name, "scopes": scopes},
        headers=headers)
    assert created.status_code == 201, created.text
    body = created.json()
    assert "key" in body and body["key"].startswith("sk_")
    return body["id"], body["key"]


def test_api_key_scope_matrix(client, rbac):
    """Read key reads, cannot write; admin key can; effective = role ∩ scope."""
    headers = rbac["headers"]
    _read_id, read_key = _make_key(client, headers["admin"], scopes="read")
    _admin_id, admin_key = _make_key(client, headers["admin"], scopes="admin",
                                     name="k2")
    read_h = {"X-API-Key": read_key}
    assert client.get("/api/v1/assets", headers=read_h).status_code == 200
    denied = client.post(
        "/api/v1/alerting/integrations",
        json={"name": "h", "channel": "slack",
              "webhook_url": "https://hooks.example.com/x"}, headers=read_h)
    assert denied.status_code == 403
    admin_h = {"X-API-Key": admin_key}
    created = client.post(
        "/api/v1/alerting/integrations",
        json={"name": "key hook", "channel": "slack",
              "webhook_url": "https://hooks.example.com/x"}, headers=admin_h)
    assert created.status_code == 201, created.text


def test_api_key_rejections_and_last_used(client, db, rbac):
    """Expired, inactive, malformed keys rejected; last_used_at stamped."""
    from datetime import datetime, timedelta, timezone

    from models.organization import APIKey

    headers = rbac["headers"]
    key_id, key = _make_key(client, headers["admin"], name="k3")
    row = db.query(APIKey).filter(APIKey.id == key_id).one()
    assert row.last_used_at is None
    assert client.get("/api/v1/assets",
                      headers={"X-API-Key": key}).status_code == 200
    db.expire_all()
    assert db.query(APIKey).filter(APIKey.id == key_id).one().last_used_at is not None

    # Expired.
    row = db.query(APIKey).filter(APIKey.id == key_id).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert client.get("/api/v1/assets",
                      headers={"X-API-Key": key}).status_code == 401
    row.expires_at = None
    row.is_active = False
    db.commit()
    assert client.get("/api/v1/assets",
                      headers={"X-API-Key": key}).status_code == 401
    row.is_active = True
    db.commit()
    # Wrong prefix / no separator / empty.
    assert client.get("/api/v1/assets",
                      headers={"X-API-Key": "xx" + key[2:]}).status_code == 401
    assert client.get("/api/v1/assets",
                      headers={"X-API-Key": "noseparator"}).status_code == 401
    assert client.get("/api/v1/assets",
                      headers={"X-API-Key": ""}).status_code == 401


def test_effective_permissions_unit():
    """role ∩ scope semantics incl. unknown roles/scopes."""
    assert effective_permissions("admin") == ROLE_PERMISSIONS["admin"]
    assert effective_permissions("viewer", "admin") == ROLE_PERMISSIONS["viewer"]
    assert effective_permissions("nobody") == frozenset()
    assert effective_permissions("admin", "bogus") == frozenset()
    assert (effective_permissions("analyst", "read,write")
            == ROLE_PERMISSIONS["analyst"] & ROLE_PERMISSIONS["analyst"])
