"""Task 0.1: scanner persistence is tenant-isolated per (organization_id, domain)."""

from models.asset import Asset
from models.domain import Domain
from models.subdomain import Subdomain

from services.scanner.persistence import (
    get_or_create_domain,
    persist_discovery_results,
)


def test_scanner_get_or_create_domain_is_per_org(db, org_factory):
    org_a, _ = org_factory("Scanner A", "scanner_a", "scanner_a@example.com")
    org_b, _ = org_factory("Scanner B", "scanner_b", "scanner_b@example.com")

    asset_a = Asset(organization_id=org_a.id, name="shared.example")
    asset_b = Asset(organization_id=org_b.id, name="shared.example")
    db.add_all([asset_a, asset_b])
    db.flush()

    row_a = get_or_create_domain(db, org_a.id, asset_a, "shared.example")
    row_b = get_or_create_domain(db, org_b.id, asset_b, "shared.example")
    db.flush()

    assert row_a.id != row_b.id
    assert row_a.organization_id == org_a.id
    assert row_b.organization_id == org_b.id
    assert row_a.asset_id == asset_a.id
    assert row_b.asset_id == asset_b.id

    # Same-org roundtrip returns the same row.
    again = get_or_create_domain(db, org_a.id, asset_a, "shared.example")
    assert again.id == row_a.id


def test_persist_discovery_results_is_per_org(db, org_factory):
    org_a, _ = org_factory("Persist A", "persist_a", "persist_a@example.com")
    org_b, _ = org_factory("Persist B", "persist_b", "persist_b@example.com")

    payload = {
        "registrar": "Example Registrar",
        "asn": None,
        "dns": [{"type": "A", "value": "93.184.216.34"}],
        "subdomains": [{"subdomain": "www.shared.example", "source": "crt.sh"}],
    }

    out_a = persist_discovery_results(db, org_a.id, "shared.example", payload)
    out_b = persist_discovery_results(db, org_b.id, "shared.example", payload)
    db.flush()

    assert out_a["domain_id"] != out_b["domain_id"]
    assert out_a["asset_id"] != out_b["asset_id"]

    rows = db.query(Domain).filter(Domain.domain == "shared.example").all()
    assert sorted(r.organization_id for r in rows) == sorted([org_a.id, org_b.id])

    subs_a = db.query(Subdomain).filter(
        Subdomain.domain_id == out_a["domain_id"]
    ).all()
    subs_b = db.query(Subdomain).filter(
        Subdomain.domain_id == out_b["domain_id"]
    ).all()
    assert [s.subdomain for s in subs_a] == ["www.shared.example"]
    assert [s.subdomain for s in subs_b] == ["www.shared.example"]
