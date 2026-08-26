"""Tenant-isolation tests at the REPOSITORY layer.

These prove that cross-tenant access is structurally impossible: scoped
repositories filter by organization_id at the query layer, and the domain
hijack bug (global-unique domains being reassigned across tenants) now fails
loudly instead of silently stealing data.
"""

import pytest

from models.asset import Asset
from models.domain import Domain

from app.db.scoped import OrgScope, TenantScopeError
from app.repositories.assets import AssetRepository, DomainOwnedByAnotherOrgError, DomainRepository
from app.repositories.users import UserRepository


def test_scope_without_org_raises(db):
    scope = OrgScope(db=db, organization_id=None)
    with pytest.raises(TenantScopeError):
        scope.query(Asset).all()


def test_user_repo_is_scoped_to_organization(db, org_factory):
    org_a, user_a = org_factory("Iso A", "iso_a")
    org_b, user_b = org_factory("Iso B", "iso_b")

    repo_a = UserRepository(OrgScope(db=db, organization_id=org_a.id))
    repo_b = UserRepository(OrgScope(db=db, organization_id=org_b.id))

    assert [u.id for u in repo_a.list_for_organization()] == [user_a.id]
    assert [u.id for u in repo_b.list_for_organization()] == [user_b.id]

    assert repo_a.get(user_b.id) is None
    assert repo_b.get(user_a.id) is None


def test_asset_repo_is_scoped(db, org_factory):
    org_a, user_a = org_factory("Iso Assets A", "iso_assets_a")
    org_b, user_b = org_factory("Iso Assets B", "iso_assets_b")

    asset_a = Asset(organization_id=org_a.id, name="a.example.com")
    asset_b = Asset(organization_id=org_b.id, name="b.example.com")
    db.add_all([asset_a, asset_b])
    db.flush()

    repo_a = AssetRepository(OrgScope(db=db, organization_id=org_a.id))
    repo_b = AssetRepository(OrgScope(db=db, organization_id=org_b.id))

    assert repo_a.get(asset_b.id) is None
    assert repo_b.get(asset_a.id) is None
    assert repo_a.get(asset_a.id) is not None

    assert [a.id for a in repo_a.list()] == [asset_a.id]
    assert [a.id for a in repo_b.list()] == [asset_b.id]


def test_get_or_create_domain_same_org_roundtrip(db, org_factory):
    org_a, _ = org_factory("Domain Org", "domain_user")
    asset = Asset(organization_id=org_a.id, name="domain-org.example")
    db.add(asset)
    db.flush()

    repo = DomainRepository(OrgScope(db=db, organization_id=org_a.id))
    created = repo.get_or_create("shared.example", asset)
    db.flush()

    again = repo.get_or_create("shared.example", asset)
    assert again.id == created.id
    assert again.organization_id == org_a.id


def test_get_or_create_domain_cross_org_raises_not_hijacks(db, org_factory):
    """The old bug: org B scanning a domain owned by org A reassigned the row.

    Now the scoped repository raises instead of stealing the row.
    """
    org_a, _ = org_factory("Domain Owner", "owner_user")
    org_b, _ = org_factory("Domain Attacker", "attacker_user")

    asset_a = Asset(organization_id=org_a.id, name="owner.example")
    asset_b = Asset(organization_id=org_b.id, name="attacker.example")
    db.add_all([asset_a, asset_b])
    db.flush()

    repo_a = DomainRepository(OrgScope(db=db, organization_id=org_a.id))
    owned = repo_a.get_or_create("contested.example", asset_a)
    original_asset_id = owned.asset_id
    original_org_id = owned.organization_id
    db.flush()

    repo_b = DomainRepository(OrgScope(db=db, organization_id=org_b.id))
    with pytest.raises(DomainOwnedByAnotherOrgError):
        repo_b.get_or_create("contested.example", asset_b)

    # Row untouched: still org A's.
    db.expire_all()
    row = db.query(Domain).filter(Domain.domain == "contested.example").one()
    assert row.organization_id == original_org_id
    assert row.asset_id == original_asset_id
    assert row.organization_id == org_a.id


def test_domain_repo_get_scoped(db, org_factory):
    org_a, _ = org_factory("Domain Iso A", "domain_iso_a")
    org_b, _ = org_factory("Domain Iso B", "domain_iso_b")

    asset_a = Asset(organization_id=org_a.id, name="iso-a.example")
    asset_b = Asset(organization_id=org_b.id, name="iso-b.example")
    db.add_all([asset_a, asset_b])
    db.flush()

    domain_a = Domain(organization_id=org_a.id, asset_id=asset_a.id, domain="only-a.example")
    db.add(domain_a)
    db.flush()

    repo_b = DomainRepository(OrgScope(db=db, organization_id=org_b.id))
    assert repo_b.get_by_name("only-a.example") is None
    assert repo_b.get(domain_a.id) is None

    repo_a = DomainRepository(OrgScope(db=db, organization_id=org_a.id))
    assert repo_a.get_by_name("only-a.example") is not None
