"""Asset & domain repositories (v2, tenant-scoped).

Domains are unique per organization (``uq_domains_org_domain``). Lookups are
org-scoped, so two orgs may each own the same domain name as separate rows.
``DomainOwnedByAnotherOrgError`` is kept for backwards compatibility but is no
longer raised by :meth:`DomainRepository.get_or_create`.
"""

from typing import Optional

from models.asset import Asset
from models.domain import Domain

from app.core.errors import ConflictError
from app.db.scoped import OrgScope, OrgScopedRepository


class DomainOwnedByAnotherOrgError(ConflictError):
    code = "domain_owned_by_other_org"

    def __init__(self, domain: str) -> None:
        super().__init__(
            "Domain already belongs to another organization",
            details={"domain": domain},
        )


class AssetRepository(OrgScopedRepository[Asset]):

    model = Asset

    def get_by_name(self, name: str) -> Optional[Asset]:
        return self._q().filter(Asset.name == name).first()


class DomainRepository(OrgScopedRepository[Domain]):

    model = Domain

    def get_by_name(self, name: str) -> Optional[Domain]:
        return self._q().filter(Domain.domain == name).first()

    def get_or_create(self, name: str, asset: Asset) -> Domain:
        """Fetch this org's domain by name, creating it under ``asset`` if absent.

        Each organization gets its own row: a domain owned by another org does
        not affect this org's lookup.
        """
        existing = self.get_by_name(name)
        if existing is not None:
            if existing.asset_id != asset.id:
                existing.asset_id = asset.id  # same org, re-point to scanning asset
                self.db.flush()
            return existing

        domain = Domain(
            organization_id=self.scope.organization_id,
            asset_id=asset.id,
            domain=name,
        )
        return self.add(domain)
