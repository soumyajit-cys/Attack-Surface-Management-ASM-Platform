"""Asset & domain repositories (v2, tenant-scoped).

Fixes the cross-tenant hijack bug: the legacy
``services.scanner.persistence.get_or_create_domain`` looked domains up
globally (the ``domains.domain`` column is globally unique) and reassigned an
existing row into the scanning tenant's asset. Here the lookup is org-scoped
first, and a collision with *another* tenant's domain raises
:class:`DomainOwnedByAnotherOrgError` instead of silently stealing the row.

NOTE: the schema still enforces global uniqueness on ``domains.domain``; the
migration to ``unique(organization_id, domain)`` lands with the data-model
chunk. Until then, scanning a domain owned by another org fails loudly.
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

        Raises :class:`DomainOwnedByAnotherOrgError` when the domain exists
        globally but belongs to a different organization.
        """
        existing = self.get_by_name(name)
        if existing is not None:
            if existing.asset_id != asset.id:
                existing.asset_id = asset.id  # same org, re-point to scanning asset
                self.db.flush()
            return existing

        global_row = (
            self.db.query(Domain).filter(Domain.domain == name).first()
        )
        if global_row is not None:
            raise DomainOwnedByAnotherOrgError(name)

        domain = Domain(
            organization_id=self.scope.organization_id,
            asset_id=asset.id,
            domain=name,
        )
        return self.add(domain)
