"""Tenant (organization) scoping primitives.

Every repository query MUST go through an :class:`OrgScope`. The scope injects
``organization_id`` filters at the query layer, so cross-tenant access is
structurally impossible rather than depending on each route remembering to
filter.
"""

from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from sqlalchemy import ColumnExpressionArgument
from sqlalchemy.orm import Query, Session

from app.core.errors import TenantScopeError
from models.base import Base


@dataclass(frozen=True)
class OrgScope:
    """Tenant execution context carried by every scoped repository."""

    db: Session
    organization_id: int | None

    def filter(self, model: type[Base]) -> ColumnExpressionArgument[bool]:
        if self.organization_id is None:
            raise TenantScopeError(
                "Query attempted without tenant context (organization_id is None)"
            )
        return model.organization_id == self.organization_id  # type: ignore[attr-defined]

    def query(self, model: type[Base]) -> Query:
        return self.db.query(model).filter(self.filter(model))


M = TypeVar("M", bound=Any)


class OrgScopedRepository(Generic[M]):
    """Base class for repositories whose model carries ``organization_id``.

    Subclasses set ``model`` and automatically receive tenant-filtered
    ``get``/``list``/``count`` primitives. Direct use of the raw session for
    tenant-owned models is discouraged in v1+ code.
    """

    model: type[Base]

    def __init__(self, scope: OrgScope) -> None:
        self.scope = scope

    @property
    def db(self) -> Session:
        return self.scope.db

    def _q(self) -> Query:
        return self.scope.query(self.model)

    def get(self, record_id: int) -> M | None:
        return (
            self._q()
            .filter(self.model.id == record_id)  # type: ignore[attr-defined]
            .first()
        )

    def list(self, *, limit: int | None = None, offset: int = 0) -> list[M]:
        query = self._q().order_by(self.model.id)  # type: ignore[attr-defined]
        if offset:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)
        return list(query.all())

    def count(self) -> int:
        return int(self._q().count())

    def add(self, instance: M) -> M:
        self.db.add(instance)
        self.db.flush()
        return instance

    def delete(self, instance: M) -> None:
        self.db.delete(instance)
        self.db.flush()
