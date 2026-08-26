"""User repository (v2, tenant-scoped).

Reads are always scoped to the caller's organization. Global lookups
(``get_by_username`` / ``get_by_email``) remain intentionally global because
usernames/emails are globally unique and are only used by authentication
flows that must resolve any tenant's user.
"""

from typing import Optional

from models.user import User

from app.db.scoped import OrgScope, OrgScopedRepository


class UserRepository(OrgScopedRepository[User]):

    model = User

    def get_by_username(self, username: str) -> Optional[User]:
        return (
            self.scope.db.query(User)
            .filter(User.username == username)
            .first()
        )

    def get_by_email(self, email: str) -> Optional[User]:
        return (
            self.scope.db.query(User)
            .filter(User.email == email)
            .first()
        )

    def list_for_organization(self) -> list[User]:
        return list(self._q().order_by(User.id).all())
