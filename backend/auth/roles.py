from fastapi import Depends, HTTPException, status

from auth.dependencies import get_current_user
from models.user import User

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"

ROLE_HIERARCHY = {
    ROLE_VIEWER: 1,
    ROLE_ANALYST: 2,
    ROLE_ADMIN: 3,
}

ALL_ROLES = set(ROLE_HIERARCHY.keys())


def require_role(required_role: str):
    from auth.dependencies import require_role as _require_role
    return _require_role(required_role)


def require_roles(*roles: str):
    from auth.dependencies import require_roles as _require_roles
    return _require_roles(*roles)


def is_at_least(user: User, minimum_role: str) -> bool:
    return (
        ROLE_HIERARCHY.get(user.role, 0)
        >= ROLE_HIERARCHY.get(minimum_role, 0)
    )


def require_min_role(minimum_role: str):
    def checker(
        user: User = Depends(get_current_user),
    ) -> User:
        if not is_at_least(user, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user
    return checker