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


def is_at_least(user: User, minimum_role: str) -> bool:
    return (
        ROLE_HIERARCHY.get(user.role, 0)
        >= ROLE_HIERARCHY.get(minimum_role, 0)
    )