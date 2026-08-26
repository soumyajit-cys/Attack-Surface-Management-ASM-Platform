"""Fine-grained permissions and their mapping to roles / API-key scopes.

Roles remain coarse (viewer < analyst < admin) for backwards compatibility,
but authorization decisions are made against :class:`Permission` sets, never
against raw role names. API keys carry coarse scopes (``read``, ``write``,
``admin``) which are intersected with the owning user's role permissions.
"""

from enum import Enum
from typing import Mapping

from app.core.errors import ForbiddenError


class Permission(str, Enum):

    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    FINDING_READ = "finding:read"
    SCAN_READ = "scan:read"
    SCAN_CREATE = "scan:create"
    POLICY_MANAGE = "policy:manage"
    ALERT_MANAGE = "alert:manage"
    REPORT_EXPORT = "report:export"
    ORG_MANAGE = "org:manage"
    AUDIT_READ = "audit:read"


_READ_PERMISSIONS = frozenset(
    {
        Permission.ASSET_READ,
        Permission.FINDING_READ,
        Permission.SCAN_READ,
    }
)

_ANALYST_PERMISSIONS = _READ_PERMISSIONS | frozenset(
    {
        Permission.SCAN_CREATE,
        Permission.POLICY_MANAGE,
        Permission.REPORT_EXPORT,
    }
)

_ADMIN_PERMISSIONS = frozenset(Permission)

ROLE_PERMISSIONS: Mapping[str, frozenset[Permission]] = {
    "viewer": _READ_PERMISSIONS,
    "analyst": _ANALYST_PERMISSIONS,
    "admin": _ADMIN_PERMISSIONS,
}

# Coarse API-key scopes -> permission sets they grant.
SCOPE_GRANTS: Mapping[str, frozenset[Permission]] = {
    "read": _READ_PERMISSIONS,
    "write": _ANALYST_PERMISSIONS,
    "admin": _ADMIN_PERMISSIONS,
}


def permissions_for_role(role: str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def permissions_for_scopes(scopes: str) -> frozenset[Permission]:
    """Parse an API-key ``scopes`` string (e.g. ``"read,write"``) into grants."""
    granted: set[Permission] = set()
    for raw in scopes.split(","):
        grant = SCOPE_GRANTS.get(raw.strip().lower())
        if grant:
            granted |= grant
    return frozenset(granted)


def effective_permissions(role: str, scopes: str | None = None) -> frozenset[Permission]:
    """Effective permission set for a user, optionally narrowed by API-key scopes."""
    role_perms = permissions_for_role(role)
    if scopes is None:
        return role_perms
    return role_perms & permissions_for_scopes(scopes)


def require_permissions(
    granted: frozenset[Permission], *needed: Permission
) -> None:
    """Raise :class:`ForbiddenError` unless ``granted`` covers ``needed``."""
    missing = [p.value for p in needed if p not in granted]
    if missing:
        raise ForbiddenError(
            "Missing required permissions",
            details={"missing": missing},
        )
