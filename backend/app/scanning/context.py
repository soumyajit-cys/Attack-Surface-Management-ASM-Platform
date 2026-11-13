"""Immutable scan context passed to every scanner module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class ScanContext:
    """Carries all state a scanner module needs to execute.

    Modules must NOT mutate this object. All persistence goes through ``db``.
    """

    domain: str
    pinned_ip: str
    org_id: int
    scan_id: int
    db: Session

    subdomains: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    # Optional cached HTTP response (status_code, headers, body) collected
    # by header_scan, reused by downstream modules (e.g. tech_fingerprint)
    # to avoid duplicate requests.
    http_response: dict[str, Any] | None = None
    # Scan scope name (see app.scanning.scope). Plain string (not imported)
    # to avoid a registry -> context -> scope import cycle.
    scope: str = "full"
