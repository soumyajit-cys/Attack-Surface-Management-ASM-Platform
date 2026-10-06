"""Scan scopes: exactly what each scope is allowed to touch.

Single source of truth for scope semantics (Phase 1, task 1.2). The pipeline
consults this mapping instead of scattering ``if scope == ...`` checks:

- ``passive`` — third-party/normal-DNS discovery only (crt.sh, DNS records,
  DNS brute-force resolution, WHOIS). Zero packets to target ports/services.
- ``active`` — adds port scanning, TLS inspection, and HTTP header checks.
- ``full`` — active plus CVE enrichment (OSV.dev banner matching).

NOTE (Phase 4): the nuclei template scanner slots into ``full`` as a new
registry phase (e.g. ``ScanPhase.VULN``) added to ``SCOPE_PHASES["full"]``
and to the enrichment gate below. ``run_nuclei_scan`` exists but is
deliberately unwired until then.
"""

from __future__ import annotations

from app.scanning.registry import ScanPhase

SCOPE_PASSIVE = "passive"
SCOPE_ACTIVE = "active"
SCOPE_FULL = "full"

SCOPES = (SCOPE_PASSIVE, SCOPE_ACTIVE, SCOPE_FULL)

DEFAULT_SCOPE = SCOPE_FULL

SCOPE_PHASES: dict[str, frozenset[ScanPhase]] = {
    SCOPE_PASSIVE: frozenset({ScanPhase.DISCOVERY}),
    SCOPE_ACTIVE: frozenset({ScanPhase.DISCOVERY, ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER}),
    SCOPE_FULL: frozenset({ScanPhase.DISCOVERY, ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER}),
}

#: Scopes allowed to run post-scan CVE enrichment (OSV.dev).
SCOPE_ENRICHMENT: frozenset[str] = frozenset({SCOPE_FULL})


def normalize_scope(scope: str | None) -> str:
    """Lowercase *scope*, defaulting to ``full``; raises ``ValueError`` if unknown."""
    normalized = (scope or DEFAULT_SCOPE).strip().lower()
    if normalized not in SCOPES:
        raise ValueError(f"Unknown scan scope: {scope!r}")
    return normalized


def phases_for_scope(scope: str) -> frozenset[ScanPhase]:
    """Registry phases a scan of *scope* may execute."""
    return SCOPE_PHASES[normalize_scope(scope)]


def phase_allowed(scope: str, phase: ScanPhase) -> bool:
    """True if *phase* may run under *scope*."""
    return phase in phases_for_scope(scope)


def enrichment_allowed(scope: str) -> bool:
    """True if post-scan CVE enrichment may run under *scope*."""
    return normalize_scope(scope) in SCOPE_ENRICHMENT
