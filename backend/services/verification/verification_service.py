"""Domain ownership verification: challenges, checks, and scan gating.

Methods: ``dns_txt`` (``_sentinelasm-challenge.<domain>`` TXT) and
``http_file`` (``/.well-known/sentinelasm-<token>.txt``). Both the token and
the HTTP body carry ``sentinelasm-verification=<token>``; tokens are
challenge secrets and are never logged.

Public suffixes (``co.uk``, ``github.io``, bare TLDs) can never be verified:
the PSL check uses tldextract with ``suffix_list_urls=()`` (bundled snapshot
only, zero network I/O by construction) plus ``cache_dir=None`` (no disk
writes, container-safe) and the private-domains section enabled.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

import tldextract
from sqlalchemy.orm import Session

from models.alert import Alert
from models.verified_domain import VerifiedDomain
from utils.logger import logger
from utils.ssrf_guard import verify_domain_ownership

METHOD_DNS_TXT = "dns_txt"
METHOD_HTTP_FILE = "http_file"
METHODS = (METHOD_DNS_TXT, METHOD_HTTP_FILE)

STATUS_PENDING = "pending"
STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"
STATUS_GRANDFATHERED = "grandfathered"

HTTP_FILE_TIMEOUT_SECONDS = 10
HTTP_MAX_REDIRECT_HOPS = 3
# Verification bodies are under 100 bytes; never buffer more than this.
HTTP_MAX_BODY_BYTES = 65536

_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _expiry_days() -> int:
    from app.core.config import settings
    try:
        return max(int(settings.verification_expiry_days), 1)
    except (TypeError, ValueError):
        return 90


def normalize_domain(domain: str | None) -> str:
    return (domain or "").strip().lower().rstrip(".")


def is_public_suffix(domain: str) -> bool:
    """True when *domain* is itself a public suffix (or has no registrable part)."""
    domain = normalize_domain(domain)
    if not domain:
        return True
    try:
        extracted = _EXTRACTOR(domain)
    except Exception:
        return True
    return not extracted.top_domain_under_public_suffix


def parent_candidates(domain: str) -> list[str]:
    """Parent domains, nearest first, excluding bare TLDs."""
    parts = normalize_domain(domain).split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]


def challenge_value(token: str) -> str:
    return f"sentinelasm-verification={token}"


def http_file_path(token: str) -> str:
    return f"/.well-known/sentinelasm-{token}.txt"


def initiate_verification(
    db: Session, org_id: int, domain: str, method: str
) -> VerifiedDomain:
    """Create (or reset) a pending challenge for *domain*.

    Raises ``ValueError`` for unknown methods and public suffixes.
    """
    domain = normalize_domain(domain)
    if method not in METHODS:
        raise ValueError(f"Unknown verification method: {method!r}")
    if is_public_suffix(domain):
        raise ValueError(
            f"Cannot verify {domain!r}: public suffixes cannot be owned by one organization"
        )

    row = (
        db.query(VerifiedDomain)
        .filter(
            VerifiedDomain.organization_id == org_id,
            VerifiedDomain.domain == domain,
        )
        .first()
    )
    token = secrets.token_urlsafe(16)
    if row is None:
        row = VerifiedDomain(
            organization_id=org_id,
            domain=domain,
            method=method,
            status=STATUS_PENDING,
            token=token,
        )
        db.add(row)
    else:
        row.method = method
        row.token = token
        row.status = STATUS_PENDING
        row.verified_at = None
        row.expires_at = None
    db.flush()
    return row


def find_covering_row(
    db: Session, org_id: int, domain: str
) -> VerifiedDomain | None:
    """This org's row for *domain* or the nearest verified-capable parent."""
    domain = normalize_domain(domain)
    for candidate in [domain, *parent_candidates(domain)]:
        row = (
            db.query(VerifiedDomain)
            .filter(
                VerifiedDomain.organization_id == org_id,
                VerifiedDomain.domain == candidate,
            )
            .first()
        )
        if row is not None:
            return row
    return None


def is_scan_allowed(
    db: Session, org_id: int, domain: str, now: datetime | None = None
) -> tuple[bool, str, VerifiedDomain | None]:
    """Gate helper. Returns ``(allowed, mode_or_reason, row)``.

    Modes: ``"verified"`` or ``"grandfathered"``. Reasons are human-readable
    and safe to surface to the caller.
    """
    now = now or _now()
    row = find_covering_row(db, org_id, normalize_domain(domain))
    if row is None:
        return False, "Domain is not verified for this organization", None
    if row.status == STATUS_VERIFIED and (
        row.expires_at is None or row.expires_at > now
    ):
        return True, STATUS_VERIFIED, row
    if (
        row.status == STATUS_GRANDFATHERED
        and row.expires_at is not None
        and row.expires_at > now
    ):
        return True, STATUS_GRANDFATHERED, row
    if row.status in (STATUS_VERIFIED, STATUS_GRANDFATHERED):
        return (
            False,
            f"Domain verification expired on {row.expires_at}; re-verify to scan",
            row,
        )
    return (
        False,
        f"Domain verification is {row.status}; complete verification to scan",
        row,
    )


def record_grace_notice(
    db: Session, org_id: int, asset_id: int | None, row: VerifiedDomain
) -> Alert:
    """In-app alert reminding owners to verify a grandfathered domain."""
    alert = Alert(
        organization_id=org_id,
        asset_id=asset_id,
        title=f"Verify {row.domain} before {row.expires_at}",
        severity="medium",
        message=json.dumps({
            "type": "verification_grace",
            "domain": row.domain,
            "expires_at": str(row.expires_at),
        }),
    )
    db.add(alert)
    db.flush()
    return alert


def record_skip_notice(
    db: Session,
    org_id: int,
    asset_id: int | None,
    target: str,
    reason: str,
) -> Alert:
    """In-app alert recording a verification-gated skip (never silent)."""
    alert = Alert(
        organization_id=org_id,
        asset_id=asset_id,
        title=f"Scan skipped for {target}: {reason}",
        severity="medium",
        message=json.dumps({
            "type": "verification_skip",
            "target": target,
            "reason": reason,
        }),
    )
    db.add(alert)
    db.flush()
    return alert


async def check_row(db: Session, row: VerifiedDomain) -> tuple[bool, str]:
    """Run the row's method check and persist the outcome (caller commits)."""
    expected = challenge_value(row.token)
    if row.method == METHOD_DNS_TXT:
        ok, message = await verify_domain_ownership(row.domain, row.token)
    else:
        ok, message = await _check_http_file(row.domain, row.token, expected)

    now = _now()
    row.last_checked_at = now
    if ok:
        row.status = STATUS_VERIFIED
        row.verified_at = now
        row.expires_at = now + timedelta(days=_expiry_days())
    elif row.status == STATUS_VERIFIED:
        row.status = STATUS_EXPIRED
    elif row.status == STATUS_PENDING:
        row.status = STATUS_FAILED
    # Grandfathered rows keep their grace clock on a failed manual check.
    db.flush()
    return ok, message


async def _check_http_file(domain: str, token: str, expected: str) -> tuple[bool, str]:
    """Fetch the verification file through the shared egress helper.

    Single resolution per hop, validated IPs only, manual 3-hop redirects,
    64 KiB cap -- see :mod:`utils.egress`. The token never appears in
    messages or logs. ``EgressBlocked`` reasons already name the cause
    ("blocked address", "Too many redirects"); only the over-cap message
    is normalized to the long-standing verification wording.
    """
    from utils.egress import EgressBlocked, fetch_url_validated

    path = http_file_path(token)
    try:
        result = await fetch_url_validated(
            f"http://{domain}{path}",
            timeout=HTTP_FILE_TIMEOUT_SECONDS,
            max_redirects=HTTP_MAX_REDIRECT_HOPS,
            max_bytes=HTTP_MAX_BODY_BYTES,
        )
    except EgressBlocked as exc:
        if "exceeds" in str(exc):
            return False, "Verification file too large"
        return False, str(exc)
    except Exception:
        logger.warning("HTTP verification fetch failed for %s", domain)
        return False, "Verification fetch failed"
    if result.status_code != 200:
        return False, (
            f"Verification file returned HTTP {result.status_code}"
        )
    if result.body.decode("utf-8", errors="replace").strip() == expected:
        return True, "Domain ownership verified"
    return False, "Verification file content does not match"
