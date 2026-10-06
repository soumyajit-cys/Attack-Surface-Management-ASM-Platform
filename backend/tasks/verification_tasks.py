"""Beat task: re-check verified domains, expiring failures early.

Time-based expiry is enforced at scan time, but this task also flips rows
whose ``expires_at`` has passed to ``expired`` so UI/API state stays truthful,
and re-runs the live ownership check for ``verified`` rows: a domain that no
longer proves ownership (sold, record removed) is marked ``expired``
immediately instead of remaining trusted until ``expires_at``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from models.verified_domain import VerifiedDomain
from services.verification.verification_service import (
    STATUS_EXPIRED,
    STATUS_GRANDFATHERED,
    STATUS_VERIFIED,
    check_row,
)
from utils.database import SessionLocal
from utils.logger import logger
from workers.celery_app import celery


@celery.task(name="tasks.verification.recheck_verified_domains")
def recheck_verified_domains() -> dict:
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    rechecked = 0
    expired = 0
    time_expired = 0

    try:
        stale = (
            db.query(VerifiedDomain)
            .filter(
                VerifiedDomain.status.in_([STATUS_VERIFIED, STATUS_GRANDFATHERED]),
                VerifiedDomain.expires_at.is_not(None),
                VerifiedDomain.expires_at <= now,
            )
            .all()
        )
        for row in stale:
            row.status = STATUS_EXPIRED
            time_expired += 1

        live = (
            db.query(VerifiedDomain)
            .filter(VerifiedDomain.status == STATUS_VERIFIED)
            .all()
        )
        for row in live:
            # Skip rows just expired above (status already flipped in-session).
            if row.status != STATUS_VERIFIED:
                continue
            try:
                ok, _ = asyncio.run(check_row(db, row))
                rechecked += 1
                if not ok:
                    expired += 1
            except Exception as exc:
                logger.warning(
                    "Verification recheck failed for %s: %s", row.domain, exc
                )

        db.commit()
    finally:
        db.close()

    logger.info(
        "recheck_verified_domains: rechecked=%s expired=%s time_expired=%s",
        rechecked, expired, time_expired,
    )
    return {"rechecked": rechecked, "expired": expired, "time_expired": time_expired}
