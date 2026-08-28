"""Celery Beat tasks.

Two scheduled workloads:
1. ``process_due_scan_policies`` -- finds active scan policies whose
   ``next_run_at`` has passed (or that have never run) and dispatches a scan.
2. ``send_due_email_digests`` -- sends scheduled digest emails for
   ``EmailDigestConfig`` rows that are due.

Both are idempotent: they stamp ``last_run_at`` / ``last_sent_at`` so a missed
beat tick simply catches up on the next one.  Cron expressions (custom scan
policy schedules, digest emails) are evaluated with ``croniter``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from models import (
    Alert,
    Asset,
    EmailDigestConfig,
    Finding,
    Organization,
    ScanFrequency,
    ScanPolicy,
)
from models.scan_history import ScanHistory
from services.alerts.email_service import send_email
from utils.database import SessionLocal
from utils.logger import logger
from workers.celery_app import celery

DEFAULT_SCHEDULE_HOUR_UTC = 9

_ONE_DAY = timedelta(days=1)


# ── Next-run computation ───────────────────────────────────────────────────────

def compute_next_run(
    frequency: ScanFrequency | str,
    cron_expression: str | None,
    from_dt: datetime,
    hour_utc: int = DEFAULT_SCHEDULE_HOUR_UTC,
) -> datetime:
    """Return the next run time after *from_dt* for a policy.

    Non-cron frequencies are calendar-aligned helpers:
    - ``daily``   → tomorrow at *hour_utc*
    - ``weekly``  → next Monday at *hour_utc*
    - ``monthly`` → first day of next month at *hour_utc*
    - ``custom_cron`` → evaluated with ``croniter`` (falls back to daily)
    """
    freq = ScanFrequency(frequency) if isinstance(frequency, str) else frequency
    from_dt = from_dt.replace(second=0, microsecond=0)

    if freq == ScanFrequency.DAILY:
        nxt = from_dt.replace(hour=hour_utc) + _ONE_DAY
        return nxt

    if freq == ScanFrequency.WEEKLY:
        nxt = from_dt.replace(hour=hour_utc)
        while nxt.weekday() != 0:  # Monday
            nxt += _ONE_DAY
        if nxt <= from_dt:
            nxt += 7 * _ONE_DAY
        return nxt

    if freq == ScanFrequency.MONTHLY:
        first = from_dt.replace(day=1, hour=hour_utc)
        return _add_months(first, 1)

    if freq == ScanFrequency.CUSTOM_CRON:
        return _croniter_next(cron_expression, from_dt, hour_utc)

    raise ValueError(f"Unsupported frequency: {freq}")


_ONE_DAY = __import__("datetime").timedelta(days=1)


def _add_months(dt: datetime, months: int) -> datetime:
    year = dt.year + (dt.month - 1 + months) // 12
    month = (dt.month - 1 + months) % 12 + 1
    return dt.replace(year=year, month=month)


def _croniter_next(
    cron_expression: str | None,
    from_dt: datetime,
    hour_utc: int = DEFAULT_SCHEDULE_HOUR_UTC,
) -> datetime:
    if cron_expression:
        try:
            from croniter import croniter
            return croniter(cron_expression, from_dt).get_next(datetime)
        except (ValueError, KeyError) as exc:
            logger.warning("Invalid cron expression %r: %s", cron_expression, exc)
    return (from_dt.replace(hour=hour_utc) + _ONE_DAY)


# ── Scan-policy scheduler ─────────────────────────────────────────────────────

@celery.task(name="tasks.scheduler.process_due_scan_policies")
def process_due_scan_policies() -> dict:
    """Dispatch scans for all due, active scan policies."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    dispatched = 0
    failed = 0

    try:
        policies = (
            db.query(ScanPolicy)
            .filter(ScanPolicy.is_active.is_(True))
            .all()
        )

        for policy in policies:
            due = policy.next_run_at is None or policy.next_run_at <= now
            if not due:
                continue

            asset = db.get(Asset, policy.asset_id)
            target = asset.name if asset else None
            if not asset or not target:
                logger.warning(
                    "Scan policy %s references missing asset %s",
                    policy.id, policy.asset_id,
                )
                continue

            scan = ScanHistory(
                organization_id=policy.organization_id,
                asset_id=asset.id,
                target=target,
                status="pending",
            )
            db.add(scan)
            db.flush()

            try:
                from tasks.discovery_tasks import run_discovery
                run_discovery.delay(scan_id=scan.id)
            except Exception as exc:
                logger.warning(
                    "Failed to dispatch scan for policy %s: %s",
                    policy.id, exc,
                )
                failed += 1
                continue

            policy.last_run_at = now
            policy.next_run_at = compute_next_run(
                policy.frequency,
                policy.cron_expression,
                now,
            )
            dispatched += 1

        db.commit()
    finally:
        db.close()

    logger.info(
        "process_due_scan_policies: dispatched=%s failed=%s",
        dispatched, failed,
    )
    return {"dispatched": dispatched, "failed": failed}


# ── Email digest scheduler ────────────────────────────────────────────────────

@celery.task(name="tasks.scheduler.send_due_email_digests")
def send_due_email_digests() -> dict:
    """Send scheduled email digests that are due."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    sent = 0
    skipped = 0

    try:
        configs = (
            db.query(EmailDigestConfig)
            .filter(EmailDigestConfig.is_active.is_(True))
            .all()
        )

        for cfg in configs:
            if not _digest_due(cfg, now):
                skipped += 1
                continue

            org = db.get(Organization, cfg.organization_id)
            if org is None:
                continue

            body = _build_digest_body(db, cfg, now)
            for recipient in _recipients(cfg.recipient_emails):
                send_email(
                    recipient,
                    _digest_subject(cfg, org.name),
                    body,
                )

            cfg.last_sent_at = now
            sent += 1

        db.commit()
    finally:
        db.close()

    logger.info("send_due_email_digests: sent=%s skipped=%s", sent, skipped)
    return {"sent": sent, "skipped": skipped}


def _digest_due(cfg: EmailDigestConfig, now: datetime) -> bool:
    """True if a digest should be sent *now* for *cfg*."""
    freq = (cfg.frequency or "weekly").lower()

    if freq == "daily":
        window = now.replace(hour=cfg.hour_utc or DEFAULT_SCHEDULE_HOUR_UTC, minute=0, second=0, microsecond=0)
        return not cfg.last_sent_at or cfg.last_sent_at < window <= now

    if freq == "weekly":
        if now.weekday() != (cfg.day_of_week or 1):
            return False
        window = now.replace(hour=cfg.hour_utc or DEFAULT_SCHEDULE_HOUR_UTC, minute=0, second=0, microsecond=0)
        return not cfg.last_sent_at or cfg.last_sent_at < window <= now

    if freq == "monthly":
        if now.day != 1:
            return False
        window = now.replace(hour=cfg.hour_utc or DEFAULT_SCHEDULE_HOUR_UTC, minute=0, second=0, microsecond=0)
        return not cfg.last_sent_at or cfg.last_sent_at < window <= now

    logger.warning("Unknown digest frequency %r", freq)
    return False


def _recipients(raw: str) -> list[str]:
    return [r.strip() for r in (raw or "").split(",") if r.strip()]


def _digest_subject(cfg: EmailDigestConfig, org_name: str) -> str:
    return f"[SentinelASM] {org_name} -- weekly security digest"


def _build_digest_body(
    db: Session,
    cfg: EmailDigestConfig,
    now: datetime,
) -> str:
    org_id = cfg.organization_id
    min_severity = (cfg.min_severity or "medium").lower()

    since = cfg.last_sent_at
    # Daily digests summarize the previous day; others use the last send time.
    window_start = since if since else now.replace(day=max(now.day - 7, 1), hour=0, minute=0, second=0, microsecond=0)

    assets = db.query(Asset).filter(Asset.organization_id == org_id).count()

    findings = (
        db.query(Finding)
        .filter(
            Finding.organization_id == org_id,
        )
        .all()
    )

    total = 0
    recent = 0
    by_severity: dict[str, int] = {}
    for f in findings:
        total += 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        if f.created_at and f.created_at >= window_start:
            recent += 1

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_lines = []
    for sev in sev_order:
        sev_lines.append(f"  - {sev.upper()}: {by_severity.get(sev, 0)}")

    alerts_open = (
        db.query(Alert)
        .filter(Alert.organization_id == org_id)
        .filter(Alert.status.in_(["open", "acknowledged"]))
        .count()
    )

    return (
        f"Security digest for period ending {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"\n"
        f"Assets monitored: {assets}\n"
        f"Total findings: {total}\n"
        f"Findings since last digest: {recent}\n"
        f"Open/acknowledged alerts: {alerts_open}\n"
        f"\n"
        f"Findings by severity:\n"
        f"{chr(10).join(sev_lines)}\n"
        f"\n"
        f"Minimum severity in this digest: {min_severity}\n"
    )


# Beat schedule (declared here so celery_app can import it without work).
BEAT_SCHEDULE = {
    "process-due-scan-policies": {
        "task": "tasks.scheduler.process_due_scan_policies",
        "schedule": 60.0,  # every minute
    },
    "send-due-email-digests": {
        "task": "tasks.scheduler.send_due_email_digests",
        "schedule": 3600.0,  # hourly
    },
}