"""Alerting service: dispatches finding alerts to Slack/Discord/email.

Chunk 2 changes:
- ``send_email`` now lives in ``services.alerts.email_service`` (canonical).
- Webhook delivery retries with exponential backoff (1 attempt, 2 retries).
- ``process_finding_alerts`` is called from the scan pipeline (was dead code).
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models import Alert, AlertIntegration, AlertChannel, EmailDigestConfig, AlertSeverity, Finding, Asset
from app.core.crypto import DecryptFailedError, UndecryptableSecret
from services.alerts.email_service import send_email
from utils.egress import EgressBlocked, fetch_url_validated, validate_webhook_url
from utils.logger import logger
from config import settings


SEVERITY_ORDER = {
    AlertSeverity.CRITICAL: 5,
    AlertSeverity.HIGH: 4,
    AlertSeverity.MEDIUM: 3,
    AlertSeverity.LOW: 2,
    AlertSeverity.INFO: 1,
}

# Webhook delivery configuration.
_WEBHOOK_TIMEOUT = 10.0
_WEBHOOK_MAX_RETRIES = 2
_WEBHOOK_BACKOFF_BASE = 1.5  # seconds


def severity_meets_threshold(finding_severity: str, min_severity: AlertSeverity) -> bool:
    try:
        finding_level = SEVERITY_ORDER.get(AlertSeverity(finding_severity.lower()), 0)
    except ValueError:
        return False
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    return finding_level >= min_level


async def _post_with_retry(url: str, payload: dict, auth: tuple[str, str] | None = None) -> bool:
    """POST to *url* with exponential-backoff retry on transient failures.

    The destination is validated (https, no userinfo, allowlisted port,
    all-resolved-IPs routable) before every attempt, delivery goes through
    the shared egress helper with redirects refused, and the response is
    size-capped. Validation failures fail closed immediately (no retry).
    """
    try:
        validate_webhook_url(url)
    except EgressBlocked as exc:
        logger.warning("Webhook %s blocked: %s", url, exc)
        return False

    import asyncio

    body = json.dumps(payload).encode("utf-8")
    last_error = None
    for attempt in range(_WEBHOOK_MAX_RETRIES + 1):
        try:
            result = await fetch_url_validated(
                url, method="POST", content=body, auth=auth,
                headers={"Content-Type": "application/json"},
                timeout=_WEBHOOK_TIMEOUT, max_redirects=0,
            )
            if result.status_code >= 500:
                last_error = f"HTTP {result.status_code}"
                wait = _WEBHOOK_BACKOFF_BASE * (2 ** attempt)
                logger.debug(
                    "Webhook %s returned %s, retrying in %.1fs (attempt %s/%s)",
                    url, result.status_code, wait, attempt + 1, _WEBHOOK_MAX_RETRIES,
                )
                await asyncio.sleep(wait)
            elif result.status_code >= 400:
                logger.warning("Webhook %s returned client error %s", url, result.status_code)
                return False
            else:
                return True
        except EgressBlocked as exc:
            logger.warning("Webhook %s blocked: %s", url, exc)
            return False
        except Exception as exc:
            last_error = exc
            wait = _WEBHOOK_BACKOFF_BASE * (2 ** attempt)
            logger.debug(
                "Webhook %s failed (%s), retrying in %.1fs (attempt %s/%s)",
                url, exc, wait, attempt + 1, _WEBHOOK_MAX_RETRIES,
            )
            await asyncio.sleep(wait)

    logger.warning("Webhook %s delivery failed after %s attempts: %s", url, _WEBHOOK_MAX_RETRIES + 1, last_error)
    return False


async def send_slack_alert(webhook_url: str, finding: Finding, asset: Asset) -> bool:
    # Destination validated inside _post_with_retry (fail-closed, no retry).

    severity_emoji = {
        "critical": "\U0001f534",
        "high": "\U0001f7e0",
        "medium": "\U0001f7e1",
        "low": "\U0001f7e2",
        "info": "\U0001f535",
    }

    emoji = severity_emoji.get(finding.severity.lower(), "\u26aa")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} SentinelASM Alert: {finding.severity.upper()}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Asset:*\n{asset.name}"},
                    {"type": "mrkdwn", "text": f"*Finding:*\n{finding.title}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Category:*\n{finding.category or 'N/A'}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{finding.description or 'N/A'}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommendation:*\n{finding.recommendation or 'N/A'}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"SentinelASM | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    },
                ],
            },
        ],
    }

    return await _post_with_retry(webhook_url, payload)


def assert_https_host_safe(url: str) -> str:
    """Resolve *url*'s hostname and fail closed on blocked targets.

    Kept for backwards compatibility; delegates to
    :func:`utils.egress.validate_webhook_url`, which additionally requires
    https, rejects userinfo/odd ports, and validates *every* resolved IP
    (the old single-``gethostbyname`` check is superseded). Returns the
    validated hostname. Raises ``ValueError`` (via ``EgressBlocked``) on
    any violation.
    """
    host, _port, _path = validate_webhook_url(url)
    return host


def _adf_paragraph(text: str) -> dict:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": (text or "")[:2000]}],
            }
        ],
    }


async def send_jira_alert(integration: AlertIntegration, finding: Finding, asset: Asset) -> bool:
    """Create a Jira issue for *finding* via the Jira Cloud REST API (v3).

    Connection details come from the per-organisation *integration* row
    (base URL, project key, email + API token); the token is only ever used
    as HTTP Basic auth and never logged. Returns True on issue creation.
    """
    base_url = (integration.jira_base_url or "").rstrip("/")
    project_key = (integration.jira_project_key or "").strip().upper()
    email = (integration.jira_email or "").strip()
    raw_token = integration.jira_api_token
    if isinstance(raw_token, UndecryptableSecret):
        # Stored token cannot be decrypted: fail without raising or leaking.
        # The caller records last_error (dispatch loops do this with streak
        # alerts; see _unreadable_credential below).
        return False
    api_token = raw_token or ""
    issue_type = (integration.jira_issue_type or "Task").strip() or "Task"

    if not (base_url and project_key and email and api_token):
        logger.warning("Jira integration %s is missing connection settings", integration.id)
        return False

    try:
        assert_https_host_safe(base_url)
    except ValueError as exc:
        logger.warning("Jira base URL blocked by SSRF guard: %s", exc)
        return False

    severity = (finding.severity or "info").lower()
    summary = f"[SentinelASM:{severity.upper()}] {finding.title} on {asset.name}"
    body = (
        f"Asset: {asset.name}\n"
        f"Finding: {finding.title}\n"
        f"Severity: {severity.upper()}\n"
        f"Category: {finding.category or 'N/A'}\n\n"
        f"Description:\n{finding.description or 'N/A'}\n\n"
        f"Recommendation:\n{finding.recommendation or 'N/A'}"
    )
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:255],
            "description": _adf_paragraph(body),
            "issuetype": {"name": issue_type},
            "labels": ["sentinelasm", f"severity-{severity}"],
        }
    }

    return await _post_with_retry(
        f"{base_url}/rest/api/3/issue", payload, auth=(email, api_token)
    )


async def send_discord_alert(webhook_url: str, finding: Finding, asset: Asset) -> bool:
    # Destination validated inside _post_with_retry (fail-closed, no retry).

    severity_color = {
        "critical": 15548997,
        "high": 16744192,
        "medium": 16776960,
        "low": 5763719,
        "info": 3447003,
    }

    color = severity_color.get(finding.severity.lower(), 8421504)

    embed = {
        "title": f"SentinelASM Alert: {finding.severity.upper()}",
        "description": finding.description or finding.title or "No description",
        "color": color,
        "fields": [
            {"name": "Asset", "value": asset.name, "inline": True},
            {"name": "Severity", "value": finding.severity.upper(), "inline": True},
            {"name": "Category", "value": finding.category or "N/A", "inline": True},
        ],
        "footer": {
            "text": f"SentinelASM | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        },
    }

    payload = {"embeds": [embed]}
    return await _post_with_retry(webhook_url, payload)


def _unreadable_credential(integration: AlertIntegration) -> str | None:
    """Specific message if a needed credential is unreadable, else None.

    Checked before every send so unreadable integrations fail with the
    actionable message (and streak alerts) instead of generic failures.
    """
    if isinstance(integration.webhook_url, UndecryptableSecret):
        return "secret cannot be decrypted: check SECRETS_ENCRYPTION_KEY"
    if integration.channel == AlertChannel.JIRA and isinstance(
        integration.jira_api_token, UndecryptableSecret
    ):
        return "secret cannot be decrypted: check SECRETS_ENCRYPTION_KEY"
    return None


async def process_finding_alerts(db: Session, finding: Finding, asset: Asset) -> None:
    """Dispatch finding to all matching alert integrations for the org.

    Integration IDs are listed first (plain integers, never decrypted) so
    one unreadable row cannot sink the round: each row loads in isolation
    and failures are recorded without touching ORM-decrypted state.
    """
    id_rows = db.query(AlertIntegration.id).filter(
        AlertIntegration.organization_id == asset.organization_id,
        AlertIntegration.is_active == True,
    ).all()

    skipped = 0
    for (integration_id,) in id_rows:
        try:
            integration = db.get(AlertIntegration, integration_id)
        except DecryptFailedError:
            db.rollback()
            _record_unreadable(db, integration_id)
            db.commit()
            skipped += 1
            continue
        if not severity_meets_threshold(finding.severity, integration.min_severity):
            continue

        success = False
        if integration.channel == AlertChannel.SLACK:
            success = await send_slack_alert(integration.webhook_url, finding, asset)
        elif integration.channel == AlertChannel.DISCORD:
            success = await send_discord_alert(integration.webhook_url, finding, asset)
        elif integration.channel == AlertChannel.JIRA:
            success = await send_jira_alert(integration, finding, asset)

        _record_delivery(db, integration, success)
        db.commit()

    if skipped:
        logger.error(
            "Alert dispatch skipped %s integration(s) with unreadable "
            "secrets; check SECRETS_ENCRYPTION_KEY",
            skipped,
        )


def _record_unreadable(db: Session, integration_id: int) -> None:
    """Persist unreadable-credential state without ORM-decrypting the row.

    Reads and writes plain columns only (Core), so it works under a wrong
    key. Alerts once per failure streak like :func:`_record_delivery`.
    """
    from sqlalchemy import select, update

    org_id, name, previous = db.execute(
        select(
            AlertIntegration.organization_id,
            AlertIntegration.name,
            AlertIntegration.last_error,
        ).where(AlertIntegration.id == integration_id)
    ).one()
    message = "secret cannot be decrypted: check SECRETS_ENCRYPTION_KEY"
    if previous is None:
        db.add(Alert(
            organization_id=org_id,
            asset_id=None,
            title=f"Alert delivery failing for integration {name}",
            severity="medium",
            message=json.dumps({
                "type": "integration_delivery_failed",
                "integration_id": integration_id,
            }),
        ))
    db.execute(
        update(AlertIntegration)
        .where(AlertIntegration.id == integration_id)
        .values(last_error=message, last_error_at=datetime.now(timezone.utc))
    )


def _record_delivery(
    db: Session, integration: AlertIntegration, success: bool, detail: str = ""
) -> None:
    """Stamp a delivery outcome; alert once per failure streak.

    Success clears any previous failure. The first failure of a streak
    creates one in-app alert; subsequent failures only refresh the stamp.
    A caller-supplied *detail* (e.g. an undecryptable secret) is preserved
    over the generic message. Commit is left to the caller.
    """
    now = datetime.now(timezone.utc)
    if success:
        integration.last_triggered_at = now
        integration.last_error = None
        integration.last_error_at = None
        return
    if integration.last_error is None:
        db.add(Alert(
            organization_id=integration.organization_id,
            asset_id=None,
            title=f"Alert delivery failing for integration {integration.name}",
            severity="medium",
            message=json.dumps({
                "type": "integration_delivery_failed",
                "integration_id": integration.id,
                "channel": str(integration.channel),
            }),
        ))
    if detail:
        integration.last_error = detail
    elif integration.last_error is None:
        integration.last_error = "delivery failed"
    integration.last_error_at = now


def _change_alert_as_finding(alert) -> Finding:
    """Adapt a change-detection :class:`Alert` to the finding shape.

    Lets change events reuse the exact Slack/Discord block builders without
    duplicating formatting logic. Only attribute access is used downstream.
    """
    return Finding(
        organization_id=alert.organization_id,
        asset_id=alert.asset_id,
        title=alert.title,
        severity=alert.severity or "info",
        category="asset_change",
        description=alert.message or alert.title,
        recommendation=(
            "Review this asset change in the dashboard. If it was unexpected, "
            "investigate the asset for misconfiguration or compromise."
        ),
    )


async def process_change_alerts(db: Session, alerts: list, asset: Asset) -> None:
    """Dispatch change-detection alerts to all matching integrations.

    ``alerts`` are :class:`Alert` rows created by
    :func:`services.history.change_detector.persist_alerts`. Severity
    thresholds, channel routing, and retry behavior are identical to
    :func:`process_finding_alerts`.
    """
    id_rows = db.query(AlertIntegration.id).filter(
        AlertIntegration.organization_id == asset.organization_id,
        AlertIntegration.is_active == True,
    ).all()

    skipped = 0
    for alert in alerts:
        finding_like = _change_alert_as_finding(alert)
        for (integration_id,) in id_rows:
            try:
                integration = db.get(AlertIntegration, integration_id)
            except DecryptFailedError:
                db.rollback()
                _record_unreadable(db, integration_id)
                db.commit()
                skipped += 1
                continue
            if not severity_meets_threshold(finding_like.severity, integration.min_severity):
                continue

            success = False
            if integration.channel == AlertChannel.SLACK:
                success = await send_slack_alert(integration.webhook_url, finding_like, asset)
            elif integration.channel == AlertChannel.DISCORD:
                success = await send_discord_alert(integration.webhook_url, finding_like, asset)
            elif integration.channel == AlertChannel.JIRA:
                success = await send_jira_alert(integration, finding_like, asset)

            _record_delivery(db, integration, success)
            db.commit()

    if skipped:
        logger.error(
            "Alert dispatch skipped %s integration(s) with unreadable "
            "secrets; check SECRETS_ENCRYPTION_KEY",
            skipped,
        )


async def send_email_digest(db: Session, config: EmailDigestConfig) -> bool:
    from models import Finding as FindingModel, Asset as AssetModel

    since = datetime.now(timezone.utc) - timedelta(days=7)

    findings = db.query(FindingModel).join(AssetModel).filter(
        FindingModel.organization_id == config.organization_id,
        FindingModel.created_at >= since,
        FindingModel.severity.in_([s.value for s in AlertSeverity if SEVERITY_ORDER[s] >= SEVERITY_ORDER[config.min_severity]]),
    ).order_by(FindingModel.created_at.desc()).limit(50).all()

    if not findings:
        logger.info("No findings for email digest, skipping")
        return False

    recipients = [e.strip() for e in config.recipient_emails.split(",") if e.strip()]
    if not recipients:
        logger.warning("No recipient emails configured for digest")
        return False

    by_severity = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
        <h2>SentinelASM Weekly Security Digest</h2>
        <p>Period: {(datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')} to {datetime.now(timezone.utc).strftime('%Y-%m-%d')}</p>
        <p>Total findings: {len(findings)}</p>
        <hr>
    """

    for severity in ["critical", "high", "medium", "low", "info"]:
        severity_findings = by_severity.get(severity, [])
        if not severity_findings:
            continue

        color = {
            "critical": "#dc2626", "high": "#ea580c", "medium": "#f59e0b",
            "low": "#10b981", "info": "#6b7280",
        }.get(severity, "#6b7280")

        html += f'<h3 style="color: {color};">{severity.upper()} ({len(severity_findings)})</h3><ul>'

        for f in severity_findings[:10]:
            asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
            desc = (f.description[:200] if f.description else "No description")
            html += f'<li><strong>{f.title}</strong> - {asset.name if asset else "Unknown asset"}<br><small>{desc}</small></li>'

        html += "</ul>"

    frontend_url = settings.frontend_url
    html += f"""
        <hr>
        <p><small>Generated by SentinelASM | <a href="{frontend_url}">View Dashboard</a></small></p>
    </body>
    </html>
    """

    for recipient in recipients:
        sent = send_email(
            recipient,
            f"SentinelASM Weekly Security Digest - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            html,
        )
        if not sent:
            logger.warning("Failed to send digest to %s", recipient)

    config.last_sent_at = datetime.now(timezone.utc)
    return True
