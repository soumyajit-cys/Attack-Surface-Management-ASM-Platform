"""Alerting service: dispatches finding alerts to Slack/Discord/email.

Chunk 2 changes:
- ``send_email`` now lives in ``services.alerts.email_service`` (canonical).
- Webhook delivery retries with exponential backoff (1 attempt, 2 retries).
- ``process_finding_alerts`` is called from the scan pipeline (was dead code).
"""

import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

import socket

from sqlalchemy.orm import Session

from models import AlertIntegration, AlertChannel, EmailDigestConfig, AlertSeverity, Finding, Asset
from services.alerts.email_service import send_email
from utils.ssrf_guard import is_allowed_target
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
    """POST to *url* with exponential-backoff retry on transient failures."""
    last_error = None
    for attempt in range(_WEBHOOK_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT) as client:
                resp = await client.post(url, json=payload, auth=auth)
                resp.raise_for_status()
                return True
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code >= 500:
                last_error = exc
                wait = _WEBHOOK_BACKOFF_BASE * (2 ** attempt)
                logger.debug(
                    "Webhook %s returned %s, retrying in %.1fs (attempt %s/%s)",
                    url, exc.response.status_code, wait, attempt + 1, _WEBHOOK_MAX_RETRIES,
                )
                import asyncio
                await asyncio.sleep(wait)
            else:
                logger.warning("Webhook %s returned client error %s", url, exc.response.status_code)
                return False
        except Exception as exc:
            last_error = exc
            wait = _WEBHOOK_BACKOFF_BASE * (2 ** attempt)
            logger.debug(
                "Webhook %s failed (%s), retrying in %.1fs (attempt %s/%s)",
                url, exc, wait, attempt + 1, _WEBHOOK_MAX_RETRIES,
            )
            import asyncio
            await asyncio.sleep(wait)

    logger.warning("Webhook %s delivery failed after %s attempts: %s", url, _WEBHOOK_MAX_RETRIES + 1, last_error)
    return False


async def send_slack_alert(webhook_url: str, finding: Finding, asset: Asset) -> bool:
    if not is_allowed_target(webhook_url):
        logger.warning("Slack webhook URL blocked by SSRF guard: %s", webhook_url)
        return False

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

    Complements :func:`utils.ssrf_guard.is_allowed_target` (which only
    inspects literal IPs): the hostname is resolved and the resulting IP is
    checked, so DNS pointing a connector at a private/cloud-metadata address
    refuses delivery. Returns the resolved IP. Raises ``ValueError`` for
    non-HTTPS URLs, unresolvable hosts, or blocked IPs.
    """
    parsed = urlparse(url or "")
    if parsed.scheme != "https":
        raise ValueError(f"Connector URL must use https: {url!r}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"Connector URL has no hostname: {url!r}")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Connector host {host!r} does not resolve: {exc}") from exc
    if not is_allowed_target(ip):
        raise ValueError(f"Connector host {host!r} resolved to blocked IP {ip!r}")
    return ip


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
    api_token = integration.jira_api_token or ""
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
    if not is_allowed_target(webhook_url):
        logger.warning("Discord webhook URL blocked by SSRF guard: %s", webhook_url)
        return False

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


async def process_finding_alerts(db: Session, finding: Finding, asset: Asset) -> None:
    """Dispatch finding to all matching alert integrations for the org."""
    integrations = db.query(AlertIntegration).filter(
        AlertIntegration.organization_id == asset.organization_id,
        AlertIntegration.is_active == True,
    ).all()

    for integration in integrations:
        if not severity_meets_threshold(finding.severity, integration.min_severity):
            continue

        success = False
        if integration.channel == AlertChannel.SLACK:
            success = await send_slack_alert(integration.webhook_url, finding, asset)
        elif integration.channel == AlertChannel.DISCORD:
            success = await send_discord_alert(integration.webhook_url, finding, asset)
        elif integration.channel == AlertChannel.JIRA:
            success = await send_jira_alert(integration, finding, asset)

        if success:
            integration.last_triggered_at = datetime.now(timezone.utc)
            db.commit()


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
    integrations = db.query(AlertIntegration).filter(
        AlertIntegration.organization_id == asset.organization_id,
        AlertIntegration.is_active == True,
    ).all()

    for alert in alerts:
        finding_like = _change_alert_as_finding(alert)
        for integration in integrations:
            if not severity_meets_threshold(finding_like.severity, integration.min_severity):
                continue

            success = False
            if integration.channel == AlertChannel.SLACK:
                success = await send_slack_alert(integration.webhook_url, finding_like, asset)
            elif integration.channel == AlertChannel.DISCORD:
                success = await send_discord_alert(integration.webhook_url, finding_like, asset)
            elif integration.channel == AlertChannel.JIRA:
                success = await send_jira_alert(integration, finding_like, asset)

            if success:
                integration.last_triggered_at = datetime.now(timezone.utc)
                db.commit()


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
