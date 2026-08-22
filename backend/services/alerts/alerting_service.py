import httpx
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models import AlertIntegration, AlertChannel, EmailDigestConfig, AlertSeverity, Finding, Asset, User
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


def severity_meets_threshold(finding_severity: str, min_severity: AlertSeverity) -> bool:
    finding_level = SEVERITY_ORDER.get(AlertSeverity(finding_severity.upper()), 0)
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    return finding_level >= min_level


async def send_slack_alert(webhook_url: str, finding: Finding, asset: Asset) -> bool:
    if not is_allowed_target(webhook_url):
        logger.warning("Slack webhook URL blocked by SSRF guard: %s", webhook_url)
        return False

    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵",
    }

    emoji = severity_emoji.get(finding.severity.lower(), "⚪")

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

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.warning("Failed to send Slack alert: %s", exc)
        return False


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
        "description": finding.title,
        "color": color,
        "fields": [
            {"name": "Asset", "value": asset.name, "inline": True},
            {"name": "Severity", "value": finding.severity.upper(), "inline": True},
            {"name": "Category", "value": finding.category or "N/A", "inline": True},
        ],
        "description": finding.description or "No description",
        "footer": {
            "text": f"SentinelASM | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        },
    }

    payload = {"embeds": [embed]}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.warning("Failed to send Discord alert: %s", exc)
        return False


async def process_finding_alerts(db: Session, finding: Finding, asset: Asset) -> None:
    from models import AlertIntegration, AlertChannel

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

        if success:
            integration.last_triggered_at = datetime.now(timezone.utc)
            db.commit()


async def send_email_digest(db: Session, config: EmailDigestConfig) -> bool:
    from models import Finding, Asset

    since = datetime.now(timezone.utc) - timedelta(days=7)

    findings = db.query(Finding).join(Asset).filter(
        Finding.organization_id == config.organization_id,
        Finding.created_at >= since,
        Finding.severity.in_([s.value for s in AlertSeverity if SEVERITY_ORDER[s] >= SEVERITY_ORDER[config.min_severity]]),
    ).order_by(Finding.created_at.desc()).limit(50).all()

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

        html += f"""
        <h3 style="color: {'#dc2626' if severity == 'critical' else '#ea580c' if severity == 'high' else '#f59e0b' if severity == 'medium' else '#10b981' if severity == 'low' else '#6b7280'};">
            {severity.upper()} ({len(severity_findings)})
        </h3>
        <ul>
        """

        for f in severity_findings[:10]:
            asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
            html += f"""
            <li><strong>{f.title}</strong> - {asset.name if asset else 'Unknown asset'}
                <br><small>{f.description[:200] if f.description else 'No description'}</small>
            </li>
            """

        html += "</ul>"

    html += """
        <hr>
        <p><small>Generated by SentinelASM | <a href="{settings.frontend_url}">View Dashboard</a></small></p>
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


def send_email(receiver: str, subject: str, body: str) -> bool:
    if not settings.smtp_host:
        logger.info("Email service not configured; would send to=%s subject=%s", receiver, subject)
        return False

    from email.message import EmailMessage
    import smtplib

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = receiver
    msg.add_alternative(body, subtype="html")

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("Failed to send email to %s: %s", receiver, exc)
        return False