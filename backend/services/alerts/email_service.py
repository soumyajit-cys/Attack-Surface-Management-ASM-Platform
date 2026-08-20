import smtplib

from email.message import EmailMessage

from config import settings
from utils.logger import logger


def send_email(
    receiver: str,
    subject: str,
    body: str,
) -> bool:
    if not settings.smtp_host:
        logger.info(
            "Email service not configured; would send to=%s subject=%s",
            receiver,
            subject,
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = receiver
    msg.set_content(body)

    try:
        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=15,
        ) as server:
            server.starttls()
            if settings.smtp_user:
                server.login(
                    settings.smtp_user,
                    settings.smtp_password,
                )
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("Failed to send email to %s: %s", receiver, exc)
        return False