import smtplib

from email.message import EmailMessage


def send_email(
    receiver,
    subject,
    body
):

    msg = EmailMessage()

    msg["Subject"] = subject

    msg["To"] = receiver

    msg.set_content(body)

    # SMTP Config