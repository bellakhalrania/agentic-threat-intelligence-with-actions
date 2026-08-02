"""
actions/notifier_email.py
SMTP email delivery for notify_analyst actions.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

from config import config


def _validate_email_config() -> tuple[bool, str]:
    if not config.NOTIFY_EMAIL_ENABLED:
        return False, "NOTIFY_EMAIL_ENABLED is false"
    if not config.NOTIFY_EMAIL_SMTP_HOST:
        return False, "NOTIFY_EMAIL_SMTP_HOST is not set"
    if not config.NOTIFY_EMAIL_FROM:
        return False, "NOTIFY_EMAIL_FROM is not set"
    if not config.NOTIFY_EMAIL_TO:
        return False, "NOTIFY_EMAIL_TO is empty"
    return True, ""


def send_notify_analyst_email(target: str, message: str) -> dict[str, Any]:
    """Send an analyst notification email via SMTP.

    Returns:
        dict with fields: sent (bool), detail (str), recipients (list[str]).
    """
    ok, reason = _validate_email_config()
    if not ok:
        return {
            "sent": False,
            "detail": f"Email notification skipped: {reason}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }

    subject = f"{config.NOTIFY_EMAIL_SUBJECT_PREFIX} notify_analyst -> {target}"

    body = (
        "Agentic Threat Intelligence - Analyst Notification\n\n"
        f"Target: {target}\n"
        f"Message: {message}\n"
    )

    email = EmailMessage()
    email["From"] = config.NOTIFY_EMAIL_FROM
    email["To"] = ", ".join(config.NOTIFY_EMAIL_TO)
    email["Subject"] = subject
    email.set_content(body)

    try:
        with smtplib.SMTP(
            config.NOTIFY_EMAIL_SMTP_HOST,
            config.NOTIFY_EMAIL_SMTP_PORT,
            timeout=config.NOTIFY_EMAIL_TIMEOUT,
        ) as smtp:
            if config.NOTIFY_EMAIL_USE_TLS:
                smtp.starttls()
            if config.NOTIFY_EMAIL_SMTP_USER:
                smtp.login(config.NOTIFY_EMAIL_SMTP_USER, config.NOTIFY_EMAIL_SMTP_PASS)
            smtp.send_message(email)

        return {
            "sent": True,
            "detail": f"Email notification sent to {', '.join(config.NOTIFY_EMAIL_TO)}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }
    except Exception as e:
        return {
            "sent": False,
            "detail": f"Email notification failed: {e}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }
