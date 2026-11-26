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


def send_action_result_email(action_result: dict[str, Any]) -> dict[str, Any]:
    """Email the final result of a response action to the SOC team."""
    action = action_result.get("action") or {}
    action_type = action.get("action_type", "unknown")
    target = action.get("target", "unknown")
    status = action_result.get("status", "unknown")
    severity = action.get("severity", "unknown")
    detail = action_result.get("detail", "")
    rationale = action.get("rationale", "")

    subject = f"{config.NOTIFY_EMAIL_SUBJECT_PREFIX} action result: {action_type} -> {target}"
    message = (
        "Agentic Threat Intelligence - Response Action Result\n\n"
        f"Action: {action_type}\n"
        f"Target: {target}\n"
        f"Status: {status}\n"
        f"Severity: {severity}\n"
        f"Detail: {detail}\n"
        f"Rationale: {rationale}\n"
    )

    ok, reason = _validate_email_config()
    if not ok:
        return {
            "sent": False,
            "detail": f"Action result email skipped: {reason}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }

    email = EmailMessage()
    email["From"] = config.NOTIFY_EMAIL_FROM
    email["To"] = ", ".join(config.NOTIFY_EMAIL_TO)
    email["Subject"] = subject
    email.set_content(message)

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
            "detail": f"Action result email sent to {', '.join(config.NOTIFY_EMAIL_TO)}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }
    except Exception as error:
        return {
            "sent": False,
            "detail": f"Action result email failed: {error}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }


def send_action_results_email(
    action_results: list[dict[str, Any]],
    risk_assessment: Any = None,
) -> dict[str, Any]:
    """Send one summary email after all response actions are processed."""
    if not action_results:
        return {"sent": False, "detail": "No action results to report", "recipients": []}

    ok, reason = _validate_email_config()
    if not ok:
        return {
            "sent": False,
            "detail": f"Action results email skipped: {reason}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }

    lines = [
        "Agentic Threat Intelligence - Response Actions Summary",
        "",
        f"Total actions processed: {len(action_results)}",
        "",
    ]
    if risk_assessment is not None:
        risk_factors = getattr(risk_assessment, "factors", [])
        score = getattr(risk_assessment, "score", "unknown")
        version = getattr(risk_assessment, "version", "unknown")
        factor_points = []
        for factor in risk_factors:
            name, _, points = str(factor).partition(":")
            factor_points.append((name, points or "0"))
        formula = " + ".join(points for _, points in factor_points) or "0"
        formula = f"{formula} = {score}/100"
        lines.extend([
            "Risk Assessment",
            f"Final score: {score}/100",
            f"Calculation: {formula}",
            f"Scoring version: {version}",
            "Contributing factors:",
            *[f"- {name.replace('_', ' ').title()}: {points} points" for name, points in factor_points],
            f"Automatic execution threshold: strictly greater than {config.AUTO_RISK_THRESHOLD}",
            "",
        ])
    for index, result in enumerate(action_results, 1):
        action = result.get("action") or {}
        lines.extend([
            f"Action {index}: {action.get('action_type', 'unknown')}",
            f"Target: {action.get('target', 'unknown')}",
            f"Status: {result.get('status', 'unknown')}",
            f"Severity: {action.get('severity', 'unknown')}",
            f"Detail: {result.get('detail', '')}",
            f"Rationale: {action.get('rationale', '')}",
            "",
        ])

    email = EmailMessage()
    email["From"] = config.NOTIFY_EMAIL_FROM
    email["To"] = ", ".join(config.NOTIFY_EMAIL_TO)
    email["Subject"] = f"{config.NOTIFY_EMAIL_SUBJECT_PREFIX} response actions summary"
    email.set_content("\n".join(lines))

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
            "detail": f"Action results email sent to {', '.join(config.NOTIFY_EMAIL_TO)}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }
    except Exception as error:
        return {
            "sent": False,
            "detail": f"Action results email failed: {error}",
            "recipients": list(config.NOTIFY_EMAIL_TO),
        }
