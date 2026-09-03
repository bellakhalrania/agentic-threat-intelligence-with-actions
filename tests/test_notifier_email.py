from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from actions.notifier_email import send_action_results_email


def test_action_summary_email_includes_risk_calculation():
    action_results = [
        {
            "action": {
                "action_type": "block_ip",
                "target": "198.51.100.10",
                "severity": "high",
                "rationale": "Repeated failed logins.",
            },
            "status": "executed",
            "detail": "IP blocked.",
        }
    ]
    risk = SimpleNamespace(
        score=81,
        factors=[
            "severity:25",
            "observed_technique_confidence:20",
            "failed_login_repetition:12",
            "successful_authentication_after_failures:20",
            "malicious_ioc:0",
            "campaign_confidence:4",
        ],
        version="1.0",
    )
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp

    with patch("actions.notifier_email._validate_email_config", return_value=(True, "")), \
         patch("actions.notifier_email.smtplib.SMTP", return_value=smtp):
        result = send_action_results_email(action_results, risk)

    message = smtp.send_message.call_args.args[0]
    body = message.get_content()
    assert result["sent"] is True
    assert "Final score: 81/100" in body
    assert "Calculation: 25 + 20 + 12 + 20 + 0 + 4 = 81/100" in body
    assert "Severity: 25 points" in body
    assert "Automatic execution threshold: strictly greater than 80" in body
    assert "Action 1: block_ip" in body