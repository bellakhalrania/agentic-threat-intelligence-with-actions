"""
actions/test_email.py
Quick SMTP smoke test for notify_analyst email delivery.

Usage:
  python -m actions.test_email
  python -m actions.test_email --target "SOC Team" --message "Test alert"
"""

from __future__ import annotations

import argparse
import json
import sys

from actions.notifier_email import send_notify_analyst_email


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a notify_analyst SMTP test email")
    parser.add_argument("--target", default="SOC Team", help="Logical notification target label")
    parser.add_argument(
        "--message",
        default="SMTP test from Agentic Threat Intelligence notify_analyst",
        help="Message body to include in the email",
    )
    args = parser.parse_args()

    result = send_notify_analyst_email(target=args.target, message=args.message)

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if result.get("sent"):
        print("\n✅ Test email sent successfully.")
        return 0

    print("\n❌ Test email failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
