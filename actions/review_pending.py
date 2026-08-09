"""
actions/review_pending.py
Human-in-the-loop CLI: lists unresolved pending actions and records an
append-only approve/deny decision with the reviewer's identity.

Usage:
    python -m actions.review_pending
"""

from actions.approval_service import ApprovalError, decide_pending_action, list_pending_actions


def main():
    pending = list_pending_actions()
    if not pending:
        print("No pending actions.")
        return

    for entry in pending:
        print("\n" + "=" * 60)
        print(f"Action ID:   {entry['action_id']}")
        print(f"Campaign:    {entry['campaign_id']}")
        print(f"Action:      {entry['action_type']} -> {entry['target']}")
        print(f"Severity:    {entry['severity']}  Confidence: {entry['confidence']}")
        print(f"Rationale:   {entry['rationale']}")

        choice = input("Decision [approve/deny/skip]: ").strip().lower()
        if choice not in {"approve", "deny"}:
            print("Skipped.")
            continue
        reviewer = input("Reviewer identity: ").strip()
        note = input("Decision note (optional): ").strip()
        try:
            result = decide_pending_action(entry["action_id"], choice, reviewer, note)
            print(f"-> {result['status']}: {result['detail']}")
        except ApprovalError as exc:
            print(f"Could not apply decision: {exc}")


if __name__ == "__main__":
    main()
