"""
actions/review_pending.py
Human-in-the-loop CLI: lists unresolved pending actions and records an
append-only approve/deny decision with the reviewer's identity.

Usage:
    python -m actions.review_pending
"""

from actions.approval_service import ApprovalError, decide_pending_action, list_pending_actions
from actions.approval_notifications import notify_batch_approval_outcomes


def main():
    pending = list_pending_actions()
    if not pending:
        print("No pending actions.")
        return
    processed: list[dict] = []

    for entry in pending:
        print("\n" + "=" * 60)
        print(f"Action ID:   {entry['action_id']}")
        print(f"Campaign:    {entry['campaign_id']}")
        print(f"Action:      {entry['action_type']} -> {entry['target']}")
        print(f"Severity:    {entry['severity']}  Confidence: {entry['confidence']}")
        print(f"Risk score:  {entry.get('risk_score', 0)}/100")
        print(f"Rationale:   {entry['rationale']}")

        choice = input("Decision [approve/deny/skip]: ").strip().lower()
        if choice not in {"approve", "deny"}:
            print("Skipped.")
            continue
        reviewer = input("Reviewer identity: ").strip()
        note = input("Decision note (optional): ").strip()
        try:
            # Suppress per-action notifications; collect results and send one summary later.
            result = decide_pending_action(entry["action_id"], choice, reviewer, note, send_notification=False)
            print(f"-> {result['status']}: {result['detail']}")
            processed.append({
                "action_id": entry.get("action_id"),
                "action_type": entry.get("action_type"),
                "target": entry.get("target"),
                "severity": entry.get("severity"),
                "confidence": entry.get("confidence"),
                "decision": choice,
                "status": result.get("status"),
                "detail": result.get("detail"),
                **(result.get("approval") or {}),
            })
        except ApprovalError as exc:
            print(f"Could not apply decision: {exc}")
            processed.append({
                "action_id": entry.get("action_id"),
                "action_type": entry.get("action_type"),
                "target": entry.get("target"),
                "severity": entry.get("severity"),
                "confidence": entry.get("confidence"),
                "decision": choice,
                "status": "failed",
                "error": str(exc),
            })

    # After processing all pending actions, send a single summary email if any actions were processed
    if processed:
        summary_result = notify_batch_approval_outcomes(processed)
        if summary_result.get("sent"):
            print(f"Summary notification sent: {summary_result.get('detail')}")
        else:
            print(f"Summary notification failed/suppressed: {summary_result.get('detail')}")


if __name__ == "__main__":
    main()
