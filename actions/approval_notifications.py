"""Analyst notifications for human response-action decisions and outcomes."""

import json
from typing import Any, Dict

from actions.action_models import ProposedAction
from actions.connectors import notify_analyst


def notify_approval_outcome(
    action: ProposedAction,
    action_id: str,
    campaign_id: str,
    reviewer: str,
    decision: str,
    detail: str,
    remote_metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Send one concise, auditable notification after a reviewer decision."""
    remote_metadata = remote_metadata or {}
    message = "\n".join([
        f"Response action {decision}",
        f"Campaign: {campaign_id or 'unknown'}",
        f"Action ID: {action_id}",
        f"Reviewer: {reviewer}",
        f"Action: {action.action_type} -> {action.target}",
        f"Severity: {action.severity} | Confidence: {action.confidence:.2f}",
        f"Result: {detail}",
        *([f"Remote execution ID: {remote_metadata['remote_execution_id']}"]
          if remote_metadata.get("remote_execution_id") else []),
        *([f"Remote status: {remote_metadata['remote_status']} | Exit code: {remote_metadata.get('remote_exit_code')}"]
          if remote_metadata.get("remote_status") else []),
    ])
    try:
        raw_result = notify_analyst(message)
        parsed = json.loads(raw_result)
        return {
            "sent": parsed.get("status") in {"executed", "simulated"},
            "status": parsed.get("status", "unknown"),
            "detail": parsed.get("detail", raw_result),
        }
    except Exception as exc:
        return {"sent": False, "status": "failed", "detail": str(exc)}
