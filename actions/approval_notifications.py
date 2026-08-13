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


def notify_batch_approval_outcomes(processed_actions: list[Dict[str, Any]], run_id: str | None = None) -> Dict[str, Any]:
    """Send a single summary email for a list of processed actions.

    `processed_actions` should be a list of dicts with at least these keys:
    - action_id, action_type, target, severity, confidence, decision, status, detail
    Optional keys: execution_id, verification_status, error
    """
    if not processed_actions:
        return {"sent": False, "status": "no_actions", "detail": "No actions to report"}

    lines: list[str] = [
        "Agentic Threat Intelligence - Review Pending Summary",
        f"Run ID: {run_id or 'manual'}",
        "",
        f"Total actions processed: {len(processed_actions)}",
        "",
        "Details:",
    ]

    for pa in processed_actions:
        lines.append("-" * 40)
        lines.append(f"Action ID: {pa.get('action_id')}")
        lines.append(f"Action: {pa.get('action_type')} -> {pa.get('target')}")
        lines.append(f"Severity: {pa.get('severity')} | Confidence: {pa.get('confidence')}")
        lines.append(f"Decision: {pa.get('decision')}")
        lines.append(f"Execution status: {pa.get('status')}")
        if pa.get('execution_id'):
            lines.append(f"Execution ID: {pa.get('execution_id')}")
        if pa.get('verification_status'):
            lines.append(f"Verification: {pa.get('verification_status')}")
        if pa.get('error'):
            lines.append(f"Error: {pa.get('error')}")
        if pa.get('detail'):
            lines.append(f"Detail: {pa.get('detail')}")
        lines.append("")

    message = "\n".join(lines)
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
