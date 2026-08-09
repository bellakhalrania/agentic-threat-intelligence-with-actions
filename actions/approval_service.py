"""Deterministic human approval lifecycle for pending response actions."""

import json
from threading import Lock
from typing import Any, Dict, List

from actions import audit_log, policy
from actions.action_models import ActionResult, ActionSeverity, ActionType, ProposedAction
from actions.connectors import ACTION_DISPATCH
from config import config


class ApprovalError(ValueError):
    """Raised when an approval decision cannot be safely applied."""


_DECISION_LOCK = Lock()


def list_pending_actions() -> List[Dict[str, Any]]:
    """Return unresolved, identifiable actions awaiting an analyst decision."""
    return [entry for entry in audit_log.read_pending_approvals() if entry.get("action_id")]


def decide_pending_action(
    action_id: str,
    decision: str,
    reviewer: str,
    note: str = "",
) -> Dict[str, Any]:
    """Approve-and-execute or deny one pending action exactly once.

    Decisions append lifecycle events to the audit log rather than mutating the
    original proposal. A decision is accepted only while the latest event for
    ``action_id`` remains ``pending_approval``.
    """
    # Serialize the read-check-write lifecycle inside this service process so
    # two concurrent API requests cannot both approve the same action.
    with _DECISION_LOCK:
        decision = decision.strip().lower()
        reviewer = reviewer.strip()
        if decision not in {"approve", "deny"}:
            raise ApprovalError("decision must be 'approve' or 'deny'")
        if not reviewer:
            raise ApprovalError("reviewer is required")

        pending = audit_log.get_latest_action(action_id)
        if pending is None:
            raise ApprovalError("pending action was not found")
        if pending.get("status") != "pending_approval":
            raise ApprovalError(f"action has already been decided (status: {pending.get('status')})")

        action = _to_proposed_action(pending)
        campaign_id = pending.get("campaign_id", "")
        metadata = {"reviewer": reviewer, "decision": decision, "note": note.strip()}

        if decision == "deny":
            result = ActionResult(
                action_id=action_id,
                action=action,
                status="denied",
                detail=f"Denied by reviewer {reviewer}.",
                dry_run=config.DRY_RUN,
            )
            return audit_log.record(result, campaign_id=campaign_id, metadata=metadata)

        # Defense in depth: policy-denied targets cannot be resurrected through a
        # crafted or stale pending record. Other pending policy outcomes are the
        # explicit purpose of this human review step and may be approved.
        if action.target in policy.PROTECTED_TARGETS:
            result = ActionResult(
                action_id=action_id,
                action=action,
                status="denied",
                detail="Target is protected and cannot be approved.",
                dry_run=config.DRY_RUN,
            )
            metadata["decision"] = "denied_protected_target"
            return audit_log.record(result, campaign_id=campaign_id, metadata=metadata)

        approval_result = ActionResult(
            action_id=action_id,
            action=action,
            status="approved",
            detail=f"Approved by reviewer {reviewer}; executing action.",
            dry_run=config.DRY_RUN,
        )
        audit_log.record(approval_result, campaign_id=campaign_id, metadata=metadata)

        try:
            raw_output = _dispatch(action)
            detail, failed = _connector_detail(raw_output)
            result = ActionResult(
                action_id=action_id,
                action=action,
                status="failed" if failed else "executed",
                detail=detail,
                dry_run=config.DRY_RUN,
            )
        except Exception as exc:
            result = ActionResult(
                action_id=action_id,
                action=action,
                status="failed",
                detail=str(exc),
                dry_run=config.DRY_RUN,
            )
        return audit_log.record(result, campaign_id=campaign_id, metadata=metadata)


def _to_proposed_action(entry: Dict[str, Any]) -> ProposedAction:
    try:
        return ProposedAction(
            action_type=ActionType(entry["action_type"]),
            target=entry["target"],
            severity=ActionSeverity(entry["severity"]),
            rationale=entry["rationale"],
            technique_id=entry.get("technique_id"),
            confidence=entry.get("confidence", 0.0),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ApprovalError(f"stored action is invalid: {exc}") from exc


def _dispatch(action: ProposedAction) -> str:
    handler = ACTION_DISPATCH.get(action.action_type)
    if handler is None:
        raise ApprovalError("no connector is registered for this action")
    if action.action_type == ActionType.NOTIFY_ANALYST:
        return handler(
            f"Notify target: {action.target} | Technique: {action.technique_id or 'N/A'} | "
            f"Confidence: {action.confidence:.2f} | Rationale: {action.rationale}"
        )
    return handler(action.target)


def _connector_detail(raw_output: str) -> tuple[str, bool]:
    try:
        parsed = json.loads(raw_output)
    except (TypeError, json.JSONDecodeError):
        return str(raw_output), False
    return parsed.get("detail", raw_output), parsed.get("status") == "failed"
