"""Deterministic human approval lifecycle for pending response actions."""

from threading import Lock
from typing import Any, Dict, List

from actions import audit_log, policy
from actions.action_models import ActionResult, ActionSeverity, ActionType, ProposedAction
from actions.approval_execution_service import execute_approved_action
from actions.approval_notifications import notify_approval_outcome
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
    send_notification: bool = True,
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
            detail = f"Denied by reviewer {reviewer}."
            notification = None
            if send_notification:
                notification = notify_approval_outcome(
                    action, action_id, campaign_id, reviewer, "denied", detail
                )
            metadata["notification"] = notification or {"sent": False, "status": "suppressed", "detail": "notification suppressed"}
            result = ActionResult(
                action_id=action_id,
                action=action,
                status="denied",
                detail=detail,
                dry_run=config.DRY_RUN,
            )
            return audit_log.record(result, campaign_id=campaign_id, metadata=metadata)

        # Defense in depth: policy-denied targets cannot be resurrected through a
        # crafted or stale pending record. Other pending policy outcomes are the
        # explicit purpose of this human review step and may be approved.
        if action.target in policy.PROTECTED_TARGETS:
            detail = "Target is protected and cannot be approved."
            result = ActionResult(
                action_id=action_id,
                action=action,
                status="denied",
                detail=detail,
                dry_run=config.DRY_RUN,
            )
            metadata["decision"] = "denied_protected_target"
            if send_notification:
                metadata["notification"] = notify_approval_outcome(
                    action, action_id, campaign_id, reviewer, "denied", detail
                )
            else:
                metadata["notification"] = {"sent": False, "status": "suppressed", "detail": "notification suppressed"}
            return audit_log.record(result, campaign_id=campaign_id, metadata=metadata)

        approval_result = ActionResult(
            action_id=action_id,
            action=action,
            status="approved",
            detail=f"Approved by reviewer {reviewer}; executing action.",
            dry_run=config.DRY_RUN,
        )
        audit_log.record(approval_result, campaign_id=campaign_id, metadata=metadata)

        execution = execute_approved_action(action, campaign_id)
        notification = None
        if send_notification:
            notification = notify_approval_outcome(
                action=action,
                action_id=action_id,
                campaign_id=campaign_id,
                reviewer=reviewer,
                decision=execution["status"],
                detail=execution["detail"],
                remote_metadata=execution.get("metadata", {}),
            )
        metadata.update(execution.get("metadata", {}))
        metadata["notification"] = notification or {"sent": False, "status": "suppressed", "detail": "notification suppressed"}
        result = ActionResult(
            action_id=action_id,
            action=action,
            status=execution["status"],
            detail=execution["detail"],
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
