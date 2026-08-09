import os

import pytest

from actions import audit_log
from actions.action_models import ActionResult, ActionSeverity, ActionType, ProposedAction
from actions.approval_service import ApprovalError, decide_pending_action, list_pending_actions
import actions.approval_service as approval_service
from agents.execution_translation_agent import ExecutionTranslationAgent


@pytest.fixture(autouse=True)
def isolated_audit_log():
    original_path = audit_log.AUDIT_LOG_PATH
    audit_log.AUDIT_LOG_PATH = "./data/test_approval_audit_log.jsonl"
    if os.path.exists(audit_log.AUDIT_LOG_PATH):
        os.remove(audit_log.AUDIT_LOG_PATH)
    audit_log._index_built = False
    yield
    if os.path.exists(audit_log.AUDIT_LOG_PATH):
        os.remove(audit_log.AUDIT_LOG_PATH)
    audit_log.AUDIT_LOG_PATH = original_path
    audit_log._index_built = False


def _pending_action() -> ActionResult:
    return ActionResult(
        action=ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="198.51.100.10",
            severity=ActionSeverity.MEDIUM,
            rationale="Confirmed malicious source.",
            technique_id="T1110",
            confidence=0.9,
        ),
        status="pending_approval",
        detail="Awaiting human approval.",
        dry_run=True,
    )


def test_approval_pushes_remotely_once_and_resolves_pending_action(monkeypatch):
    pending = _pending_action()
    audit_log.record(pending, campaign_id="campaign-1")

    monkeypatch.setattr(
        approval_service,
        "execute_approved_action",
        lambda action, campaign_id: {
            "status": "executed_remote",
            "detail": "Remote script completed successfully (execution_id=remote-1).",
            "metadata": {"remote_execution_id": "remote-1", "remote_status": "completed", "remote_exit_code": 0},
        },
    )
    monkeypatch.setattr(approval_service, "notify_approval_outcome", lambda *args, **kwargs: {"sent": True, "status": "simulated"})

    result = decide_pending_action(pending.action_id, "approve", "analyst@example.test", "Verified alert")

    assert result["status"] == "executed_remote"
    assert result["action_id"] == pending.action_id
    assert result["approval"]["reviewer"] == "analyst@example.test"
    assert result["approval"]["decision"] == "approve"
    assert result["approval"]["note"] == "Verified alert"
    assert list_pending_actions() == []
    assert result["approval"]["remote_execution_id"] == "remote-1"
    assert result["approval"]["notification"]["sent"] is True
    assert audit_log.get_latest_action(pending.action_id)["status"] == "executed_remote"

    with pytest.raises(ApprovalError, match="already been decided"):
        decide_pending_action(pending.action_id, "approve", "second@example.test")


def test_denial_is_audited_and_emails_the_analyst(monkeypatch):
    pending = _pending_action()
    audit_log.record(pending, campaign_id="campaign-1")
    sent = []
    monkeypatch.setattr(approval_service, "execute_approved_action", lambda *_: pytest.fail("denied action must not execute"))
    monkeypatch.setattr(approval_service, "notify_approval_outcome", lambda *args, **kwargs: sent.append(args) or {"sent": True, "status": "simulated"})

    result = decide_pending_action(pending.action_id, "deny", "analyst@example.test", "False positive")

    assert result["status"] == "denied"
    assert result["approval"]["decision"] == "deny"
    assert result["approval"]["notification"]["sent"] is True
    assert sent
    assert list_pending_actions() == []


def test_pending_action_requires_a_reviewer():
    pending = _pending_action()
    audit_log.record(pending, campaign_id="campaign-1")

    with pytest.raises(ApprovalError, match="reviewer is required"):
        decide_pending_action(pending.action_id, "approve", "")

    assert audit_log.get_latest_action(pending.action_id)["status"] == "pending_approval"


def test_pending_actions_are_not_translated_into_scripts():
    pending = _pending_action().model_dump()

    result = ExecutionTranslationAgent().run([pending], platform="linux")

    assert result["execution_packages"] == []
