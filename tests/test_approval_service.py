import os

import pytest

from actions import audit_log
from actions.action_models import ActionResult, ActionSeverity, ActionType, ProposedAction
from actions.approval_service import ApprovalError, decide_pending_action, list_pending_actions
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


def test_approval_executes_once_and_resolves_pending_action(monkeypatch):
    pending = _pending_action()
    audit_log.record(pending, campaign_id="campaign-1")

    monkeypatch.setitem(
        __import__("actions.approval_service", fromlist=["ACTION_DISPATCH"]).ACTION_DISPATCH,
        ActionType.BLOCK_IP,
        lambda target: '{"status":"simulated","detail":"would block ' + target + '"}',
    )

    result = decide_pending_action(pending.action_id, "approve", "analyst@example.test", "Verified alert")

    assert result["status"] == "executed"
    assert result["action_id"] == pending.action_id
    assert result["approval"] == {
        "reviewer": "analyst@example.test",
        "decision": "approve",
        "note": "Verified alert",
    }
    assert list_pending_actions() == []
    assert audit_log.get_latest_action(pending.action_id)["status"] == "executed"

    with pytest.raises(ApprovalError, match="already been decided"):
        decide_pending_action(pending.action_id, "approve", "second@example.test")


def test_denial_is_audited_and_does_not_call_connector(monkeypatch):
    pending = _pending_action()
    audit_log.record(pending, campaign_id="campaign-1")
    monkeypatch.setitem(
        __import__("actions.approval_service", fromlist=["ACTION_DISPATCH"]).ACTION_DISPATCH,
        ActionType.BLOCK_IP,
        lambda _: pytest.fail("denied action must not execute"),
    )

    result = decide_pending_action(pending.action_id, "deny", "analyst@example.test", "False positive")

    assert result["status"] == "denied"
    assert result["approval"]["decision"] == "deny"
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
