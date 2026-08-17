import os

import pytest

from actions import audit_log
from actions.action_models import ActionResult, ActionSeverity, ActionType, ProposedAction
from actions.approval_service import ApprovalError, decide_pending_action, list_pending_actions
import actions.approval_service as approval_service
import actions.approval_execution_service as approval_execution_service
from agents.execution_translation_agent import ExecutionTranslationAgent
from config import config


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


def test_block_ip_translation_rejects_management_source_and_keeps_rules_targeted(monkeypatch):
    monkeypatch.setattr(config, "REMOTE_MANAGER_IP", "203.0.113.10")
    monkeypatch.setattr(config, "REMOTE_AGENT_PORT", 9001)

    action = _pending_action().model_dump()
    action["action"]["target"] = "203.0.113.10"

    result = ExecutionTranslationAgent().run([
        {"action": action["action"], "status": "executed"}
    ], platform="linux")

    script = result["combined_script"]
    assert "management_source_ip" in script
    assert "target_ip" in script
    assert "iptables -P INPUT DROP" not in script
    assert "iptables -P OUTPUT DROP" not in script
    assert "REJECTED" in script


def test_execute_approved_action_rejects_protected_management_ip(monkeypatch):
    monkeypatch.setattr(config, "REMOTE_AGENT_ENABLED", True)
    monkeypatch.setattr(config, "REMOTE_AGENT_URL", "http://example.test")
    monkeypatch.setattr(config, "REMOTE_AGENT_API_KEY", "key")
    monkeypatch.setattr(config, "REMOTE_AGENT_HMAC_SECRET", "secret")
    monkeypatch.setattr(config, "REMOTE_AGENT_TIMEOUT", 60)
    monkeypatch.setattr(config, "APPROVAL_REMOTE_PLATFORM", "linux")
    monkeypatch.setattr(config, "REMOTE_MANAGER_IP", "203.0.113.10")
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)

    action = ProposedAction(
        action_type=ActionType.BLOCK_IP,
        target="203.0.113.10",
        severity=ActionSeverity.MEDIUM,
        rationale="test",
        technique_id="T1110",
        confidence=0.9,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("remote execution should not be attempted")

    monkeypatch.setattr(approval_execution_service, "ExecutionTranslationAgent", lambda: type("Dummy", (), {"run": fail_if_called})())
    monkeypatch.setattr(approval_execution_service, "verify_remote_connection", fail_if_called)
    monkeypatch.setattr(approval_execution_service, "push_script_to_remote", fail_if_called)

    result = approval_execution_service.execute_approved_action(action, campaign_id="campaign-1")

    assert result["status"] == "denied"
    assert result["metadata"]["protected_target"] is True
    assert result["detail"].startswith("Rejected:")


def test_execute_approved_action_allows_non_protected_ip(monkeypatch):
    monkeypatch.setattr(config, "REMOTE_AGENT_ENABLED", True)
    monkeypatch.setattr(config, "REMOTE_AGENT_URL", "http://example.test")
    monkeypatch.setattr(config, "REMOTE_AGENT_API_KEY", "key")
    monkeypatch.setattr(config, "REMOTE_AGENT_HMAC_SECRET", "secret")
    monkeypatch.setattr(config, "REMOTE_AGENT_TIMEOUT", 60)
    monkeypatch.setattr(config, "APPROVAL_REMOTE_PLATFORM", "linux")
    monkeypatch.setattr(config, "REMOTE_MANAGER_IP", "203.0.113.10")
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)

    action = ProposedAction(
        action_type=ActionType.BLOCK_IP,
        target="198.51.100.20",
        severity=ActionSeverity.MEDIUM,
        rationale="test",
        technique_id="T1110",
        confidence=0.9,
    )

    monkeypatch.setattr(
        approval_execution_service,
        "ExecutionTranslationAgent",
        lambda: type("Dummy", (), {
            "run": lambda *args, **kwargs: {
                "execution_packages": [{"action_type": "block_ip"}],
                "combined_script": "#!/bin/bash\necho ok",
                "combined_filename": "response.sh",
            }
        })(),
    )
    monkeypatch.setattr(approval_execution_service, "verify_remote_connection", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        approval_execution_service,
        "push_script_to_remote",
        lambda *args, **kwargs: {
            "success": True,
            "status": "completed",
            "exit_code": 0,
            "execution_id": "exec-123",
            "stdout": "",
            "stderr": "",
        },
    )

    result = approval_execution_service.execute_approved_action(action, campaign_id="campaign-1")

    assert result["status"] == "executed_remote"
    assert result["metadata"]["remote_execution_id"] == "exec-123"
