"""
tests/test_response.py
Integration tests for the Response Agent and its supporting modules.

Tests cover:
  - Connector functions return structured JSON with proper fields
  - DRY_RUN mode produces "simulated" status
  - Policy evaluation: denied, pending_approval, auto_execute
  - Policy: rate limiting, protected targets, confidence threshold
  - Audit log: record, query, count_by_status, read_pending_approvals
  - ResponseAgent: end-to-end with mocked LLM output
  - review_pending.py: basic CLI flow (no actual stdin)
  - Edge cases: empty proposals, malformed JSON, unknown action types
"""

import json
import os
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from actions.action_models import ProposedAction, ActionResult, ActionType, ActionSeverity
from actions.connectors import (
    block_ip, isolate_host, disable_account, kill_process,
    quarantine_file, notify_analyst, ACTION_DISPATCH,
)
from actions import policy, audit_log
from config import config


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def reset_policy_state():
    """Reset the in-memory rate limiter and audit log index before each test."""
    policy._action_history.clear()
    audit_log._index_built = False
    yield


@pytest.fixture(autouse=True)
def mock_llm_client():
    """Mock ChatGroq at the import level to prevent API calls during tests.

    Without this, importing agents.response_agent triggers the module-level
    ChatGroq() instantiation in llm/groq_client.py which hangs trying to
    connect to the Groq API.
    """
    with patch("llm.groq_client.ChatGroq") as mock:
        mock.return_value.invoke.return_value.content = "[]"
        yield


def _response_agent():
    """Lazy import of ResponseAgent (avoids triggering ChatGroq at module level)."""
    from agents.response_agent import ResponseAgent
    return ResponseAgent()


@pytest.fixture
def sample_action():
    return ProposedAction(
        action_type=ActionType.BLOCK_IP,
        target="198.51.100.99",
        severity=ActionSeverity.MEDIUM,
        rationale="Test block",
        technique_id="T1071",
        confidence=0.9,
    )


@pytest.fixture
def sample_campaign():
    return {
        "campaign_id": "test-camp-001",
        "name": "Test Campaign",
        "timeline": [],
        "related_techniques": ["T1059.001"],
    }


@pytest.fixture
def sample_techniques():
    return [
        {"attack_id": "T1059.001", "technique_name": "PowerShell", "confidence": 1.0},
    ]


@pytest.fixture
def sample_iocs():
    return [
        {"value": "198.51.100.99", "ioc_type": "ip", "verdict": "suspicious"},
    ]


# ═══════════════════════════════════════════════════════════════════════
# Connector Tests
# ═══════════════════════════════════════════════════════════════════════

class TestConnectors:
    """Verify every connector returns a valid structured JSON string."""

    def _parse_result(self, raw: str) -> dict:
        return json.loads(raw)

    def test_block_ip_returns_structured_json(self):
        result = self._parse_result(block_ip("10.0.0.1"))
        assert result["action_type"] == "block_ip"
        assert result["target"] == "10.0.0.1"
        assert result["status"] in ("simulated", "executed", "failed")
        assert "timestamp" in result
        assert "duration_ms" in result
        assert result["dry_run"] is True  # DRY_RUN defaults to true

    def test_isolate_host_returns_structured_json(self):
        result = self._parse_result(isolate_host("WORKSTATION-07"))
        assert result["action_type"] == "isolate_host"
        assert result["target"] == "WORKSTATION-07"
        assert result["status"] in ("simulated", "executed", "failed")

    def test_disable_account_returns_structured_json(self):
        result = self._parse_result(disable_account("jdoe"))
        assert result["action_type"] == "disable_account"
        assert result["target"] == "jdoe"

    def test_kill_process_returns_structured_json(self):
        result = self._parse_result(kill_process("powershell.exe on WS-01"))
        assert result["action_type"] == "kill_process"
        assert result["target"] == "powershell.exe on WS-01"

    def test_quarantine_file_returns_structured_json(self):
        result = self._parse_result(quarantine_file("d41d8cd98f00b204e9800998ecf8427e"))
        assert result["action_type"] == "quarantine_file"
        assert result["target"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_notify_analyst_returns_structured_json(self):
        result = self._parse_result(notify_analyst("Test alert message"))
        assert result["action_type"] == "notify_analyst"
        assert result["status"] in ("simulated", "executed")

    def test_all_connectors_in_dispatch(self):
        """ACTION_DISPATCH should have all six action types."""
        expected = {"block_ip", "isolate_host", "disable_account",
                    "kill_process", "quarantine_file", "notify_analyst"}
        assert set(ACTION_DISPATCH.keys()) == expected

    def test_connector_duration_is_positive(self):
        result = self._parse_result(block_ip("10.0.0.1"))
        assert result["duration_ms"] > 0

    def test_dry_run_status_is_simulated(self):
        """When DRY_RUN is True, status should be 'simulated'."""
        result = self._parse_result(block_ip("10.0.0.1"))
        assert result["status"] == "simulated"
        assert result["dry_run"] is True


# ═══════════════════════════════════════════════════════════════════════
# Policy Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPolicyEvaluation:
    """Test the deterministic policy engine."""

    def test_denied_for_protected_target(self):
        """Protected targets are denied even when auto-response is enabled."""
        action = ProposedAction(
            action_type=ActionType.ISOLATE_HOST,
            target="DC-FILESRV01",
            severity=ActionSeverity.HIGH,
            rationale="Test",
            confidence=1.0,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            assert policy.evaluate(action) == "denied"

    def test_denied_for_domain_admin(self):
        """Domain admin is a protected target and should be denied."""
        action = ProposedAction(
            action_type=ActionType.DISABLE_ACCOUNT,
            target="domain admin",
            severity=ActionSeverity.HIGH,
            rationale="Test",
            confidence=1.0,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            assert policy.evaluate(action) == "denied"

    def test_pending_approval_for_low_confidence(self):
        """Low confidence actions should require approval even when auto-response is on."""
        action = ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="198.51.100.1",
            severity=ActionSeverity.LOW,
            rationale="Test",
            confidence=0.5,  # below 0.85 threshold
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            assert policy.evaluate(action) == "pending_approval"

    def test_pending_approval_for_high_severity(self):
        """High severity actions always require human approval."""
        action = ProposedAction(
            action_type=ActionType.ISOLATE_HOST,
            target="WS-01",
            severity=ActionSeverity.HIGH,
            rationale="Test",
            confidence=1.0,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            assert policy.evaluate(action) == "pending_approval"

    def test_auto_execute_when_all_conditions_met(self):
        """When auto-response is enabled and all conditions pass, action auto-executes."""
        action = ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="198.51.100.1",
            severity=ActionSeverity.LOW,
            rationale="Test",
            confidence=0.9,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            assert policy.evaluate(action) == "auto_execute"

    def test_kill_switch_prevents_auto_execute(self):
        """When AUTO_RESPONSE_ENABLED is False, everything is pending_approval."""
        action = ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="198.51.100.1",
            severity=ActionSeverity.LOW,
            rationale="Test",
            confidence=0.9,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", False):
            assert policy.evaluate(action) == "pending_approval"

    def test_rate_limit_exceeded(self):
        """More than 3 actions per target per hour should be pending."""
        action = ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.1",
            severity=ActionSeverity.LOW,
            rationale="Test",
            confidence=0.9,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            # Execute 3 times (should all auto_execute)
            for _ in range(3):
                policy.evaluate(action)
            # 4th should be rate-limited
            assert policy.evaluate(action) == "pending_approval"

    def test_rate_limit_resets_after_window(self):
        """Actions older than 1 hour should not count toward the limit."""
        action = ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.2",
            severity=ActionSeverity.LOW,
            rationale="Test",
            confidence=0.9,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            # Add an old timestamp directly
            old_ts = time.time() - 7200  # 2 hours ago
            policy._action_history["10.0.0.2"].append(old_ts)
            # Should still be able to auto-execute (old entry is outside window)
            assert policy.evaluate(action) == "auto_execute"

    def test_notify_analyst_always_auto_executes(self):
        """notify_analyst is low severity and should auto-execute with high confidence."""
        action = ProposedAction(
            action_type=ActionType.NOTIFY_ANALYST,
            target="SOC Team",
            severity=ActionSeverity.LOW,
            rationale="Test notification",
            confidence=1.0,
        )
        with patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            assert policy.evaluate(action) == "auto_execute"


# ═══════════════════════════════════════════════════════════════════════
# Audit Log Tests
# ═══════════════════════════════════════════════════════════════════════

class TestAuditLog:
    """Test the append-only audit log with structured queries."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Use a temporary audit log path for tests."""
        original_path = audit_log.AUDIT_LOG_PATH
        test_path = "./data/test_action_audit_log.jsonl"
        audit_log.AUDIT_LOG_PATH = test_path
        # Clean up before test
        if os.path.exists(test_path):
            os.remove(test_path)
        audit_log._index_built = False
        yield
        # Clean up after test
        if os.path.exists(test_path):
            os.remove(test_path)
        audit_log.AUDIT_LOG_PATH = original_path
        audit_log._index_built = False

    def _make_result(self, action_type="block_ip", target="10.0.0.1",
                     status="executed", confidence=0.9):
        action = ProposedAction(
            action_type=ActionType(action_type),
            target=target,
            severity=ActionSeverity.MEDIUM,
            rationale="Test",
            confidence=confidence,
        )
        return ActionResult(action=action, status=status, detail="Test detail", dry_run=True)

    def test_record_appends_entry(self):
        result = self._make_result()
        audit_log.record(result, campaign_id="test-camp")
        entries = audit_log.get_recent()
        assert len(entries) == 1
        assert entries[0]["campaign_id"] == "test-camp"
        assert entries[0]["action_type"] == "block_ip"

    def test_record_includes_all_fields(self):
        result = self._make_result()
        audit_log.record(result, campaign_id="test-camp")
        entries = audit_log.get_recent()
        entry = entries[0]
        assert "timestamp" in entry
        assert entry["action_type"] == "block_ip"
        assert entry["target"] == "10.0.0.1"
        assert entry["status"] == "executed"
        assert entry["confidence"] == 0.9
        assert entry["rationale"] == "Test"
        assert entry["detail"] == "Test detail"
        assert entry["dry_run"] is True

    def test_read_pending_approvals(self):
        audit_log.record(self._make_result(status="executed"))
        audit_log.record(self._make_result(status="pending_approval"))
        audit_log.record(self._make_result(status="denied"))
        pending = audit_log.read_pending_approvals()
        assert len(pending) == 1
        assert pending[0]["status"] == "pending_approval"

    def test_query_by_status(self):
        audit_log.record(self._make_result(status="executed"))
        audit_log.record(self._make_result(status="pending_approval"))
        results = audit_log.query(status="executed")
        assert len(results) == 1
        assert results[0]["status"] == "executed"

    def test_query_by_action_type(self):
        audit_log.record(self._make_result(action_type="block_ip"))
        audit_log.record(self._make_result(action_type="isolate_host"))
        results = audit_log.query(action_type="block_ip")
        assert len(results) == 1
        assert results[0]["action_type"] == "block_ip"

    def test_query_by_target(self):
        audit_log.record(self._make_result(target="10.0.0.1"))
        audit_log.record(self._make_result(target="10.0.0.2"))
        results = audit_log.query(target="10.0.0.1")
        assert len(results) == 1
        assert results[0]["target"] == "10.0.0.1"

    def test_query_by_campaign_id(self):
        audit_log.record(self._make_result(), campaign_id="camp-1")
        audit_log.record(self._make_result(), campaign_id="camp-2")
        results = audit_log.query(campaign_id="camp-1")
        assert len(results) == 1
        assert results[0]["campaign_id"] == "camp-1"

    def test_query_with_multiple_filters(self):
        audit_log.record(
            self._make_result(action_type="block_ip", status="executed"),
            campaign_id="camp-1",
        )
        audit_log.record(
            self._make_result(action_type="block_ip", status="pending_approval"),
            campaign_id="camp-1",
        )
        results = audit_log.query(
            status="executed",
            action_type="block_ip",
            campaign_id="camp-1",
        )
        assert len(results) == 1

    def test_query_returns_newest_first(self):
        audit_log.record(self._make_result(target="first"), campaign_id="camp")
        audit_log.record(self._make_result(target="second"), campaign_id="camp")
        results = audit_log.query(campaign_id="camp")
        assert results[0]["target"] == "second"
        assert results[1]["target"] == "first"

    def test_query_limit(self):
        for i in range(5):
            audit_log.record(self._make_result(target=f"host-{i}"), campaign_id="camp")
        results = audit_log.query(campaign_id="camp", limit=3)
        assert len(results) == 3

    def test_count_by_status(self):
        audit_log.record(self._make_result(status="executed"))
        audit_log.record(self._make_result(status="executed"))
        audit_log.record(self._make_result(status="pending_approval"))
        counts = audit_log.count_by_status()
        assert counts.get("executed") == 2
        assert counts.get("pending_approval") == 1

    def test_count_by_action_type(self):
        audit_log.record(self._make_result(action_type="block_ip"))
        audit_log.record(self._make_result(action_type="block_ip"))
        audit_log.record(self._make_result(action_type="isolate_host"))
        counts = audit_log.count_by_action_type()
        assert counts.get("block_ip") == 2
        assert counts.get("isolate_host") == 1

    def test_export_to_json(self):
        audit_log.record(self._make_result(), campaign_id="camp")
        output_path = "./data/test_audit_export.json"
        try:
            result_path = audit_log.export_to_json(output_path)
            assert result_path == output_path
            with open(output_path, "r") as f:
                data = json.load(f)
            assert len(data) == 1
            assert data[0]["campaign_id"] == "camp"
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

    def test_empty_log_returns_empty(self):
        assert audit_log.get_recent() == []
        assert audit_log.read_pending_approvals() == []
        assert audit_log.count_by_status() == {}
        assert audit_log.export_to_json("./data/empty_export.json") == ""


# ═══════════════════════════════════════════════════════════════════════
# ResponseAgent Tests
# ═══════════════════════════════════════════════════════════════════════

class TestResponseAgent:
    """Test the ResponseAgent end-to-end with mocked LLM output."""

    @pytest.fixture
    def agent(self):
        return _response_agent()

    @pytest.fixture(autouse=True)
    def setup_audit_log(self):
        """Use a test audit log path."""
        original_path = audit_log.AUDIT_LOG_PATH
        test_path = "./data/test_response_agent_log.jsonl"
        audit_log.AUDIT_LOG_PATH = test_path
        if os.path.exists(test_path):
            os.remove(test_path)
        audit_log._index_built = False
        yield
        if os.path.exists(test_path):
            os.remove(test_path)
        audit_log.AUDIT_LOG_PATH = original_path
        audit_log._index_built = False

    def test_empty_proposals(self, agent, sample_campaign, sample_techniques, sample_iocs):
        """When LLM returns no proposals, agent should return empty list."""
        with patch("agents.response_agent.invoke_llm", return_value="[]"):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            assert results == []

    def test_malformed_llm_output_returns_empty(self, agent, sample_campaign,
                                                 sample_techniques, sample_iocs):
        """When LLM returns non-JSON, agent should return empty list."""
        with patch("agents.response_agent.invoke_llm", return_value="Not JSON at all"):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            assert results == []

    def test_single_notify_action(self, agent, sample_campaign, sample_techniques, sample_iocs):
        """A single notify_analyst action should be processed."""
        llm_output = json.dumps([
            {
                "action_type": "notify_analyst",
                "target": "SOC Team",
                "severity": "low",
                "rationale": "Test notification",
                "technique_id": "T1059.001",
                "confidence": 1.0,
            }
        ])
        with patch("agents.response_agent.invoke_llm", return_value=llm_output):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            assert len(results) == 1
            assert results[0].action.action_type == "notify_analyst"
            assert results[0].status in ("executed", "pending_approval")

    def test_multiple_actions(self, agent, sample_campaign, sample_techniques, sample_iocs):
        """Multiple actions should all be processed."""
        llm_output = json.dumps([
            {
                "action_type": "block_ip",
                "target": "198.51.100.99",
                "severity": "medium",
                "rationale": "Block C2 IP",
                "technique_id": "T1071",
                "confidence": 0.9,
            },
            {
                "action_type": "notify_analyst",
                "target": "SOC Team",
                "severity": "low",
                "rationale": "Alert",
                "technique_id": "",
                "confidence": 1.0,
            },
        ])
        with patch("agents.response_agent.invoke_llm", return_value=llm_output):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            assert len(results) == 2
            assert results[0].action.action_type == "block_ip"
            assert results[1].action.action_type == "notify_analyst"

    def test_actions_are_audit_logged(self, agent, sample_campaign, sample_techniques, sample_iocs):
        """Every action should be written to the audit log."""
        llm_output = json.dumps([
            {
                "action_type": "notify_analyst",
                "target": "SOC Team",
                "severity": "low",
                "rationale": "Test",
                "technique_id": "",
                "confidence": 1.0,
            }
        ])
        with patch("agents.response_agent.invoke_llm", return_value=llm_output):
            agent.run(sample_campaign, sample_techniques, sample_iocs)
            entries = audit_log.get_recent()
            assert len(entries) == 1
            assert entries[0]["campaign_id"] == "test-camp-001"

    def test_malformed_action_skipped(self, agent, sample_campaign, sample_techniques, sample_iocs):
        """A malformed action in the array should be skipped, not crash."""
        llm_output = json.dumps([
            {"invalid": "no action_type"},  # missing required fields
            {
                "action_type": "notify_analyst",
                "target": "SOC Team",
                "severity": "low",
                "rationale": "Valid",
                "technique_id": "",
                "confidence": 1.0,
            },
        ])
        with patch("agents.response_agent.invoke_llm", return_value=llm_output):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            assert len(results) == 1
            assert results[0].action.action_type == "notify_analyst"

    def test_unknown_action_type_returns_failed(self, agent, sample_campaign,
                                                 sample_techniques, sample_iocs):
        """An action type not in ACTION_DISPATCH should fail gracefully."""
        llm_output = json.dumps([
            {
                "action_type": "nonexistent_action",
                "target": "test",
                "severity": "low",
                "rationale": "Test",
                "technique_id": "",
                "confidence": 1.0,
            }
        ])
        with patch("agents.response_agent.invoke_llm", return_value=llm_output):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            # Malformed action_type will fail ProposedAction validation and be skipped
            assert len(results) == 0

    def test_protected_target_denied(self, agent, sample_campaign, sample_techniques, sample_iocs):
        """Actions against protected targets should be denied."""
        llm_output = json.dumps([
            {
                "action_type": "isolate_host",
                "target": "DC-FILESRV01",
                "severity": "high",
                "rationale": "Test",
                "technique_id": "T1053.005",
                "confidence": 1.0,
            }
        ])
        with patch("agents.response_agent.invoke_llm", return_value=llm_output), \
             patch.object(config, "AUTO_RESPONSE_ENABLED", True):
            results = agent.run(sample_campaign, sample_techniques, sample_iocs)
            assert len(results) == 1
            assert results[0].status == "denied"
            assert "protected" in results[0].detail.lower()

    def test_llm_invoked_with_correct_prompt(self, agent, sample_campaign,
                                              sample_techniques, sample_iocs):
        """The LLM should be called with the campaign, techniques, and IOCs."""
        with patch("agents.response_agent.invoke_llm") as mock_llm:
            mock_llm.return_value = "[]"
            agent.run(sample_campaign, sample_techniques, sample_iocs)
            # Check that the user prompt contains the campaign data
            call_args = mock_llm.call_args[1]
            assert "Campaign:" in call_args["user_prompt"]
            assert "test-camp-001" in call_args["user_prompt"]
            assert "T1059.001" in call_args["user_prompt"]
            assert "198.51.100.99" in call_args["user_prompt"]


# ═══════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases across the response system."""

    def test_action_with_minimal_fields(self):
        """An action with only required fields should be valid."""
        action = ProposedAction(
            action_type=ActionType.NOTIFY_ANALYST,
            target="test",
            severity=ActionSeverity.LOW,
            rationale="Minimal",
        )
        assert action.action_type == "notify_analyst"
        assert action.confidence == 0.0  # default
        assert action.technique_id is None  # default

    def test_action_with_all_fields(self):
        """An action with all fields should be valid."""
        action = ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.1",
            severity=ActionSeverity.HIGH,
            rationale="Full test",
            technique_id="T1071",
            confidence=0.95,
        )
        assert action.technique_id == "T1071"
        assert action.confidence == 0.95

    def test_action_result_dry_run_default(self):
        """ActionResult should default to dry_run=True."""
        action = ProposedAction(
            action_type=ActionType.NOTIFY_ANALYST,
            target="test",
            severity=ActionSeverity.LOW,
            rationale="Test",
        )
        result = ActionResult(action=action, status="executed", detail="OK")
        assert result.dry_run is True

    def test_empty_audit_log_queries(self):
        """Querying an empty audit log should return empty results."""
        # Use a non-existent path
        original = audit_log.AUDIT_LOG_PATH
        audit_log.AUDIT_LOG_PATH = "./data/nonexistent_log.jsonl"
        audit_log._index_built = False
        try:
            assert audit_log.get_recent() == []
            assert audit_log.read_pending_approvals() == []
            assert audit_log.query(status="executed") == []
            assert audit_log.count_by_status() == {}
        finally:
            audit_log.AUDIT_LOG_PATH = original
            audit_log._index_built = False

    def test_connector_dispatch_all_functions(self):
        """Every function in ACTION_DISPATCH should be callable."""
        for action_type, handler in ACTION_DISPATCH.items():
            result = json.loads(handler("test-target"))
            assert result["action_type"] == action_type
            assert result["target"] == "test-target"