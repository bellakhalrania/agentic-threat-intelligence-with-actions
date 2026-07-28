"""
tests/test_response_actions_api.py
Tests for the POST /response/actions endpoint.

Tests cover:
  - Successful request returns actions and execution packages
  - Error handling when workflow raises an exception
  - Response model field validation
  - Empty events list handling
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app import app
from graph.state import InvestigationState

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def sample_request_body():
    """Example request body matching the documented format."""
    return {
        "events": [
            {
                "source": "sysmon",
                "event_id": "evt-001",
                "timestamp": "2026-06-20T10:15:00Z",
                "host": "WORKSTATION-07",
                "process": "powershell.exe",
                "command_line": "powershell.exe -enc JABzAD0AT...",
                "event_type": "process_execution"
            },
            {
                "source": "suricata",
                "timestamp": "2026-06-20T10:16:32Z",
                "src_ip": "10.0.5.21",
                "dest_ip": "185.44.12.7",
                "signature": "ET MALWARE Possible C2 Beacon",
                "category": "Command and Control",
                "severity": 1
            }
        ]
    }


@pytest.fixture
def mock_action_result():
    """Simulate an ActionResult dict as produced by response_node."""
    return {
        "action": {
            "action_type": "isolate_host",
            "target": "host communicating with 185.44.12.7",
            "severity": "high",
            "rationale": "Multiple high-confidence ATT&CK techniques indicate active compromise.",
            "technique_id": "T1059.001",
            "confidence": 0.85,
        },
        "status": "pending_approval",
        "detail": "Awaiting human approval.",
        "dry_run": True,
    }


@pytest.fixture
def mock_execution_package():
    """Simulate an execution package as produced by execution_translation_node."""
    return {
        "action_id": "isolate_host_a1b2c3d4",
        "action_type": "isolate_host",
        "platform": "linux",
        "language": "bash",
        "filename": "isolate_host_host_communicating_with_185.44.12.7.sh",
        "script": "#!/bin/bash\n# Isolate host host communicating with 185.44.12.7\n...",
        "requires_admin": True,
        "expected_effect": "Block all traffic on host host communicating with 185.44.12.7 except loopback",
        "rollback": "# Rollback isolation\n...",
        "verification": [
            "iptables -L -n 2>/dev/null | head -5",
            "ping -c 1 -W 2 8.8.8.8 2>&1 | grep -q '100% packet loss' && echo 'ISOLATED'",
        ],
    }


@pytest.fixture
def mock_workflow_success(mock_action_result, mock_execution_package):
    """
    Patch threat_intel_workflow.invoke to return a state with
    actions_taken containing a proper action dict (not an object),
    execution_packages, combined_script, combined_filename, and a campaign.
    """
    def _invoke(state):
        return {
            "actions_taken": [mock_action_result],
            "execution_packages": [mock_execution_package],
            "combined_script": "#!/bin/bash\n# Combined response actions script\necho 'test'",
            "combined_filename": "response_actions_1_actions.sh",
            "campaign": {"campaign_id": "e3b0c442-98fc-1c14-9af8-9d5e6f8c9b1a"},
        }

    return _invoke


# ═══════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════

class TestResponseActionsEndpoint:
    """Tests for POST /response/actions."""

    def test_success_returns_actions_and_packages(
        self, sample_request_body, mock_workflow_success
    ):
        """
        A successful request should return:
          - success: true
          - actions: list of mapped action dicts
          - execution_packages: list of execution package dicts
          - campaign_id: the campaign UUID
        """
        with patch("app.threat_intel_workflow.invoke", mock_workflow_success):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()

        assert body["success"] is True
        assert len(body["actions"]) > 0
        assert len(body["execution_packages"]) > 0
        assert body["campaign_id"] == "e3b0c442-98fc-1c14-9af8-9d5e6f8c9b1a"

    def test_success_action_fields_mapped_correctly(self, sample_request_body, mock_workflow_success):
        """
        Each action in the response should have the correct fields
        with values extracted from the action result.
        """
        with patch("app.threat_intel_workflow.invoke", mock_workflow_success):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        action = response.json()["actions"][0]

        # The endpoint maps action.[field], so we compare against the action sub-dict
        assert action["action_type"] == "isolate_host"
        assert "host communicating with 185.44.12.7" in action["target"]
        assert action["severity"] == "high"
        assert action["status"] == "pending_approval"
        assert action["technique_id"] == "T1059.001"
        assert action["confidence"] == 0.85
        assert "compromise" in action["rationale"]
        assert action["dry_run"] is True

    def test_success_execution_packages_included(self, sample_request_body, mock_workflow_success):
        """
        The execution_packages from the workflow state should be
        included in the response verbatim.
        """
        with patch("app.threat_intel_workflow.invoke", mock_workflow_success):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()

        pkg = body["execution_packages"][0]
        assert pkg["action_type"] == "isolate_host"
        assert pkg["platform"] == "linux"
        assert pkg["language"] == "bash"
        assert pkg["requires_admin"] is True
        assert "script" in pkg
        assert "rollback" in pkg
        assert len(pkg["verification"]) > 0

    def test_combined_script_included(self, sample_request_body, mock_workflow_success):
        """
        The response should include a combined_script containing all actions
        and a combined_filename for the downloadable script.
        """
        with patch("app.threat_intel_workflow.invoke", mock_workflow_success):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()

        assert "combined_script" in body
        assert "combined_filename" in body
        assert body["combined_script"] != ""
        assert body["combined_filename"] != ""
        assert body["combined_script"].startswith("#!/bin/bash")
        assert body["combined_filename"].endswith(".sh")

    def test_combined_script_empty_when_no_actions(self, sample_request_body):
        """
        When there are no actions, combined_script and combined_filename
        should be empty strings.
        """
        def _invoke(state):
            return {
                "actions_taken": [],
                "execution_packages": [],
                "combined_script": "",
                "combined_filename": "",
                "campaign": {},
            }

        with patch("app.threat_intel_workflow.invoke", _invoke):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()
        assert body["combined_script"] == ""
        assert body["combined_filename"] == ""

    def test_success_empty_actions_list(self, sample_request_body):
        """
        When the workflow produces no actions_taken, the response
        should have an empty actions list and success: true.
        """
        def _invoke(state):
            return {
                "actions_taken": [],
                "execution_packages": [],
                "campaign": {"campaign_id": "test-camp-001"},
            }

        with patch("app.threat_intel_workflow.invoke", _invoke):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["actions"] == []
        assert body["execution_packages"] == []

    def test_workflow_error_returns_failure(self, sample_request_body):
        """
        When the workflow raises an exception, the endpoint should
        catch it and return success: false with the error message.
        """
        with patch("app.threat_intel_workflow.invoke", side_effect=RuntimeError("Test error")):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200  # Still 200 because we catch the error
        body = response.json()
        assert body["success"] is False
        assert "Test error" in body["error"]
        assert body["actions"] == []
        assert body["execution_packages"] == []
        assert body["campaign_id"] is None

    def test_empty_events_list(self):
        """
        Sending an empty events list should still run the workflow
        and return a valid response.
        """
        request_body = {"events": []}

        def _invoke(state):
            return {
                "actions_taken": [],
                "execution_packages": [],
                "campaign": {},
            }

        with patch("app.threat_intel_workflow.invoke", _invoke):
            response = client.post("/response/actions", json=request_body)

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["actions"] == []

    def test_missing_events_field_returns_422(self):
        """
        Omitting the required 'events' field should return a 422
        validation error from FastAPI/Pydantic.
        """
        response = client.post("/response/actions", json={})
        assert response.status_code == 422

    def test_events_not_a_list_returns_422(self):
        """
        Sending events as a non-list should return a 422 validation error.
        """
        response = client.post("/response/actions", json={"events": "not_a_list"})
        assert response.status_code == 422

    def test_multiple_actions_in_response(self, sample_request_body):
        """
        When the workflow returns multiple actions, all should be
        included in the response.
        """
        def _invoke(state):
            return {
                "actions_taken": [
                    {
                        "action": {
                            "action_type": "block_ip",
                            "target": "185.44.12.7",
                            "severity": "medium",
                            "rationale": "Block C2 IP",
                            "technique_id": "T1071",
                            "confidence": 0.9,
                        },
                        "status": "pending_approval",
                        "detail": "Awaiting approval.",
                        "dry_run": True,
                    },
                    {
                        "action": {
                            "action_type": "notify_analyst",
                            "target": "SOC Team",
                            "severity": "low",
                            "rationale": "Alert analyst",
                            "technique_id": "",
                            "confidence": 1.0,
                        },
                        "status": "executed",
                        "detail": "Notification sent.",
                        "dry_run": True,
                    },
                ],
                "execution_packages": [],
                "campaign": {"campaign_id": "multi-action-camp"},
            }

        with patch("app.threat_intel_workflow.invoke", _invoke):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()
        assert len(body["actions"]) == 2

        # First action: block_ip
        assert body["actions"][0]["action_type"] == "block_ip"
        assert body["actions"][0]["target"] == "185.44.12.7"

        # Second action: notify_analyst
        assert body["actions"][1]["action_type"] == "notify_analyst"
        assert body["actions"][1]["target"] == "SOC Team"

    def test_response_model_optional_fields(self, sample_request_body):
        """
        The response model should handle missing optional fields
        gracefully (e.g., campaign_id can be None).
        """
        def _invoke(state):
            return {
                "actions_taken": [],
                "execution_packages": [],
                "campaign": {},  # no campaign_id
            }

        with patch("app.threat_intel_workflow.invoke", _invoke):
            response = client.post("/response/actions", json=sample_request_body)

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        # campaign_id should be None (default from the dict's .get())
        assert body["campaign_id"] is None


class TestResponseActionsEndpointWithoutWorkflow:
    """
    Tests that validate the endpoint structure without needing
    the full workflow to be importable (for environments where
    dependencies like langgraph may not be available).
    """

    def test_endpoint_is_registered(self):
        """The /response/actions endpoint should exist."""
        routes = [r.path for r in app.routes]
        assert "/response/actions" in routes

    def test_endpoint_accepts_post_only(self):
        """The endpoint should only accept POST requests."""
        # GET should fail
        response = client.get("/response/actions")
        assert response.status_code == 405  # Method Not Allowed
