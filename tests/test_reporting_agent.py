from agents.reporting_agent import ReportingAgent


def test_reporting_prompt_uses_compact_event_summary():
    agent = ReportingAgent()
    state = {
        "events": [
            {
                "event_id": "evt-1",
                "source": "wazuh",
                "event_type": "authentication_success",
                "timestamp": "2026-07-28T13:56:14.486+0000",
                "host": "ip-172-31-19-70",
                "user": "ubuntu",
                "username": "root",
                "process": "sudo",
                "command_line": "sudo command " + "x" * 1000,
                "src_ip": "205.210.31.25",
                "rule_description": "PAM: Login session opened.",
                "rule_level": 3,
                "rule_groups": ["pam", "syslog", "authentication_success"],
                "raw": {
                    "very_large_raw_payload": "RAW_SHOULD_NOT_BE_SENT" * 1000,
                    "rule": {"mitre": {"id": ["T1078"], "technique": ["Valid Accounts"]}},
                },
            }
        ],
        "iocs": [],
        "techniques": [],
        "campaign": {},
        "prediction": {},
        "actions_taken": [],
    }

    prompt = agent._build_compact_prompt(state)

    assert "RAW_SHOULD_NOT_BE_SENT" not in prompt
    assert "205.210.31.25" in prompt
    assert "authentication_success" in prompt
    assert len(prompt) < 5000


def test_response_actions_section_uses_state_actions():
    agent = ReportingAgent()
    state = {
        "actions_taken": [
            {
                "action": {
                    "action_type": "block_ip",
                    "target": "198.51.100.10",
                    "severity": "high",
                    "rationale": "Repeated authentication failures.",
                },
                "status": "pending_approval",
                "detail": "Awaiting human approval.",
                "dry_run": False,
            }
        ]
    }

    report = agent._replace_response_actions_section(
        "## Recommendations\n\n## Response Actions\n\n| No data available |", state
    )

    assert "| block_ip | 198.51.100.10 | pending_approval | high |" in report
    assert "| No data available |" not in report
