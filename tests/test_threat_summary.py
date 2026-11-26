from intelligence.threat_summary import build_threat_summary


def test_build_threat_summary_is_compact_and_deterministic():
    events = [
        {
            "event_type": "authentication_failed",
            "host": "web-01",
            "username": "alice",
            "src_ip": "198.51.100.10",
            "raw": {"large": "x" * 50_000},
        },
        {
            "event_type": "authentication_failed",
            "host": "web-01",
            "user": "alice",
            "src_ip": "198.51.100.10",
        },
    ]
    summary = build_threat_summary(
        campaign={"campaign_id": "c-1", "name": "SSH Brute Force", "confidence": 0.95},
        techniques=[
            {"attack_id": "T1110", "technique_name": "Brute Force", "confidence": 1.0},
            {"attack_id": "T1110", "technique_name": "Brute Force", "confidence": 0.9},
        ],
        prediction={"likely_next_techniques": ["T1078"], "rationale": "Try valid accounts."},
        events=events,
    )

    assert summary["campaign"]["name"] == "SSH Brute Force"
    assert summary["campaign"]["severity"] == "high"
    assert summary["event_count"] == 2
    assert summary["failed_login_count"] == 2
    assert summary["successful_authentication_after_failures"] is False
    assert summary["affected_hosts"] == ["web-01"]
    assert summary["affected_users"] == ["alice"]
    assert summary["top_mitre_techniques"] == [
        {"id": "T1110", "name": "Brute Force", "count": 2, "confidence": 1.0}
    ]
    assert "raw" not in str(summary)
    assert len(str(summary)) < 3_000


def test_detects_success_after_failure_for_same_source_and_account():
    events = [
        {
            "event_type": "authentication_failed",
            "src_ip": "198.51.100.10",
            "username": "alice",
        },
        {
            "event_type": "authentication_success",
            "src_ip": "198.51.100.10",
            "username": "alice",
        },
    ]
    summary = build_threat_summary({}, [], {}, events)
    assert summary["successful_authentication_after_failures"] is True
