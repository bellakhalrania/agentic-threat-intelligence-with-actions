"""Tests for remote response-agent push safeguards."""

from actions.crypto import build_signed_payload, verify_signature
from actions.remote_push import _remote_agent_timestamp


def test_signed_payload_accepts_a_remote_timestamp():
    payload = build_signed_payload(
        script="echo safe",
        filename="response.sh",
        campaign_id="campaign-1",
        action_count=1,
        platform="linux",
        secret_key="test-secret",
        timestamp=1_786_000_000,
    )

    assert payload["timestamp"] == 1_786_000_000
    assert verify_signature(
        {key: value for key, value in payload.items() if key != "signature"},
        payload["signature"],
        "test-secret",
    )


def test_remote_agent_timestamp_uses_health_clock(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"timestamp": "2026-08-13T16:30:00+00:00"}

    monkeypatch.setattr("actions.remote_push.requests.get", lambda *args, **kwargs: Response())

    assert _remote_agent_timestamp("http://agent.example:9001/execute", "key") == 1_786_638_600
