"""
tests/test_remote_agent_forwarder.py
Unit tests for the machine-2 event forwarder.
"""

import json

import pytest
import requests

from remote_agent.forwarder import AgentEventForwarder, ForwarderConfig


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_forwarder_flushes_events_and_persists_cursor(tmp_path, monkeypatch):
    source_path = tmp_path / "agent_events.jsonl"
    cursor_path = tmp_path / "agent_cursor.json"
    source_path.write_text(
        "\n".join(
            [
                json.dumps({"event_id": "evt-1", "timestamp": "2026-08-13T12:00:00Z"}),
                json.dumps({"event_id": "evt-2", "timestamp": "2026-08-13T12:01:00Z"}),
            ]
        ),
        encoding="utf-8",
    )

    calls = []

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout, "verify": verify})
        return DummyResponse({"success": True, "events_stored": len(json["events"])})

    monkeypatch.setattr("remote_agent.forwarder.requests.post", fake_post)

    forwarder = AgentEventForwarder(
        ForwarderConfig(
            source_path=source_path,
            cursor_path=cursor_path,
            target_url="http://machine3:8000",
            api_key="shared-key",
            verify_ssl=False,
            batch_size=10,
            poll_interval=1,
            timeout=5,
            max_retries=2,
        )
    )

    result = forwarder.flush_once()

    assert result["status"] == "ok"
    assert result["sent"] == 2
    assert len(calls) == 1
    assert calls[0]["url"] == "http://machine3:8000/agent/events"
    assert calls[0]["headers"]["X-Agent-Key"] == "shared-key"
    assert cursor_path.exists()

    second_result = forwarder.flush_once()
    assert second_result["status"] == "idle"
    assert second_result["sent"] == 0


def test_forwarder_keeps_events_when_send_fails(tmp_path, monkeypatch):
    source_path = tmp_path / "agent_events.jsonl"
    cursor_path = tmp_path / "agent_cursor.json"
    source_path.write_text(json.dumps({"event_id": "evt-fail", "timestamp": "2026-08-13T12:00:00Z"}), encoding="utf-8")

    def failing_post(*args, **kwargs):
        raise requests.exceptions.ConnectionError("network down")

    monkeypatch.setattr("remote_agent.forwarder.requests.post", failing_post)

    forwarder = AgentEventForwarder(
        ForwarderConfig(
            source_path=source_path,
            cursor_path=cursor_path,
            target_url="http://machine3:8000",
            batch_size=10,
            poll_interval=1,
            timeout=1,
            max_retries=1,
        )
    )

    result = forwarder.flush_once()

    assert result["status"] == "failed"
    assert result["sent"] == 0
    failed_path = source_path.with_suffix(".failed.jsonl")
    assert failed_path.exists()