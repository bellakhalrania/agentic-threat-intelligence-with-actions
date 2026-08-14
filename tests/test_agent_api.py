"""
tests/test_agent_api.py
Tests for the custom agent ingest API on machine 3.
"""

import json

from fastapi.testclient import TestClient

import app as app_module


client = TestClient(app_module.app)


def test_agent_ingest_and_latest(tmp_path, monkeypatch):
    store_path = tmp_path / "agent_events.jsonl"
    monkeypatch.setattr(app_module, "AGENT_EVENTS_PATH", str(store_path))
    monkeypatch.setattr(app_module, "AGENT_SHARED_KEY", "agent-secret")

    payload = {
        "events": [
            {
                "event_id": "evt-100",
                "timestamp": "2026-08-13T12:00:00Z",
                "source": "agent",
                "host": "machine-2",
            },
            {
                "event_id": "evt-101",
                "timestamp": "2026-08-13T12:01:00Z",
                "source": "agent",
                "host": "machine-2",
            },
        ]
    }

    response = client.post(
        "/agent/events",
        json=payload,
        headers={"X-Agent-Key": "agent-secret"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["events_stored"] == 2
    assert body["latest_event_id"] == "evt-101"

    latest = client.get("/agent/latest?limit=2")
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["success"] is True
    assert latest_body["count"] == 2
    assert latest_body["events"][0]["event_id"] == "evt-100"
    assert latest_body["events"][1]["event_id"] == "evt-101"

    health = client.get("/agent/health")
    assert health.status_code == 200
    health_body = health.json()
    assert health_body["status"] == "healthy"
    assert health_body["events_stored"] == 2


def test_agent_ingest_rejects_invalid_key(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "AGENT_EVENTS_PATH", str(tmp_path / "agent_events.jsonl"))
    monkeypatch.setattr(app_module, "AGENT_SHARED_KEY", "agent-secret")

    response = client.post(
        "/agent/events",
        json={"events": [{"event_id": "evt-200", "timestamp": "2026-08-13T12:05:00Z"}]},
        headers={"X-Agent-Key": "wrong-key"},
    )

    assert response.status_code == 403