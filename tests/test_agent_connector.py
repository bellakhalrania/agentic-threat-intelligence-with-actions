"""
tests/test_agent_connector.py
Unit tests for the custom AgentConnector.
"""

import json

from connectors.agent_connector import AgentConnector


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_agent_connector_reads_jsonl_file(tmp_path):
    events_path = tmp_path / "agent_events.jsonl"
    cursor_path = tmp_path / "agent_cursor.json"

    events_path.write_text(
        "\n".join(
            [
                json.dumps({"event_id": "evt-1", "timestamp": "2026-08-13T10:00:00Z", "source": "agent"}),
                json.dumps({"event_id": "evt-2", "timestamp": "2026-08-13T10:01:00Z", "source": "agent"}),
            ]
        ),
        encoding="utf-8",
    )

    connector = AgentConnector(events_path=str(events_path), cursor_path=str(cursor_path))

    first_batch = connector.fetch_events()
    assert len(first_batch) == 2
    assert first_batch[0]["event_id"] == "evt-1"
    assert first_batch[1]["event_id"] == "evt-2"

    second_batch = connector.fetch_events()
    assert second_batch == []


def test_agent_connector_fetches_from_http(monkeypatch, tmp_path):
    payload = {
        "events": [
            {"event_id": "evt-10", "timestamp": "2026-08-13T11:00:00Z", "source": "agent"},
            {"event_id": "evt-11", "timestamp": "2026-08-13T11:01:00Z", "source": "agent"},
        ]
    }

    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None, verify=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["params"] = params
        captured["timeout"] = timeout
        captured["verify"] = verify
        return DummyResponse(payload)

    monkeypatch.setattr("connectors.agent_connector.requests.get", fake_get)

    connector = AgentConnector(
        source_url="http://machine2:8001",
        api_key="test-key",
        cursor_path=str(tmp_path / "agent_cursor.json"),
    )

    events = connector.fetch_events()

    assert captured["url"] == "http://machine2:8001/agent/latest"
    assert captured["headers"]["X-Agent-Key"] == "test-key"
    assert captured["params"]["limit"] > 0
    assert len(events) == 2
    assert events[0]["event_id"] == "evt-10"