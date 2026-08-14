"""
remote_agent/forwarder.py
=========================
Machine-2 event forwarder for sending local telemetry to Machine 3.

This module is intentionally small and operationally simple:
  - read events from a local JSON or JSONL spool file
  - POST batches to the Machine 3 ingest endpoint
  - remember what was sent in a small cursor file
  - keep failed events locally for retry

The forwarder is meant to run alongside the existing remote response agent.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


def _stable_event_id(event: Dict[str, Any]) -> str:
    event_id = event.get("event_id") or event.get("id")
    if event_id:
        return str(event_id)
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_json_or_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []

    if content.startswith("["):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        except json.JSONDecodeError:
            pass

    events: List[Dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON line in %s", path)
            continue

        if isinstance(item, dict) and isinstance(item.get("events"), list):
            events.extend(entry for entry in item["events"] if isinstance(entry, dict))
        elif isinstance(item, dict):
            events.append(item)

    return events


def _append_jsonl(path: Path, entry: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


@dataclass
class ForwarderConfig:
    source_path: Path
    cursor_path: Path
    target_url: str
    api_key: str = ""
    verify_ssl: bool = True
    batch_size: int = 100
    poll_interval: int = 15
    timeout: int = 30
    max_retries: int = 3


class AgentEventForwarder:
    """Forward events from a local spool file to the Machine 3 ingest API."""

    def __init__(self, config: ForwarderConfig):
        self.config = config
        self._processed_event_ids: set[str] = set()
        self._last_cursor: Optional[str] = None
        self._load_cursor()

    def _load_cursor(self) -> None:
        if not self.config.cursor_path.exists():
            return

        try:
            data = json.loads(self.config.cursor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load forwarder cursor %s: %s", self.config.cursor_path, exc)
            return

        self._last_cursor = data.get("last_cursor")
        ids = data.get("processed_event_ids") or []
        if isinstance(ids, list):
            self._processed_event_ids = {str(item) for item in ids if item}

    def _mark_batch_sent(self, events: List[Dict[str, Any]]) -> None:
        for event in events:
            self._processed_event_ids.add(_stable_event_id(event))

        cursor_values = [
            event.get("timestamp") or event.get("observed_at") or event.get("received_at")
            for event in events
        ]
        cursor_values = [value for value in cursor_values if value]
        if cursor_values:
            self._last_cursor = max(cursor_values)

        self._save_cursor()

    def _save_cursor(self) -> None:
        self.config.cursor_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_cursor": self._last_cursor,
            "processed_event_ids": sorted(self._processed_event_ids),
        }
        self.config.cursor_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _filter_new_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        new_events: List[Dict[str, Any]] = []
        for event in events:
            event_id = _stable_event_id(event)
            if event_id in self._processed_event_ids:
                continue

            cursor_value = event.get("timestamp") or event.get("observed_at") or event.get("received_at")
            if self._last_cursor and cursor_value and cursor_value <= self._last_cursor:
                continue

            new_events.append(event)

        return new_events

    def read_pending_events(self) -> List[Dict[str, Any]]:
        events = _read_json_or_jsonl(self.config.source_path)
        return self._filter_new_events(events)

    def send_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not events:
            return {"sent": 0, "status": "empty"}

        url = self.config.target_url.rstrip("/") + "/agent/events"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["X-Agent-Key"] = self.config.api_key

        response = requests.post(
            url,
            json={"events": events},
            headers=headers,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
        )
        response.raise_for_status()
        self._mark_batch_sent(events)
        return response.json()

    def flush_once(self) -> Dict[str, Any]:
        pending = self.read_pending_events()
        if not pending:
            return {"sent": 0, "status": "idle"}

        total_sent = 0
        last_response: Dict[str, Any] = {"sent": 0, "status": "idle"}

        for start in range(0, len(pending), self.config.batch_size):
            batch = pending[start : start + self.config.batch_size]
            attempt = 0
            while True:
                try:
                    last_response = self.send_batch(batch)
                    total_sent += len(batch)
                    break
                except requests.RequestException as exc:
                    attempt += 1
                    logger.warning(
                        "Failed to send agent batch to %s (attempt %s/%s): %s",
                        self.config.target_url,
                        attempt,
                        self.config.max_retries,
                        exc,
                    )
                    if attempt >= self.config.max_retries:
                        self._requeue_failed_batch(batch)
                        return {
                            "sent": total_sent,
                            "status": "failed",
                            "error": str(exc),
                        }
                    time.sleep(min(2 ** attempt, 10))

        return {
            "sent": total_sent,
            "status": "ok",
            "response": last_response,
        }

    def _requeue_failed_batch(self, batch: List[Dict[str, Any]]) -> None:
        failed_path = self.config.source_path.with_suffix(".failed.jsonl")
        for event in batch:
            _append_jsonl(failed_path, event)


def build_forwarder_from_env() -> AgentEventForwarder:
    source_path = Path(os.getenv("AGENT_EVENTS_PATH", "./data/state/agent_events.jsonl"))
    cursor_path = Path(os.getenv("AGENT_CURSOR_PATH", "./data/state/agent_cursor.json"))
    target_url = os.getenv("AGENT_SOURCE_URL", "")
    if not target_url:
        raise ValueError("AGENT_SOURCE_URL is required to run the machine-2 forwarder")

    return AgentEventForwarder(
        ForwarderConfig(
            source_path=source_path,
            cursor_path=cursor_path,
            target_url=target_url,
            api_key=os.getenv("AGENT_SOURCE_API_KEY", ""),
            verify_ssl=os.getenv("AGENT_SOURCE_VERIFY_SSL", "true").lower() == "true",
            batch_size=int(os.getenv("AGENT_FORWARD_BATCH_SIZE", "100")),
            poll_interval=int(os.getenv("AGENT_FORWARD_POLL_INTERVAL", "15")),
            timeout=int(os.getenv("AGENT_FORWARD_TIMEOUT", "30")),
            max_retries=int(os.getenv("AGENT_FORWARD_MAX_RETRIES", "3")),
        )
    )


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    forwarder = build_forwarder_from_env()
    logger.info("Starting machine-2 forwarder for %s", forwarder.config.target_url)

    while True:
        result = forwarder.flush_once()
        logger.info("Forwarder cycle result: %s", result)
        time.sleep(max(1, forwarder.config.poll_interval))


if __name__ == "__main__":
    main()