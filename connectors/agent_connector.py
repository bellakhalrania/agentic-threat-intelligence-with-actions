"""
connectors/agent_connector.py
Connector for ingesting telemetry from a custom agent on machine 2.

Supports two practical transport modes:
1. HTTP polling from an agent endpoint
2. Local JSON or JSONL spool file written by the agent
"""

import hashlib
import json
import logging
import os
from typing import Dict, List, Optional

import requests

from config import config
from connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class AgentConnector(BaseConnector):
    """Connector for a custom machine-2 agent feed."""

    def __init__(
        self,
        source_url: Optional[str] = None,
        events_path: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        cursor_path: Optional[str] = None,
        fetch_limit: Optional[int] = None,
    ):
        self.source_url = source_url or config.AGENT_SOURCE_URL
        self.events_path = events_path or config.AGENT_EVENTS_PATH
        self.api_key = api_key or config.AGENT_SOURCE_API_KEY
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.AGENT_SOURCE_VERIFY_SSL
        self.cursor_path = cursor_path or config.AGENT_CURSOR_PATH
        self.fetch_limit = fetch_limit if fetch_limit is not None else config.AGENT_FETCH_LIMIT

        self._last_timestamp: Optional[str] = None
        self._processed_event_ids: set[str] = set()
        self._processed_order: List[str] = []

        self._load_cursor()

    def fetch_events(self) -> List[Dict]:
        if self.source_url:
            events = self._fetch_from_api()
        else:
            events = self._fetch_from_file()

        self._save_cursor()
        return events

    def get_last_event_timestamp(self) -> Optional[str]:
        return self._last_timestamp

    def reset_state(self) -> None:
        self._last_timestamp = None
        self._processed_event_ids.clear()
        self._processed_order.clear()
        if self.cursor_path and os.path.exists(self.cursor_path):
            try:
                os.remove(self.cursor_path)
            except OSError:
                logger.warning("Failed to remove agent cursor file: %s", self.cursor_path)

    def _fetch_from_api(self) -> List[Dict]:
        if not self.source_url:
            return []

        url = self.source_url.rstrip("/")
        if not url.endswith("/agent/latest") and not url.endswith("/agent/events"):
            url = f"{url}/agent/latest"

        headers = {}
        if self.api_key:
            headers["X-Agent-Key"] = self.api_key

        params = {"limit": self.fetch_limit}
        if self._last_timestamp:
            params["since"] = self._last_timestamp

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30, verify=self.verify_ssl)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            logger.error("Error fetching agent events from %s: %s", url, exc)
            return []
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON from agent endpoint %s: %s", url, exc)
            return []

        events = self._extract_events(payload)
        return self._filter_new_events(events)

    def _fetch_from_file(self) -> List[Dict]:
        if not self.events_path or not os.path.exists(self.events_path):
            logger.warning("Agent events file not found: %s", self.events_path)
            return []

        try:
            with open(self.events_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
        except OSError as exc:
            logger.error("Error reading agent events file %s: %s", self.events_path, exc)
            return []

        if not content:
            return []

        events: List[Dict] = []
        if content.startswith("["):
            try:
                parsed = json.loads(content)
                if isinstance(parsed, list):
                    events.extend(item for item in parsed if isinstance(item, dict))
            except json.JSONDecodeError:
                logger.warning("Failed to parse agent file as JSON array, falling back to JSONL")

        if not events:
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid agent event line: %s", line[:120])
                    continue
                if isinstance(item, dict):
                    if isinstance(item.get("events"), list):
                        events.extend(e for e in item["events"] if isinstance(e, dict))
                    else:
                        events.append(item)

        return self._filter_new_events(events)

    def _extract_events(self, payload: object) -> List[Dict]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if isinstance(payload, dict):
            if isinstance(payload.get("events"), list):
                return [item for item in payload["events"] if isinstance(item, dict)]
            if isinstance(payload.get("data"), list):
                return [item for item in payload["data"] if isinstance(item, dict)]
            if isinstance(payload.get("event"), dict):
                return [payload["event"]]
            return [payload]

        return []

    def _filter_new_events(self, events: List[Dict]) -> List[Dict]:
        new_events: List[Dict] = []
        for event in events:
            event_id = self._event_id(event)
            timestamp = event.get("timestamp") or event.get("received_at") or event.get("observed_at")

            if event_id in self._processed_event_ids:
                continue
            if self._last_timestamp and timestamp and timestamp <= self._last_timestamp:
                continue

            new_events.append(event)
            if event_id:
                self._remember_processed_id(event_id)
            if timestamp and (self._last_timestamp is None or timestamp > self._last_timestamp):
                self._last_timestamp = timestamp

        return new_events

    def _event_id(self, event: Dict) -> str:
        raw_id = event.get("event_id") or event.get("id")
        if raw_id:
            return str(raw_id)
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _remember_processed_id(self, event_id: str) -> None:
        if event_id in self._processed_event_ids:
            return
        self._processed_event_ids.add(event_id)
        self._processed_order.append(event_id)
        if self.fetch_limit > 0 and len(self._processed_order) > max(self.fetch_limit * 20, 1000):
            to_drop = self._processed_order[:-self.fetch_limit * 10]
            self._processed_order = self._processed_order[-self.fetch_limit * 10 :]
            for stale_id in to_drop:
                self._processed_event_ids.discard(stale_id)

    def _load_cursor(self) -> None:
        if not self.cursor_path or not os.path.exists(self.cursor_path):
            return

        try:
            with open(self.cursor_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load agent cursor %s: %s", self.cursor_path, exc)
            return

        self._last_timestamp = data.get("last_timestamp")
        ids = data.get("processed_event_ids") or []
        if not isinstance(ids, list):
            ids = []

        self._processed_order = [str(item) for item in ids if item]
        self._processed_event_ids = set(self._processed_order)

    def _save_cursor(self) -> None:
        if not self.cursor_path:
            return

        os.makedirs(os.path.dirname(self.cursor_path), exist_ok=True)
        data = {
            "last_timestamp": self._last_timestamp,
            "processed_event_ids": self._processed_order[-max(self.fetch_limit * 10, 1000):],
        }
        try:
            with open(self.cursor_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError as exc:
            logger.warning("Failed to save agent cursor %s: %s", self.cursor_path, exc)