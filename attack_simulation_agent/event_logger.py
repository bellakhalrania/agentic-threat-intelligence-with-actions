from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

import requests

from .config import Settings
from .models import SimulationEvent

logger = logging.getLogger(__name__)


class EventLogger:
    """Append sanitized events locally, then optionally forward to Machine 3."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.Lock()

    def write(self, event: SimulationEvent) -> SimulationEvent:
        self.settings.event_log.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.settings.event_log.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")
        return event

    def forward(self, event: SimulationEvent) -> bool:
        if not self.settings.webhook_url:
            return False
        headers = {"Content-Type": "application/json"}
        if self.settings.webhook_key:
            headers["X-Agent-Key"] = self.settings.webhook_key
        try:
            # The platform's existing remote forwarder uses this envelope.
            response = requests.post(
                self.settings.webhook_url,
                json={"events": [event.model_dump(mode="json")]},
                headers=headers,
                timeout=self.settings.webhook_timeout_seconds,
                verify=self.settings.webhook_verify_ssl,
            )
            response.raise_for_status()
            return True
        except requests.RequestException as exc:
            # Forwarding failure must never hide the local attack result.
            logger.warning("Event forwarding failed: %s", exc)
            return False
