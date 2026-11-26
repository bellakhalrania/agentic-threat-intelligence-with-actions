from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from .config import Settings
from .event_logger import EventLogger
from .models import SimulationEvent, SimulationStatus
from .scenarios import SSHBruteForceScenario


class SimulationManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = EventLogger(settings)
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._current: SimulationStatus | None = None

    def status(self) -> SimulationStatus | None:
        with self._lock:
            return self._current

    def start(self) -> SimulationStatus:
        self.settings.validate()
        with self._lock:
            if self._current and self._current.status == "running":
                raise RuntimeError("A simulation is already running")
            current = SimulationStatus(
                simulation_id=f"attack-{uuid.uuid4().hex[:12]}", status="running",
                started_at=datetime.now(timezone.utc), detail="Scenario accepted by policy",
            )
            self._current = current
        threading.Thread(target=self._execute, args=(current,), daemon=True).start()
        return current

    def stop(self) -> bool:
        with self._lock:
            process, current = self._process, self._current
        if not process or process.poll() is not None or not current or current.status != "running":
            return False
        os.killpg(process.pid, signal.SIGTERM)
        return True

    def _set_process(self, process: subprocess.Popen[bytes] | None) -> None:
        with self._lock:
            self._process = process

    def _execute(self, status: SimulationStatus) -> None:
        started = time.monotonic()
        event_status, exit_code, detail = "failed", None, "Scenario did not start"
        try:
            event_status, exit_code, detail = SSHBruteForceScenario(self.settings).run(self._set_process)
        except Exception as exc:  # Errors become an auditable event, never a traceback to the caller.
            detail = str(exc)
        duration_ms = int((time.monotonic() - started) * 1000)
        with self._lock:
            stopped = status.status == "stopped"
        if stopped:
            event_status, detail = "stopped", "Simulation stopped by local control request"
        event = SimulationEvent(
            simulation_id=status.simulation_id, target=self.settings.target, status=event_status,
            timestamp=datetime.now(timezone.utc), dry_run=self.settings.dry_run,
            attempts_limit=self.settings.max_attempts, duration_ms=duration_ms,
            exit_code=exit_code, error=None if event_status in {"completed", "dry_run"} else detail,
        )
        self.logger.write(event)
        forwarded = self.logger.forward(event)
        # Record forwarding disposition locally without sending an additional event.
        event.forwarded = forwarded
        self.logger.write(event)
        with self._lock:
            status.status = event_status
            status.completed_at = datetime.now(timezone.utc)
            status.detail = detail
            self._process = None
