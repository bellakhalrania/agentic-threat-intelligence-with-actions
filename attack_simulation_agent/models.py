from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class SimulationEvent(BaseModel):
    simulation_id: str
    source: Literal["attack_simulation_agent"] = "attack_simulation_agent"
    attack_type: Literal["ssh_bruteforce"] = "ssh_bruteforce"
    mitre_technique: Literal["T1110.001"] = "T1110.001"
    target: str
    status: Literal["running", "completed", "failed", "stopped", "dry_run"]
    timestamp: datetime
    dry_run: bool
    attempts_limit: int
    duration_ms: int | None = None
    exit_code: int | None = None
    error: str | None = None
    forwarded: bool = False


class SimulationStatus(BaseModel):
    simulation_id: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    detail: str = Field(default="")
