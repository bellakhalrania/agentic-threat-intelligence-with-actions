"""
actions/action_models.py
Defines the action types the platform can take, and the safety policy that
governs whether an action auto-executes or requires human approval.

DESIGN PRINCIPLE: the LLM never executes anything directly. It only ever
proposes a structured Action object. A separate, deterministic policy layer
decides whether that action is allowed to run automatically.
"""

from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Optional
from uuid import uuid4


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    NOTIFY_ANALYST = "notify_analyst"  # always safe, never needs approval


class ActionSeverity(str, Enum):
    LOW = "low"        # reversible, low blast radius (e.g. notify, tag)
    MEDIUM = "medium"  # reversible but disruptive (e.g. block IP, disable account)
    HIGH = "high"      # disruptive + hard to reverse fast (e.g. isolate host)


class ProposedAction(BaseModel):
    action_type: ActionType
    target: str                      # IP, hostname, username, process id, file hash
    severity: ActionSeverity
    rationale: str
    technique_id: Optional[str] = None   # which ATT&CK technique triggered this
    confidence: float = 0.0
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_factors: List[str] = Field(default_factory=list)
    risk_version: str = ""


class ActionResult(BaseModel):
    # Stable identifier links the initial proposal, reviewer decision, and
    # final execution result in the append-only audit log.
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    action: ProposedAction
    status: str            # "executed" | "skipped_low_confidence" | "pending_approval" | "denied" | "failed"
    detail: str = ""
    dry_run: bool = True
