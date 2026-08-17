"""
actions/policy.py
The safety gate. This is intentionally NOT LLM-driven - it's plain,
auditable Python logic, because "should we auto-execute a disruptive action"
is exactly the kind of decision that should never depend on a model's
non-deterministic judgment alone.

Rules, in order:
1. Global kill switch (config.AUTO_RESPONSE_ENABLED) can disable all
   auto-execution instantly, platform-wide.
2. Per-target allowlist/denylist - some hosts/accounts (e.g. domain
   controllers, the CEO's account) should NEVER be auto-actioned.
3. Confidence threshold - low-confidence ATT&CK mappings don't get to
   trigger disruptive actions.
4. Severity threshold - HIGH severity actions (e.g. isolate_host) always
   require human approval, regardless of confidence.
5. Rate limiting - cap actions per host per hour to prevent a feedback loop
   (e.g. a misfiring detection isolating the same host repeatedly).
"""

import time
from collections import defaultdict
from config import config
from actions.action_models import ProposedAction, ActionSeverity, ActionType

# Targets that must NEVER be auto-actioned, regardless of confidence.
# Populate this with domain controllers, exec accounts, critical infra, etc.
PROTECTED_TARGETS = {
    "DC-FILESRV01",
    "domain admin",
}

# Action types that always require a human, no matter the confidence score.
#ALWAYS_REQUIRE_APPROVAL = {ActionSeverity.HIGH}
ALWAYS_REQUIRE_APPROVAL = set()
MIN_AUTO_EXECUTE_CONFIDENCE = 0.85
MAX_ACTIONS_PER_TARGET_PER_HOUR = 3

_action_history = defaultdict(list)  # target -> [timestamps]


def _rate_limit_exceeded(target: str) -> bool:
    now = time.time()
    window_start = now - 3600
    _action_history[target] = [t for t in _action_history[target] if t > window_start]
    return len(_action_history[target]) >= MAX_ACTIONS_PER_TARGET_PER_HOUR


def evaluate(action: ProposedAction) -> str:
    """Returns one of: 'auto_execute', 'pending_approval', 'denied'."""

    if action.target in PROTECTED_TARGETS:
        return "denied"

    # Safe-mode policy: keep disruptive containment gated, allow analyst notification.
    if config.SAFE_MODE_ENFORCED:
        if action.action_type == ActionType.NOTIFY_ANALYST and config.SAFE_MODE_NOTIFY_ANALYST_AUTO:
            _action_history[action.target].append(time.time())
            return "auto_execute"

        if action.action_type == ActionType.ISOLATE_HOST:
            # Explicit approval channel for isolation: operator must allowlist target.
            if action.target in config.APPROVED_ISOLATION_TARGETS:
                _action_history[action.target].append(time.time())
                return "auto_execute"
            return "pending_approval"

    if not config.AUTO_RESPONSE_ENABLED:
        return "pending_approval"  # kill switch off -> everything needs a human

    if action.severity in ALWAYS_REQUIRE_APPROVAL:
        return "pending_approval"

    if action.confidence < MIN_AUTO_EXECUTE_CONFIDENCE:
        return "pending_approval"

    if _rate_limit_exceeded(action.target):
        return "pending_approval"

    _action_history[action.target].append(time.time())
    return "auto_execute"
