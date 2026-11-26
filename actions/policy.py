"""
actions/policy.py
The safety gate. This is intentionally NOT LLM-driven - it's plain,
auditable Python logic, because "should we auto-execute a disruptive action"
is exactly the kind of decision that should never depend on a model's
non-deterministic judgment alone.

Rules, in order:
1. Analyst notifications are always attempted immediately.
2. Global kill switch (config.AUTO_RESPONSE_ENABLED) can disable disruptive
   auto-execution instantly, platform-wide.
3. Per-target allowlist/denylist - some hosts/accounts (e.g. domain
   controllers, the CEO's account) should NEVER be auto-actioned.
4. Deterministic risk threshold - only observed evidence contributes.
5. Explicit auto-executable action types and isolation target allowlists.
6. Rate limiting - cap actions per host per hour to prevent a feedback loop
   (e.g. a misfiring detection isolating the same host repeatedly).
"""

import time
from collections import defaultdict
from actions.action_models import ProposedAction, ActionType
from config import config, is_protected_target

_action_history = defaultdict(list)  # target -> [timestamps]


def _rate_limit_exceeded(target: str) -> bool:
    now = time.time()
    window_start = now - 3600
    _action_history[target] = [t for t in _action_history[target] if t > window_start]
    return len(_action_history[target]) >= config.MAX_AUTO_ACTIONS_PER_TARGET_PER_HOUR


def evaluate(action: ProposedAction) -> str:
    """Returns one of: 'auto_execute', 'pending_approval', 'denied'."""

    # Notification bypasses the disruptive-action kill switch and risk gate,
    # but connector failures are still recorded as failures.
    if action.action_type == ActionType.NOTIFY_ANALYST:
        return "auto_execute"

    if is_protected_target(action.target):
        return "denied"

    if not config.AUTO_RESPONSE_ENABLED:
        return "pending_approval"  # kill switch off -> everything needs a human

    if action.action_type.value not in config.AUTO_EXECUTE_ACTIONS:
        return "pending_approval"

    # The requirement is strictly greater than the configured threshold.
    if action.risk_score <= config.AUTO_RISK_THRESHOLD:
        return "pending_approval"

    if (
        config.SAFE_MODE_ENFORCED
        and action.action_type == ActionType.ISOLATE_HOST
        and action.target not in config.APPROVED_ISOLATION_TARGETS
    ):
        return "pending_approval"

    if _rate_limit_exceeded(action.target):
        return "pending_approval"

    _action_history[action.target].append(time.time())
    return "auto_execute"
