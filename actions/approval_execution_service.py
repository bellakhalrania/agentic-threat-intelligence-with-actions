"""Remote execution of a single human-approved response action."""

from typing import Any, Dict

from actions.action_models import ProposedAction
from actions.remote_push import RemotePushError, push_script_to_remote, verify_remote_connection
from agents.execution_translation_agent import ExecutionTranslationAgent
from config import config, get_protected_management_ips


def execute_approved_action(
    action: ProposedAction,
    campaign_id: str,
) -> Dict[str, Any]:
    """Translate and push exactly one approved action to the Remote Agent.

    This intentionally has no local connector fallback. A reviewer approval is
    an authorization to execute on the configured remote target, not on the
    manager/API host.
    """
    if not config.REMOTE_AGENT_ENABLED:
        return {
            "status": "remote_push_failed",
            "detail": "Remote execution is disabled (REMOTE_AGENT_ENABLED=false).",
            "metadata": {},
        }
    if not config.REMOTE_AGENT_URL:
        return {
            "status": "remote_push_failed",
            "detail": "Remote execution URL is not configured.",
            "metadata": {},
        }

    if action.action_type == "block_ip":
        protected_ips = get_protected_management_ips()
        if action.target in protected_ips:
            return {
                "status": "denied",
                "detail": f"Rejected: target {action.target} matches a protected management/SSH IP.",
                "metadata": {
                    "platform": config.APPROVAL_REMOTE_PLATFORM,
                    "protected_target": True,
                    "protected_ips": sorted(protected_ips),
                },
            }

    platform = config.APPROVAL_REMOTE_PLATFORM
    translation = ExecutionTranslationAgent().run(
        actions_taken=[{"action": action.model_dump(), "status": "executed"}],
        platform=platform,
    )
    packages = translation.get("execution_packages", [])
    script = translation.get("combined_script", "")
    filename = translation.get("combined_filename", "")
    if not packages or not script:
        return {
            "status": "remote_push_failed",
            "detail": "Could not generate a remote execution package for the approved action.",
            "metadata": {"platform": platform},
        }

    if not verify_remote_connection(
        remote_url=config.REMOTE_AGENT_URL,
        api_key=config.REMOTE_AGENT_API_KEY,
    ):
        return {
            "status": "remote_push_failed",
            "detail": f"Remote agent health check failed for {config.REMOTE_AGENT_URL}.",
            "metadata": {"platform": platform, "remote_url": config.REMOTE_AGENT_URL},
        }

    try:
        remote_result = push_script_to_remote(
            script=script,
            filename=filename,
            campaign_id=campaign_id,
            action_count=1,
            platform=platform,
            remote_url=config.REMOTE_AGENT_URL,
            api_key=config.REMOTE_AGENT_API_KEY,
            hmac_secret=config.REMOTE_AGENT_HMAC_SECRET,
            timeout=config.REMOTE_AGENT_TIMEOUT,
            execution_packages=packages,
        )
    except RemotePushError as exc:
        return {
            "status": "remote_push_failed",
            "detail": str(exc),
            "metadata": {"platform": platform, "remote_url": config.REMOTE_AGENT_URL},
        }

    metadata = {
        "platform": platform,
        "remote_url": config.REMOTE_AGENT_URL,
        "remote_execution_id": remote_result.get("execution_id", ""),
        "remote_status": remote_result.get("status", ""),
        "remote_exit_code": remote_result.get("exit_code"),
    }
    succeeded = (
        remote_result.get("success") is True
        and remote_result.get("status") == "completed"
        and remote_result.get("exit_code") == 0
    )
    if succeeded:
        return {
            "status": "executed_remote",
            "detail": (
                "Remote script completed successfully "
                f"(execution_id={remote_result.get('execution_id', 'unknown')})."
            ),
            "metadata": metadata,
        }

    error = remote_result.get("error") or remote_result.get("stderr") or "Remote script did not complete successfully."
    return {
        "status": "remote_execution_failed",
        "detail": str(error)[:2000],
        "metadata": metadata,
    }
