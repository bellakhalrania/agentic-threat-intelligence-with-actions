"""
actions/connectors.py
One function per action type. Each function simulates a real API call to a
firewall, EDR, or identity provider with proper logging, error handling, and
structured responses. Every function respects config.DRY_RUN: when true, it
logs the intended action instead of calling anything real.

When you're ready to connect to real infrastructure, replace the simulated
logic in each function with the actual API call. Examples of what you'd plug in:
  - block_ip          -> Palo Alto / Fortinet / pfSense API, or a cloud
                          security-group rule (AWS/Azure/GCP)
  - isolate_host       -> CrowdStrike Falcon, SentinelOne, Defender for
                          Endpoint "isolate device" API
  - disable_account    -> Active Directory (via pyad/ldap3), Okta, Entra ID
  - kill_process       -> EDR API "kill process" action (rarely safe to
                          automate without isolation first)
  - quarantine_file     -> EDR API "quarantine file" action
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from actions.notifier_email import send_notify_analyst_email
from config import config

logger = logging.getLogger(__name__)


def _build_result(
    action_type: str,
    target: str,
    status: str,
    detail: str,
    duration_ms: Optional[float] = None,
) -> dict:
    """Build a structured result dict for every connector action."""
    return {
        "action_type": action_type,
        "target": target,
        "status": status,
        "detail": detail,
        "dry_run": config.DRY_RUN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
    }


def _simulate_api_call(action_type: str, target: str, success: bool = True) -> dict:
    """Simulate an API call with timing and structured output.

    In production, replace this with the actual API call. The structured
    result format remains the same regardless of DRY_RUN mode.
    """
    import time

    start = time.time()
    # Simulate network latency (50-300ms)
    time.sleep(0.05)

    if config.DRY_RUN:
        detail = f"[DRY RUN] Would execute {action_type} on {target}"
        logger.info(detail)
        return _build_result(action_type, target, "simulated", detail, time.time() - start)

    if not success:
        duration = time.time() - start
        detail = f"API call to {action_type} on {target} failed: simulated service unavailable"
        logger.error(detail)
        return _build_result(action_type, target, "failed", detail, duration)

    duration = time.time() - start
    detail = f"Successfully executed {action_type} on {target}"
    logger.info(detail)
    return _build_result(action_type, target, "executed", detail, duration)


def block_ip(ip_address: str) -> str:
    """Block an IP address at the perimeter firewall.

    Simulates adding a firewall rule to deny traffic to/from the given IP.
    Replace with a real firewall API call, e.g.:
        response = requests.post(
            f"{FIREWALL_API_URL}/rules",
            json={"action": "deny", "destination": ip_address},
            headers={"Authorization": f"Bearer {FIREWALL_API_TOKEN}"},
        )
        response.raise_for_status()
    """
    result = _simulate_api_call("block_ip", ip_address)
    return json.dumps(result)


def isolate_host(hostname: str) -> str:
    """Isolate a host from the network via EDR.

    Simulates an EDR isolate-device API call. In production, replace with:
        response = requests.post(
            f"{EDR_API_URL}/devices/{hostname}/isolate",
            headers={"Authorization": f"Bearer {EDR_API_TOKEN}"},
        )
        response.raise_for_status()
    """
    result = _simulate_api_call("isolate_host", hostname)
    return json.dumps(result)


def disable_account(username: str) -> str:
    """Disable a user account in the identity provider.

    Simulates an AD/IAM disable-user API call. In production, replace with:
        # LDAP example
        conn = ldap3.Connection(AD_SERVER, user=AD_USER, password=AD_PASSWORD)
        conn.modify(f"CN={username},CN=Users,DC=corp,DC=local",
                     {"userAccountControl": (ldap3.MODIFY_REPLACE, [514])})
    """
    result = _simulate_api_call("disable_account", username)
    return json.dumps(result)


def kill_process(process_ref: str) -> str:
    """Kill a process on an endpoint via EDR.

    Simulates an EDR kill-process API call. In production, replace with:
        response = requests.post(
            f"{EDR_API_URL}/endpoints/{hostname}/processes/{pid}/kill",
            headers={"Authorization": f"Bearer {EDR_API_TOKEN}"},
        )
        response.raise_for_status()
    """
    result = _simulate_api_call("kill_process", process_ref)
    return json.dumps(result)


def quarantine_file(file_hash: str) -> str:
    """Quarantine a file by hash via EDR.

    Simulates an EDR quarantine-file API call. In production, replace with:
        response = requests.post(
            f"{EDR_API_URL}/files/{file_hash}/quarantine",
            headers={"Authorization": f"Bearer {EDR_API_TOKEN}"},
        )
        response.raise_for_status()
    """
    result = _simulate_api_call("quarantine_file", file_hash)
    return json.dumps(result)


def notify_analyst(message: str) -> str:
    """Send analyst notification by SMTP email (real delivery when DRY_RUN=false)."""
    if config.DRY_RUN:
        result = _simulate_api_call("notify_analyst", message, success=True)
        return json.dumps(result)

    start = time.time()
    send_result = send_notify_analyst_email(target="SOC Team", message=message)
    duration = time.time() - start

    if send_result.get("sent"):
        detail = send_result.get("detail", "Email notification sent")
        result = _build_result("notify_analyst", message, "executed", detail, duration)
        logger.info(detail)
        return json.dumps(result)

    detail = send_result.get("detail", "Email notification failed")
    result = _build_result("notify_analyst", message, "failed", detail, duration)
    logger.error(detail)
    return json.dumps(result)


ACTION_DISPATCH = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "disable_account": disable_account,
    "kill_process": kill_process,
    "quarantine_file": quarantine_file,
    "notify_analyst": notify_analyst,
}