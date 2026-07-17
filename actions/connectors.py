"""
actions/connectors.py
One function per action type. These are stubs — replace the body of each
with a real API call to your firewall, EDR, or identity provider. Every
function respects config.DRY_RUN: when true, it logs the intended action
instead of calling anything real.

Examples of what you'd plug in here:
  - block_ip          -> Palo Alto / Fortinet / pfSense API, or a cloud
                         security-group rule (AWS/Azure/GCP)
  - isolate_host       -> CrowdStrike Falcon, SentinelOne, Defender for
                         Endpoint "isolate device" API
  - disable_account    -> Active Directory (via pyad/ldap3), Okta, Entra ID
  - kill_process       -> EDR API "kill process" action (rarely safe to
                         automate without isolation first)
  - quarantine_file     -> EDR API "quarantine file" action
"""

from config import config


def _log_action(action_type: str, target: str, detail: str = "") -> str:
    prefix = "[DRY RUN] " if config.DRY_RUN else "[EXECUTED] "
    message = f"{prefix}{action_type} -> {target} {detail}".strip()
    print(message)
    return message


def block_ip(ip_address: str) -> str:
    if config.DRY_RUN:
        return _log_action("BLOCK_IP", ip_address)

    # --- Replace with a real firewall API call, e.g.: ---
    # response = requests.post(
    #     f"{FIREWALL_API_URL}/rules",
    #     json={"action": "deny", "destination": ip_address},
    #     headers={"Authorization": f"Bearer {FIREWALL_API_TOKEN}"},
    # )
    # response.raise_for_status()
    return _log_action("BLOCK_IP", ip_address, "(no real connector configured)")


def isolate_host(hostname: str) -> str:
    if config.DRY_RUN:
        return _log_action("ISOLATE_HOST", hostname)

    # --- Replace with a real EDR isolate-device API call ---
    return _log_action("ISOLATE_HOST", hostname, "(no real connector configured)")


def disable_account(username: str) -> str:
    if config.DRY_RUN:
        return _log_action("DISABLE_ACCOUNT", username)

    # --- Replace with a real AD/IAM disable-user API call ---
    return _log_action("DISABLE_ACCOUNT", username, "(no real connector configured)")


def kill_process(process_ref: str) -> str:
    if config.DRY_RUN:
        return _log_action("KILL_PROCESS", process_ref)

    # --- Replace with a real EDR kill-process API call ---
    return _log_action("KILL_PROCESS", process_ref, "(no real connector configured)")


def quarantine_file(file_hash: str) -> str:
    if config.DRY_RUN:
        return _log_action("QUARANTINE_FILE", file_hash)

    # --- Replace with a real EDR quarantine-file API call ---
    return _log_action("QUARANTINE_FILE", file_hash, "(no real connector configured)")


def notify_analyst(message: str) -> str:
    # Always "executes" — replace with Slack/Teams/PagerDuty webhook.
    return _log_action("NOTIFY_ANALYST", "", message)


ACTION_DISPATCH = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "disable_account": disable_account,
    "kill_process": kill_process,
    "quarantine_file": quarantine_file,
    "notify_analyst": notify_analyst,
}
