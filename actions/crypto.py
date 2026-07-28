"""
actions/crypto.py
=================
Cryptographic utilities for securing the push communication between
Machine 1 (Threat Intel Platform) and Machine 2 (Remote Response Agent).

Provides:
  - HMAC-SHA256 signing of payloads
  - Timestamp + nonce generation and verification (replay protection)
  - Action whitelist validation
"""

import os
import json
import time
import hmac
import hashlib
import base64
import uuid
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Default replay protection window (seconds)
DEFAULT_REPLAY_WINDOW = 300  # 5 minutes

# Allowed action types that can appear in a response script
ALLOWED_ACTION_TYPES = {
    "block_ip",
    "isolate_host",
    "disable_account",
    "kill_process",
    "quarantine_file",
    "notify_analyst",
}

# Shell commands that are ALWAYS forbidden regardless of action type
FORBIDDEN_COMMANDS = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs.",
    "dd if=",
    "> /dev/sd",
    ":(){ :|:& };:",  # fork bomb
    "chmod -R 000 /",
    "chown -R 0:0 /",
    "wget http://",
    "curl http://",
    "bash -c '",
    "python -c '",
    "eval ",
    "exec ",
]


def generate_nonce() -> str:
    """Generate a unique nonce for replay protection."""
    return str(uuid.uuid4())


def current_timestamp() -> int:
    """Get current Unix timestamp in seconds."""
    return int(time.time())


def sign_payload(
    payload: Dict[str, Any],
    secret_key: str,
) -> str:
    """
    Sign a payload dict with HMAC-SHA256 using the shared secret key.

    The signature is computed over the canonical JSON representation of
    the payload (sorted keys, no whitespace) to ensure deterministic output.

    Args:
        payload: The dict to sign (must be JSON-serializable).
        secret_key: The shared HMAC secret key.

    Returns:
        Base64-encoded HMAC-SHA256 signature string.
    """
    # Canonical JSON: sorted keys, no extra whitespace
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(
        secret_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    )
    return base64.b64encode(mac.digest()).decode("utf-8")


def verify_signature(
    payload: Dict[str, Any],
    signature: str,
    secret_key: str,
) -> bool:
    """
    Verify an HMAC-SHA256 signature against a payload.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        payload: The original payload dict.
        signature: The Base64-encoded signature to verify.
        secret_key: The shared HMAC secret key.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected = sign_payload(payload, secret_key)
    # Constant-time comparison
    return hmac.compare_digest(expected, signature)


def verify_replay_protection(
    payload_timestamp: int,
    nonce: str,
    seen_nonces: set,
    window: int = DEFAULT_REPLAY_WINDOW,
) -> bool:
    """
    Verify that a request is not a replay attack.

    Checks:
      1. The timestamp is within the allowed window (default 5 minutes).
      2. The nonce has not been seen before.

    Args:
        payload_timestamp: Unix timestamp from the payload.
        nonce: Unique nonce string from the payload.
        seen_nonces: Set of previously seen nonces (caller maintains this).
        window: Allowed time window in seconds.

    Returns:
        True if the request is fresh, False if it's a replay or expired.
    """
    now = current_timestamp()

    # Check timestamp bounds
    if payload_timestamp < now - window:
        logger.warning(f"Replay check failed: timestamp too old "
                       f"({payload_timestamp} vs now {now}, window {window}s)")
        return False

    if payload_timestamp > now + window:
        logger.warning(f"Replay check failed: timestamp in the future "
                       f"({payload_timestamp} vs now {now})")
        return False

    # Check nonce uniqueness
    if nonce in seen_nonces:
        logger.warning(f"Replay check failed: duplicate nonce {nonce}")
        return False

    return True


def validate_action_whitelist(
    script: str,
    allowed_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Validate that a script only contains whitelisted actions.

    This parses the script for known action patterns and checks them
    against the allowed action list. It also scans for forbidden commands.

    Args:
        script: The script content to validate.
        allowed_actions: List of allowed action type strings.
                         Defaults to ALLOWED_ACTION_TYPES.

    Returns:
        Dict with:
          - "valid": bool
          - "detected_actions": list of action types found
          - "forbidden_commands": list of forbidden commands found
          - "reason": str (if invalid)
    """
    if allowed_actions is None:
        allowed_actions = list(ALLOWED_ACTION_TYPES)

    allowed_set = set(allowed_actions)
    result = {
        "valid": True,
        "detected_actions": [],
        "forbidden_commands": [],
        "reason": "",
    }

    # Detect action types from the script content
    # Each action function is named action_N and has a comment with the action type
    for action_type in ALLOWED_ACTION_TYPES:
        # Look for patterns like "# Action 1: block_ip" or "action_type == 'block_ip'"
        if action_type in script.lower():
            result["detected_actions"].append(action_type)

    # Check that all detected actions are in the whitelist
    for detected in result["detected_actions"]:
        if detected not in allowed_set:
            result["valid"] = False
            result["reason"] = (
                f"Action type '{detected}' is not in the allowed whitelist. "
                f"Allowed: {sorted(allowed_set)}"
            )
            return result

    # Scan for forbidden commands
    script_lower = script.lower()
    for forbidden in FORBIDDEN_COMMANDS:
        if forbidden.lower() in script_lower:
            result["valid"] = False
            result["forbidden_commands"].append(forbidden)
            result["reason"] = f"Script contains forbidden command: {forbidden}"
            return result

    # If no actions were detected but the script is non-empty, flag it
    if not result["detected_actions"] and script.strip():
        # This might be a valid script with custom actions, allow it but log a warning
        logger.warning("No known action types detected in script. "
                       "Proceeding but this may be a custom script.")

    return result


def build_signed_payload(
    script: str,
    filename: str,
    campaign_id: str,
    action_count: int,
    platform: str,
    secret_key: str,
    execution_packages: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Build a complete signed payload with replay protection.

    This is the main function called by the push client to prepare
    a secure request to the remote agent.

    Args:
        script: The executable script content.
        filename: The script filename.
        campaign_id: Campaign identifier.
        action_count: Number of actions in the script.
        platform: Target platform.
        secret_key: The shared HMAC secret key.
        execution_packages: Optional list of execution package dicts for
                            action whitelist validation on the remote side.

    Returns:
        A dict ready to be sent as JSON to the remote agent, containing:
          - script, filename, campaign_id, action_count, platform
          - timestamp, nonce
          - signature
          - execution_packages (if provided)
    """
    nonce = generate_nonce()
    ts = current_timestamp()

    payload = {
        "script": script,
        "filename": filename,
        "campaign_id": campaign_id,
        "action_count": action_count,
        "platform": platform,
        "timestamp": ts,
        "nonce": nonce,
    }

    if execution_packages:
        # Include only the action_type from each package for validation
        payload["action_types"] = [
            pkg.get("action_type", "unknown")
            for pkg in execution_packages
        ]

    signature = sign_payload(payload, secret_key)
    payload["signature"] = signature

    return payload