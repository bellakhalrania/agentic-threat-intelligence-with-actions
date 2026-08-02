"""
actions/remote_push.py
======================
Push client (Machine 1 side).

Sends cryptographically signed response scripts to the Remote Response
Agent running on the target machine (Machine 2) for execution. Returns
the execution result.

Security features:
  - HMAC-SHA256 digital signature of every payload
  - Timestamp + nonce to prevent replay attacks
  - Action whitelist validation on both sides
  - Bearer token authentication

This module is called by the execution_translation_node after the script
has been generated and saved locally.
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List

import requests

from actions.crypto import build_signed_payload

logger = logging.getLogger(__name__)


class RemotePushError(Exception):
    """Raised when pushing a script to the remote agent fails."""
    pass


def push_script_to_remote(
    script: str,
    filename: str,
    campaign_id: str = "",
    action_count: int = 0,
    platform: str = "linux",
    remote_url: Optional[str] = None,
    api_key: Optional[str] = None,
    hmac_secret: Optional[str] = None,
    timeout: int = 3600,
    execution_packages: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Push a cryptographically signed response script to the Remote Response
    Agent (Machine 2).

    The payload includes:
      - The script content, filename, campaign metadata
      - A unique nonce + timestamp for replay protection
      - An HMAC-SHA256 signature over the entire payload
      - The list of action types for whitelist validation

    Args:
        script: The executable script content.
        filename: The script filename.
        campaign_id: Campaign identifier for audit trail.
        action_count: Number of actions in the script.
        platform: Target platform.
        remote_url: Full URL of the remote agent's /execute endpoint.
                     Falls back to env var REMOTE_AGENT_URL.
        api_key: Bearer token for authentication.
                 Falls back to env var REMOTE_AGENT_API_KEY.
        hmac_secret: Shared HMAC secret for signing.
                     Falls back to env var REMOTE_AGENT_HMAC_SECRET.
        timeout: Request timeout in seconds (default 1 hour).
        execution_packages: Optional list of execution package dicts for
                            action whitelist validation on the remote side.

    Returns:
        The execution result dict from the remote agent.

    Raises:
        RemotePushError: If the push fails for any reason.
    """
    # Resolve configuration
    url = remote_url or os.getenv("REMOTE_AGENT_URL", "")
    key = api_key or os.getenv("REMOTE_AGENT_API_KEY", "")
    hmac_key = hmac_secret or os.getenv("REMOTE_AGENT_HMAC_SECRET", "")

    if not url:
        raise RemotePushError(
            "Remote agent URL not configured. "
            "Set REMOTE_AGENT_URL in .env or pass remote_url parameter."
        )

    if not key:
        raise RemotePushError(
            "Remote agent API key not configured. "
            "Set REMOTE_AGENT_API_KEY in .env or pass api_key parameter."
        )

    if not hmac_key:
        raise RemotePushError(
            "HMAC secret not configured. "
            "Set REMOTE_AGENT_HMAC_SECRET in .env or pass hmac_secret parameter."
        )

    # Ensure URL points to the execute endpoint
    if not url.endswith("/execute"):
        url = url.rstrip("/") + "/execute"

    # Build the signed payload with replay protection
    signed_payload = build_signed_payload(
        script=script,
        filename=filename,
        campaign_id=campaign_id,
        action_count=action_count,
        platform=platform,
        secret_key=hmac_key,
        execution_packages=execution_packages,
    )

    # Build headers with Bearer token
    headers = {
        "Content-Type": "application/json",
        # Avoid keep-alive edge cases across overlay networks (e.g., Tailscale)
        # where the request is processed remotely but the client stalls waiting
        # on a persistent socket.
        "Connection": "close",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"

    logger.info(
        f"Pushing signed script '{filename}' to remote agent at {url} "
        f"(campaign={campaign_id}, actions={action_count}, "
        f"nonce={signed_payload.get('nonce', 'N/A')[:8]}...)"
    )

    try:
        response = requests.post(
            url,
            json=signed_payload,
            headers=headers,
            timeout=timeout,
        )

        if response.status_code == 200:
            result = response.json()
            logger.info(
                f"Remote execution complete: "
                f"status={result.get('status')}, "
                f"exit_code={result.get('exit_code')}, "
                f"duration={result.get('duration_ms')}ms"
            )
            return result
        elif response.status_code == 401:
            raise RemotePushError(
                "Authentication failed (401). Check REMOTE_AGENT_API_KEY."
            )
        elif response.status_code == 403:
            raise RemotePushError(
                "Access denied (403). Invalid API key or signature."
            )
        elif response.status_code == 400:
            error_detail = response.json().get("detail", "Bad request")
            raise RemotePushError(f"Remote agent rejected request (400): {error_detail}")
        else:
            raise RemotePushError(
                f"Remote agent returned HTTP {response.status_code}: {response.text[:500]}"
            )

    except requests.ConnectionError as e:
        raise RemotePushError(
            f"Cannot connect to remote agent at {url}. "
            f"Is the remote agent running? Details: {e}"
        )
    except requests.Timeout:
        raise RemotePushError(
            f"Remote agent did not respond within {timeout}s timeout."
        )
    except requests.RequestException as e:
        raise RemotePushError(f"Request to remote agent failed: {e}")


def _base_url_from_remote_url(remote_url: str) -> str:
    """Normalize configured remote URL to base origin/path without /execute."""
    normalized = remote_url.strip().rstrip("/")
    if normalized.endswith("/execute"):
        return normalized[: -len("/execute")]
    return normalized


def verify_remote_connection(
    remote_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> bool:
    """
    Check if the remote agent is reachable by calling its /health endpoint.

    Args:
        remote_url: Base URL of the remote agent.
                     Falls back to env var REMOTE_AGENT_URL.
        api_key: Bearer token for authentication.

    Returns:
        True if the remote agent responds with status "healthy".
    """
    url = remote_url or os.getenv("REMOTE_AGENT_URL", "")
    key = api_key or os.getenv("REMOTE_AGENT_API_KEY", "")

    if not url:
        logger.warning("REMOTE_AGENT_URL not configured, cannot verify connection")
        return False

    # Use base URL (remove trailing /execute if present)
    health_url = _base_url_from_remote_url(url) + "/health"

    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        response = requests.get(health_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "healthy":
                logger.info(f"Remote agent at {url} is healthy")
                return True
        logger.warning(
            f"Remote agent at {url} returned unexpected response: "
            f"{response.status_code} {response.text[:300]}"
        )
        return False
    except requests.RequestException as e:
        logger.warning(f"Cannot reach remote agent at {url}: {e}")
        return False