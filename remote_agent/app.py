"""
remote_agent/app.py
===================
Lightweight Remote Response Agent (Machine 2).

This FastAPI service runs on the target/endpoint machine and listens for
response scripts pushed from the main Threat Intelligence Platform (Machine 1).

Endpoints:
  POST /execute    - Receive, validate, execute a response script, return results
  GET  /health     - Health check
  GET  /status     - Show execution log

Security:
  - Bearer token authentication (configurable via REMOTE_AGENT_API_KEY env var)
  - HTTPS-ready (deploy behind reverse proxy with TLS)
  - All executions are logged to remote_agent/execution_log.jsonl
"""

import os
import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Optional, Set

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

# Shared crypto module is co-located; copy it to remote_agent/ or install from path
# For now, inline the needed functions to keep the remote agent self-contained.
# In production, use a shared package or copy actions/crypto.py to remote_agent/.
import hmac
import hashlib
import base64
import time

# ---------------------------------------------------------------------------
# Inline crypto functions (mirrors actions/crypto.py for self-contained agent)
# ---------------------------------------------------------------------------

DEFAULT_REPLAY_WINDOW = 300  # 5 minutes
ALLOWED_ACTION_TYPES = {"block_ip", "isolate_host", "disable_account",
                        "kill_process", "quarantine_file", "notify_analyst"}
FORBIDDEN_COMMANDS = [
    "rm -rf /", "rm -rf /*", "mkfs.", "dd if=", "> /dev/sd",
    ":(){ :|:& };:", "chmod -R 000 /", "chown -R 0:0 /",
    "wget http://", "curl http://", "bash -c '", "python -c '",
    "eval ", "exec ",
]

# In-memory set of seen nonces for replay protection
_seen_nonces: Set[str] = set()

# Max entries in seen_nonces to prevent memory exhaustion
_MAX_NONCES = 10000


def _verify_signature(payload: dict, signature: str, secret_key: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    # Remove signature field before recomputing
    payload_copy = {k: v for k, v in payload.items() if k != "signature"}
    canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(secret_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256)
    expected = base64.b64encode(mac.digest()).decode("utf-8")
    return hmac.compare_digest(expected, signature)


def _check_replay(timestamp: int, nonce: str, window: int = DEFAULT_REPLAY_WINDOW) -> bool:
    """Verify timestamp is within window and nonce is unique."""
    now = int(time.time())
    if timestamp < now - window or timestamp > now + window:
        return False
    if nonce in _seen_nonces:
        return False
    # Prune seen nonces if too large
    if len(_seen_nonces) >= _MAX_NONCES:
        _seen_nonces.clear()
    _seen_nonces.add(nonce)
    return True


def _validate_script(script: str) -> dict:
    """Validate script against action whitelist and forbidden commands."""
    result = {"valid": True, "detected_actions": [], "forbidden_commands": [], "reason": ""}
    script_lower = script.lower()

    for action_type in ALLOWED_ACTION_TYPES:
        if action_type in script_lower:
            result["detected_actions"].append(action_type)

    for cmd in FORBIDDEN_COMMANDS:
        if cmd.lower() in script_lower:
            result["valid"] = False
            result["forbidden_commands"].append(cmd)
            result["reason"] = f"Script contains forbidden command: {cmd}"
            return result

    return result


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HOST = os.getenv("REMOTE_AGENT_HOST", "0.0.0.0")
PORT = int(os.getenv("REMOTE_AGENT_PORT", "9001"))
API_KEY = os.getenv("REMOTE_AGENT_API_KEY", "change-me-in-production")
HMAC_SECRET = os.getenv("REMOTE_AGENT_HMAC_SECRET", "")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.abspath(os.getenv("REMOTE_AGENT_SCRIPTS_DIR", os.path.join(BASE_DIR, "received_scripts")))
LOG_FILE = os.path.abspath(os.getenv("REMOTE_AGENT_LOG_FILE", os.path.join(BASE_DIR, "execution_log.jsonl")))
REPLAY_WINDOW = int(os.getenv("REMOTE_AGENT_REPLAY_WINDOW", "300"))

os.makedirs(SCRIPTS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("remote_agent")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Remote Response Agent",
    description="Receives and executes response scripts from the Threat Intelligence Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ExecuteRequest(BaseModel):
    """Request body from Machine 1 containing the script to execute.

    Includes cryptographic fields for security verification:
      - signature: HMAC-SHA256 of the payload
      - timestamp: Unix timestamp for replay window check
      - nonce: Unique identifier to prevent replay attacks
      - action_types: List of action types for whitelist validation
    """

    script: str = Field(..., description="The executable script content (Bash/PowerShell)")
    filename: str = Field("response.sh", description="Suggested filename for the script")
    campaign_id: str = Field("", description="Campaign identifier for audit trail")
    action_count: int = Field(0, description="Number of actions in the script")
    platform: str = Field("linux", description="Target platform (linux/windows/macos)")
    signature: str = Field("", description="HMAC-SHA256 signature of the payload")
    timestamp: int = Field(0, description="Unix timestamp for replay protection")
    nonce: str = Field("", description="Unique nonce for replay protection")
    action_types: list = Field([], description="List of action types for whitelist validation")


class ExecutionResult(BaseModel):
    """Result returned after executing the script."""

    success: bool
    execution_id: str
    filename: str
    campaign_id: str
    exit_code: int
    stdout: str
    stderr: str
    status: str  # "completed", "failed", "timeout"
    executed_at: str
    duration_ms: float
    error: Optional[str] = None


class ExecutionLogEntry(BaseModel):
    """An entry in the execution audit log."""
    execution_id: str
    campaign_id: str
    filename: str
    status: str
    exit_code: int
    stdout: str
    stderr: str
    executed_at: str
    duration_ms: float


# ---------------------------------------------------------------------------
# Authentication dependency
# ---------------------------------------------------------------------------


def verify_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> bool:
    """Verify Bearer token. If no API key is configured, allow unauthenticated access."""
    if not API_KEY or API_KEY == "":
        return True

    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    token = credentials.credentials
    if token != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid authentication token")

    return True


# ---------------------------------------------------------------------------
# Helper: log execution to JSONL
# ---------------------------------------------------------------------------


def _log_execution(entry: ExecutionLogEntry) -> None:
    """Append an execution record to the JSONL log file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry.model_dump_json() + "\n")
    except Exception as e:
        logger.error(f"Failed to write execution log: {e}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": f"RemoteResponseAgent",
    }


@app.get("/status")
async def get_status(auth: bool = Depends(verify_auth)):
    """Return execution log summary."""
    entries = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception as e:
            logger.error(f"Failed to read execution log: {e}")

    return {
        "total_executions": len(entries),
        "entries": entries[-20:],  # last 20 entries
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/execute", response_model=ExecutionResult)
async def execute_script(
    request: ExecuteRequest,
    auth: bool = Depends(verify_auth),
    x_api_key: Optional[str] = Header(None),
):
    """
    Receive a response script, execute it, and return the result.

    This is the primary endpoint called by Machine 1 after generating
    the response script.
    """
    execution_id = str(uuid.uuid4())
    start_time = datetime.now(timezone.utc)

    logger.info(
        f"Received execution request {execution_id}: "
        f"campaign={request.campaign_id}, "
        f"actions={request.action_count}, "
        f"platform={request.platform}"
    )

    # ======================================================================
    # SECURITY CHECK 1: Signature verification (HMAC-SHA256)
    # ======================================================================
    if HMAC_SECRET:
        if not request.signature:
            raise HTTPException(
                status_code=400,
                detail="Signature required but not provided. Set REMOTE_AGENT_HMAC_SECRET on both sides.",
            )

        # Build the verification payload (same keys as signed on Machine 1)
        payload_dict = request.model_dump()
        if not _verify_signature(payload_dict, request.signature, HMAC_SECRET):
            logger.warning(
                f"Signature verification FAILED for execution {execution_id}. "
                f"Expected valid HMAC-SHA256 with configured secret."
            )
            raise HTTPException(
                status_code=403,
                detail="Invalid payload signature. The request may have been tampered with.",
            )
        logger.info(f"Signature verified OK for execution {execution_id}")
    else:
        logger.warning(
            "REMOTE_AGENT_HMAC_SECRET not configured. "
            "Signature verification DISABLED - this is INSECURE for production!"
        )

    # ======================================================================
    # SECURITY CHECK 2: Replay attack protection (timestamp + nonce)
    # ======================================================================
    if request.timestamp > 0 and request.nonce:
        if not _check_replay(request.timestamp, request.nonce, REPLAY_WINDOW):
            logger.warning(
                f"Replay attack detected for execution {execution_id}: "
                f"timestamp={request.timestamp}, nonce={request.nonce[:16]}..."
            )
            raise HTTPException(
                status_code=400,
                detail="Replay attack detected. Timestamp out of window or duplicate nonce.",
            )
        logger.info(f"Replay check passed for execution {execution_id}")
    else:
        logger.warning(
            "No timestamp/nonce provided. Replay protection DISABLED - "
            "this is INSECURE for production!"
        )

    # ======================================================================
    # SECURITY CHECK 3: Action whitelist validation
    # ======================================================================
    validation = _validate_script(request.script)
    if not validation["valid"]:
        logger.warning(
            f"Action whitelist validation FAILED for execution {execution_id}: "
            f"{validation['reason']}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Script validation failed: {validation['reason']}",
        )

    # Also validate against the explicit action_types list if provided
    if request.action_types:
        for action_type in request.action_types:
            if action_type not in ALLOWED_ACTION_TYPES:
                logger.warning(
                    f"Action type '{action_type}' not in whitelist for execution {execution_id}"
                )
                raise HTTPException(
                    status_code=400,
                    detail=f"Action type '{action_type}' is not in the allowed whitelist. "
                           f"Allowed: {sorted(ALLOWED_ACTION_TYPES)}",
                )

    detected = validation.get("detected_actions", [])
    logger.info(
        f"Action whitelist validation passed for execution {execution_id}. "
        f"Detected actions: {detected if detected else 'none (custom script)'}"
    )

    # --- Basic content validation ---
    if not request.script or len(request.script.strip()) == 0:
        raise HTTPException(status_code=400, detail="Script content is empty")

    if len(request.script) > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(status_code=400, detail="Script exceeds maximum size (10 MB)")

    # ======================================================================
    # Save the script to disk and execute
    # ======================================================================
    sanitized_filename = os.path.basename(request.filename or f"response_{execution_id[:8]}.sh")
    script_path = os.path.join(SCRIPTS_DIR, sanitized_filename)

    try:
        with open(script_path, "w") as f:
            f.write(request.script)
        os.chmod(script_path, 0o755)  # make executable
        logger.info(f"Saved script to {script_path}")
    except Exception as e:
        logger.error(f"Failed to save script: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save script: {str(e)}")

    # --- Execute the script ---
    status = "failed"
    exit_code = -1
    stdout = ""
    stderr = ""
    error_msg = None
    duration_ms = 0.0

    try:
        logger.info(f"Executing script: {script_path}")

        # Use timeout to prevent runaway scripts (30 minutes default)
        timeout_seconds = int(os.getenv("REMOTE_AGENT_TIMEOUT", "1800"))

        result = subprocess.run(
            ["/bin/bash", os.path.abspath(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=SCRIPTS_DIR,
        )

        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr

        if exit_code == 0:
            status = "completed"
            logger.info(f"Script {execution_id} completed successfully")
        else:
            status = "failed"
            logger.warning(f"Script {execution_id} failed with exit code {exit_code}")

    except subprocess.TimeoutExpired:
        status = "timeout"
        error_msg = f"Script execution timed out after {timeout_seconds} seconds"
        logger.error(f"Script {execution_id} timed out")

    except subprocess.NoSuchFileError:
        status = "failed"
        error_msg = f"Shell interpreter not found"
        logger.error(f"Script {execution_id}: shell not found")

    except Exception as e:
        status = "failed"
        error_msg = str(e)
        logger.error(f"Script {execution_id} execution error: {e}")

    finally:
        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000

    # --- Build result ---
    result = ExecutionResult(
        success=(status == "completed" and exit_code == 0),
        execution_id=execution_id,
        filename=sanitized_filename,
        campaign_id=request.campaign_id,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        status=status,
        executed_at=start_time.isoformat(),
        duration_ms=round(duration_ms, 2),
        error=error_msg,
    )

    # --- Log execution ---
    log_entry = ExecutionLogEntry(
        execution_id=execution_id,
        campaign_id=request.campaign_id,
        filename=sanitized_filename,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        executed_at=start_time.isoformat(),
        duration_ms=round(duration_ms, 2),
    )
    _log_execution(log_entry)

    logger.info(
        f"Execution {execution_id} complete: "
        f"status={status}, exit_code={exit_code}, duration={duration_ms:.0f}ms"
    )

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    print(f"Starting Remote Response Agent on {HOST}:{PORT}")
    print(f"  API Key: {'configured' if API_KEY and API_KEY != 'change-me-in-production' else 'NOT SET (INSECURE)'}")
    print(f"  Scripts dir: {SCRIPTS_DIR}")
    print(f"  Log file: {LOG_FILE}")
    print(f"  Timeout: {os.getenv('REMOTE_AGENT_TIMEOUT', '1800')}s")
    print()
    uvicorn.run(app, host=HOST, port=PORT)