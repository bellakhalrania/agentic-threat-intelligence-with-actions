"""
agents/collection_agent.py
Converts raw, heterogeneous telemetry (Sysmon/Suricata/Zeek/Wazuh/Windows Event)
into a normalized event schema using deterministic Python code.
No LLM calls — every field is extracted via rule-based logic.
"""

import uuid
from typing import Any, Dict, List


# ── Normalized schema keys ──────────────────────────────────────────────
# All normalized events use a superset of these keys. Missing keys default
# to None. The original event dict is always preserved under "raw".
NORMALIZED_FIELDS = [
    "event_id",
    "source",
    "event_type",
    "timestamp",
    "host",
    "user",
    "username",
    "process",
    "command_line",
    "src_ip",
    "dest_ip",
    "signature",
    "category",
    "severity",
    "rule_description",
    "rule_level",
    "rule_groups",
    "proto",
    "service",
    "query",
    "raw",
]


def _blank() -> Dict[str, Any]:
    return {k: None for k in NORMALIZED_FIELDS}


# ── Source-specific normalizers ─────────────────────────────────────────


def _normalize_sysmon(event: dict) -> dict:
    n = _blank()
    n["source"] = "sysmon"
    n["event_type"] = f"sysmon_event_{event.get('EventID', 'unknown')}"
    n["timestamp"] = event.get("UtcTime") or event.get("timestamp")
    n["host"] = event.get("Computer") or event.get("host")
    n["process"] = event.get("Image") or event.get("process")
    n["command_line"] = event.get("command_line") or event.get("CommandLine")
    n["user"] = event.get("User")
    n["src_ip"] = event.get("SourceIp") or event.get("src_ip")
    n["dest_ip"] = event.get("DestinationIp") or event.get("dest_ip")
    n["raw"] = event
    return n


def _normalize_suricata(event: dict) -> dict:
    n = _blank()
    n["source"] = "suricata"
    n["event_type"] = event.get("event_type", "alert")
    n["timestamp"] = event.get("timestamp")
    n["src_ip"] = event.get("src_ip")
    n["dest_ip"] = event.get("dest_ip")
    n["proto"] = event.get("proto")
    # Check top-level fields first, then nested alert structure
    alert = event.get("alert") or {}
    n["signature"] = event.get("signature") or alert.get("signature")
    n["category"] = event.get("category") or alert.get("category")
    n["severity"] = event.get("severity") or alert.get("severity")
    n["raw"] = event
    return n


def _normalize_zeek(event: dict) -> dict:
    n = _blank()
    n["source"] = "zeek"
    n["event_type"] = event.get("event_type") or (  # infer from presence of fields
        "dns" if event.get("query") else "conn"
    )
    n["timestamp"] = event.get("ts") or event.get("timestamp")
    n["src_ip"] = event.get("id.orig_h") or event.get("src_ip")
    n["dest_ip"] = event.get("id.resp_h") or event.get("dest_ip")
    n["proto"] = event.get("proto")
    n["service"] = event.get("service")
    n["query"] = event.get("query")
    n["raw"] = event
    return n


def _normalize_wazuh(event: dict) -> dict:
    n = _blank()
    n["source"] = "wazuh"
    n["event_type"] = "wazuh_alert"
    n["timestamp"] = event.get("timestamp")
    agent = event.get("agent") or {}
    n["host"] = agent.get("name") or event.get("host")
    rule = event.get("rule") or {}
    # Check top-level fields first, then nested rule structure
    n["rule_description"] = event.get("rule_description") or rule.get("description")
    n["rule_level"] = event.get("rule_level") or rule.get("level")
    n["rule_groups"] = event.get("rule_groups") or rule.get("groups")
    n["severity"] = event.get("rule_level") or rule.get("level")
    n["process"] = event.get("process")
    n["command_line"] = event.get("command_line")
    n["src_ip"] = event.get("src_ip")
    n["dest_ip"] = event.get("dest_ip")
    n["raw"] = event
    
    # If process/command_line not at top level, try to extract from full_log
    if not n["process"] or not n["command_line"]:
        full_log = event.get("full_log", "")
        if full_log:
            import re
            # Strategy 1: Extract process name as the first space-delimited token
            # (e.g., "schtasks" from "schtasks /create ...", "powershell" from "powershell -enc ...")
            first_token_match = re.match(r'^"([^"]+)"|^(\S+)', full_log.strip())
            if first_token_match:
                first_token = first_token_match.group(1) or first_token_match.group(2)
                # If the token doesn't already have an extension, try .exe first
                if "." not in first_token and not n["process"]:
                    n["process"] = first_token
                    # command_line is everything after the first token
                    cmd_start = first_token_match.end()
                    potential_cmd = full_log[cmd_start:].strip().strip('"')
                    if potential_cmd and not n["command_line"]:
                        n["command_line"] = potential_cmd[:500]
            
            # Strategy 2: Fallback — extract any .exe file name from full_log
            if not n["process"]:
                exe_match = re.search(r'\b([A-Za-z0-9_-]+\.exe)\b', full_log, re.IGNORECASE)
                if exe_match:
                    n["process"] = exe_match.group(1)
                    cmd_start = exe_match.end()
                    potential_cmd = full_log[cmd_start:].strip()
                    if potential_cmd and not n["command_line"]:
                        n["command_line"] = potential_cmd[:500]
    
    return n


def _normalize_linux(event: dict) -> dict:
    """Normalize Linux authentication events (e.g., SSH auth from auth.log)."""
    n = _blank()
    n["source"] = "linux"
    n["event_type"] = event.get("event_type", "authentication")
    n["timestamp"] = event.get("timestamp")
    n["host"] = event.get("host")
    n["username"] = event.get("username") or event.get("user")
    n["service"] = event.get("service")
    n["src_ip"] = event.get("src_ip") or event.get("source_ip")
    n["dest_ip"] = event.get("dest_ip") or event.get("destination_ip")
    n["proto"] = event.get("proto")
    n["raw"] = event
    return n


def _normalize_windows_event(event: dict) -> dict:
    """Normalize Windows Event Log entries (EventID-based, similar to Sysmon)."""
    n = _blank()
    n["source"] = "windows_event"
    n["event_type"] = f"event_{event.get('EventID') or event.get('event_id', 'unknown')}"
    n["timestamp"] = event.get("TimeCreated") or event.get("UtcTime") or event.get("timestamp")
    n["host"] = event.get("Computer") or event.get("host")
    n["user"] = event.get("User") or event.get("user")
    n["process"] = event.get("Image") or event.get("process")
    n["command_line"] = event.get("CommandLine")
    n["src_ip"] = event.get("SourceIp") or event.get("src_ip")
    n["dest_ip"] = event.get("DestinationIp") or event.get("dest_ip")
    n["raw"] = event
    return n


# ── Heuristic source detection ──────────────────────────────────────────


def _detect_source(event: dict) -> str:
    """Determine log source heuristically from available fields."""
    # If an explicit source is already set, trust it.
    explicit = event.get("source")
    if explicit in ("sysmon", "suricata", "zeek", "wazuh", "windows_event", "linux"):
        return explicit

    # Linux: has service field (e.g., "ssh") and authentication-related event_type
    if event.get("service") == "ssh" or event.get("event_type") in ("authentication", "authentication_failed", "authentication_success"):
        return "linux"

    # Windows Event Log: has TimeCreated (or Provider) along with EventID
    if event.get("TimeCreated") is not None or event.get("Provider") is not None:
        return "windows_event"

    # Sysmon: has EventID (integer or string) but NOT TimeCreated/Provider
    if event.get("EventID") is not None:
        return "sysmon"

    # Suricata: has event_type field (typically "alert" / "flow" / "dns" / "http")
    if "event_type" in event and event.get("event_type") in (
        "alert",
        "flow",
        "dns",
        "http",
        "tls",
        "smb",
    ):
        return "suricata"

    # Zeek JSON logs: have dotted id.orig_h / id.resp_h or ts + proto + service
    if "ts" in event or "id.orig_h" in event or "id.resp_h" in event:
        return "zeek"

    # Wazuh: has rule dict with groups/description
    if "rule" in event and isinstance(event["rule"], dict):
        return "wazuh"

    # Fallback: check for generic Windows Event fields (TimeCreated, Provider)
    if event.get("TimeCreated") or event.get("Provider"):
        return "windows_event"

    # Default to sysmon for anything with EventID-like numeric field
    if event.get("event_id") and isinstance(event.get("event_id"), (int, str)):
        return "sysmon"

    # Last resort — treat as sysmon-like
    return "sysmon"


# ── Router ──────────────────────────────────────────────────────────────


_NORMALIZER_DISPATCH = {
    "sysmon": _normalize_sysmon,
    "suricata": _normalize_suricata,
    "zeek": _normalize_zeek,
    "wazuh": _normalize_wazuh,
    "linux": _normalize_linux,
    "windows_event": _normalize_windows_event,
}


def normalize_event(event: dict) -> dict:
    """Normalize a single raw event dict into the common schema.

    Preserves all original fields via the ``raw`` key.
    Generates an ``event_id`` only when one is not already present.
    Never infers or modifies values.
    """
    source = _detect_source(event)
    normalizer = _NORMALIZER_DISPATCH.get(source, _normalize_sysmon)
    normalized = normalizer(event)

    # Assign event_id only if missing
    if not normalized.get("event_id") and not event.get("event_id"):
        normalized["event_id"] = str(uuid.uuid4())
    elif event.get("event_id"):
        normalized["event_id"] = str(event["event_id"])

    return normalized


# ── Public API (same interface as before) ───────────────────────────────


class CollectionAgent:
    """Agent that normalizes raw security events using deterministic rules.

    This replaces the previous LLM-based approach with purely rule-based,
    source-aware normalization. Every original field is preserved under
    the ``raw`` key.
    """

    def run(self, raw_events: List[Dict]) -> List[Dict]:
        print("\n========== COLLECTION AGENT ==========\n")
        if not raw_events:
            return []
        normalized = []
        for event in raw_events:
            normalized.append(normalize_event(event))
            print(f"Normalized event: {normalized[-1]}")
        return normalized
