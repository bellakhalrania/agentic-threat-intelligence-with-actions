"""
actions/audit_log.py
Append-only audit trail. Every ProposedAction is logged here regardless of
whether it was executed, queued for approval, or denied — this is what
you'd show a compliance reviewer or use to debug "why did the platform
block this IP at 3am."

Supports structured queries: filter by status, action_type, target, time range,
and campaign_id without loading the entire log into memory.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional
from actions.action_models import ActionResult

AUDIT_LOG_PATH = "./data/action_audit_log.jsonl"


# ── In-memory index for common queries ──────────────────────────────────
# Built lazily on first query, invalidated when a new entry is written.
_index_built = False
_index: Dict[str, list] = {
    "by_action_id": defaultdict(list),
    "by_status": defaultdict(list),
    "by_action_type": defaultdict(list),
    "by_target": defaultdict(list),
    "by_campaign": defaultdict(list),
}


def _rebuild_index():
    """Scan the entire audit log and rebuild the in-memory index."""
    global _index_built
    for key in _index:
        _index[key].clear()

    if not os.path.exists(AUDIT_LOG_PATH):
        _index_built = True
        return

    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            _index["by_status"][entry.get("status", "unknown")].append(line_num)
            _index["by_action_id"][entry.get("action_id", "")].append(line_num)
            _index["by_action_type"][entry.get("action_type", "unknown")].append(line_num)
            _index["by_target"][entry.get("target", "")].append(line_num)
            _index["by_campaign"][entry.get("campaign_id", "")].append(line_num)

    _index_built = True


def _ensure_index():
    """Rebuild the index if it hasn't been built yet."""
    if not _index_built:
        _rebuild_index()


def _read_entry(line_num: int) -> Optional[dict]:
    """Read a single log entry by line number (0-based)."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return None
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i == line_num:
                line = line.strip()
                if not line:
                    return None
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    return None
    return None


def record(result: ActionResult, campaign_id: str = "", metadata: Optional[Dict] = None) -> dict:
    """Write a single audit log entry (append-only).

    The entry includes all action fields plus execution context like
    dry_run mode and a precise UTC timestamp.
    """
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    entry = {
        "action_id": result.action_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "campaign_id": campaign_id,
        "action_type": result.action.action_type,
        "target": result.action.target,
        "severity": result.action.severity,
        "confidence": result.action.confidence,
        "risk_score": result.action.risk_score,
        "risk_factors": result.action.risk_factors,
        "risk_version": result.action.risk_version,
        "rationale": result.action.rationale,
        "technique_id": result.action.technique_id,
        "status": result.status,
        "detail": result.detail,
        "dry_run": result.dry_run,
    }
    if metadata:
        entry["approval"] = metadata
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")

    # Invalidate the index so the next query rebuilds it
    global _index_built
    _index_built = False
    return entry


def read_pending_approvals() -> List[dict]:
    """Return pending actions whose latest audit entry is still pending."""
    _ensure_index()
    line_nums = _index["by_status"].get("pending_approval", [])
    results = []
    for ln in line_nums:
        entry = _read_entry(ln)
        if entry is not None and entry.get("action_id"):
            latest = get_latest_action(entry["action_id"])
            if latest and latest.get("status") == "pending_approval":
                results.append(latest)
        elif entry is not None:
            # Legacy records predate stable action IDs and remain viewable, but
            # cannot be safely approved because they cannot be de-duplicated.
            results.append(entry)
    return results


def get_latest_action(action_id: str) -> Optional[dict]:
    """Return the newest audit entry for a stable action ID."""
    if not action_id:
        return None
    _ensure_index()
    line_nums = _index["by_action_id"].get(action_id, [])
    if not line_nums:
        return None
    return _read_entry(line_nums[-1])


def query(
    status: Optional[str] = None,
    action_type: Optional[str] = None,
    target: Optional[str] = None,
    campaign_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    """Query the audit log with optional filters.

    Args:
        status: Filter by status (executed, pending_approval, denied, failed).
        action_type: Filter by action type (block_ip, isolate_host, etc.).
        target: Filter by target (exact match).
        campaign_id: Filter by campaign ID.
        since: ISO timestamp — only return entries after this time.
        until: ISO timestamp — only return entries before this time.
        limit: Maximum number of entries to return (default 100).

    Returns:
        A list of matching audit log entries, newest first.
    """
    _ensure_index()

    # Start with all line numbers, then intersect with filters using the index
    candidate_sets = []

    if status:
        candidate_sets.append(set(_index["by_status"].get(status, [])))
    if action_type:
        candidate_sets.append(set(_index["by_action_type"].get(action_type, [])))
    if target:
        candidate_sets.append(set(_index["by_target"].get(target, [])))
    if campaign_id:
        candidate_sets.append(set(_index["by_campaign"].get(campaign_id, [])))

    if candidate_sets:
        # Intersect all filtered sets
        candidates = set.intersection(*candidate_sets)
    else:
        # No filters: scan entire file (expensive but correct)
        if not os.path.exists(AUDIT_LOG_PATH):
            return []
        candidates = set()
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f):
                if line.strip():
                    candidates.add(line_num)

    # Read matching entries
    results = []
    for ln in sorted(candidates, reverse=True):  # newest first
        entry = _read_entry(ln)
        if entry is None:
            continue

        # Apply time-range filters (not indexed, need to check per entry)
        if since and entry.get("timestamp", "") < since:
            continue
        if until and entry.get("timestamp", "") > until:
            continue

        results.append(entry)
        if len(results) >= limit:
            break

    return results


def count_by_status() -> Dict[str, int]:
    """Return a count of entries grouped by status.

    Useful for dashboards and monitoring:
        {
            "executed": 12,
            "pending_approval": 5,
            "denied": 2,
            "failed": 1
        }
    """
    _ensure_index()
    return {
        status: len(lines)
        for status, lines in sorted(_index["by_status"].items())
    }


def count_by_action_type() -> Dict[str, int]:
    """Return a count of entries grouped by action type."""
    _ensure_index()
    return {
        atype: len(lines)
        for atype, lines in sorted(_index["by_action_type"].items())
    }


def get_recent(limit: int = 20) -> List[dict]:
    """Return the most recent audit log entries."""
    return query(limit=limit)


def export_to_json(output_path: str) -> str:
    """Export the full audit log to a single JSON array file.

    Args:
        output_path: Path to write the exported JSON file.

    Returns:
        The path to the exported file.
    """
    if not os.path.exists(AUDIT_LOG_PATH):
        return ""

    entries = []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, default=str)

    return output_path
