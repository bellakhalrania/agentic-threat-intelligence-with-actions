"""Deterministic, bounded context for response-action generation."""

from typing import Any, Dict, Iterable, List


MAX_ENTITIES = 20
MAX_TECHNIQUES = 10
MAX_PREDICTIONS = 10
MAX_TEXT_LENGTH = 500


def build_threat_summary(
    campaign: Dict[str, Any],
    techniques: List[Dict[str, Any]],
    prediction: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return compact, deterministic response context without raw events.

    The returned object deliberately contains only bounded aggregate data and
    concrete response targets.  Raw event records remain in graph state for
    reporting, validation, and evidence handling, but cannot inflate the
    Response Agent's LLM prompt.
    """
    campaign = campaign or {}
    techniques = techniques or []
    prediction = prediction or {}
    events = events or []

    affected_hosts = _unique_values(events, ("host", "dest_ip"))
    affected_users = _unique_values(events, ("user", "username"))
    source_ips = _unique_values(events, ("src_ip",))
    processes = _unique_values(events, ("process",))
    failed_logins = sum(_is_failed_login(event) for event in events)
    successful_after_failures = _successful_authentication_after_failures(events)
    top_techniques = _top_techniques(techniques)
    campaign_confidence = _number(campaign.get("confidence"))

    # These explicit target lists retain the Response Agent's grounding and
    # isolation safeguards without passing event records through the graph.
    valid_targets = sorted({
        *affected_hosts,
        *affected_users,
        *source_ips,
        *processes,
    })

    return {
        "campaign": {
            "campaign_id": _short_text(campaign.get("campaign_id")),
            "name": _short_text(campaign.get("name")) or "Unclassified Activity",
            "severity": _campaign_severity(campaign, events, techniques),
            "confidence": campaign_confidence,
        },
        "event_count": len(events),
        "failed_login_count": failed_logins,
        "successful_authentication_after_failures": successful_after_failures,
        "affected_hosts": affected_hosts,
        "affected_users": affected_users,
        "source_ips": source_ips,
        "processes": processes,
        "top_mitre_techniques": top_techniques,
        "prediction": {
            "likely_next_techniques": _bounded_items(
                prediction.get("likely_next_techniques"), MAX_PREDICTIONS
            ),
            "rationale": _short_text(prediction.get("rationale")),
        },
        "valid_action_targets": valid_targets,
        "victim_isolation_targets": affected_hosts,
        "attacker_source_ips": source_ips,
    }


def _unique_values(events: Iterable[Dict[str, Any]], keys: tuple[str, ...]) -> List[str]:
    values = {
        _short_text(event.get(key))
        for event in events
        for key in keys
        if _short_text(event.get(key))
    }
    return sorted(values)[:MAX_ENTITIES]


def _top_techniques(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rank technique IDs by occurrence, then confidence and stable name."""
    grouped: Dict[tuple[str, str], List[float]] = {}
    for technique in techniques:
        technique_id = _short_text(technique.get("attack_id") or technique.get("technique_id"))
        name = _short_text(technique.get("technique_name") or technique.get("name"))
        if not technique_id and not name:
            continue
        grouped.setdefault((technique_id, name), []).append(_number(technique.get("confidence")) or 0.0)

    ranked = sorted(
        grouped.items(),
        key=lambda item: (-len(item[1]), -max(item[1]), item[0][0], item[0][1]),
    )[:MAX_TECHNIQUES]
    return [
        {
            "id": technique_id,
            "name": name,
            "count": len(confidences),
            "confidence": round(max(confidences), 3),
        }
        for (technique_id, name), confidences in ranked
    ]


def _campaign_severity(
    campaign: Dict[str, Any], events: List[Dict[str, Any]], techniques: List[Dict[str, Any]]
) -> str:
    declared = str(campaign.get("severity") or "").lower()
    if declared in {"low", "medium", "high", "critical"}:
        return declared

    levels = [str(event.get("severity") or "").lower() for event in events]
    if "critical" in levels or "high" in levels:
        return "high"
    if "medium" in levels:
        return "medium"

    confidence = max(
        [_number(campaign.get("confidence")) or 0.0]
        + [_number(technique.get("confidence")) or 0.0 for technique in techniques]
    )
    return "high" if confidence >= 0.9 else "medium" if confidence >= 0.6 else "low"


def _is_failed_login(event: Dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or "").lower()
    if event_type in {"authentication_failed", "login_failed", "failed_login"}:
        return True
    return "authentication" in event_type and "fail" in event_type


def _is_successful_login(event: Dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or "").lower()
    if event_type in {"authentication_success", "login_success", "successful_login"}:
        return True
    return "authentication" in event_type and "success" in event_type


def _successful_authentication_after_failures(events: List[Dict[str, Any]]) -> bool:
    """Require a success to follow a failure for the same source and account."""
    failed_pairs: set[tuple[str, str]] = set()
    for event in events:
        source = _short_text(event.get("src_ip"))
        account = _short_text(event.get("user") or event.get("username"))
        pair = (source, account)
        if _is_failed_login(event):
            failed_pairs.add(pair)
        elif _is_successful_login(event) and pair in failed_pairs:
            return True
    return False


def _number(value: Any) -> float | None:
    try:
        return round(float(value), 3)
    except (TypeError, ValueError):
        return None


def _short_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()[:MAX_TEXT_LENGTH]


def _bounded_items(value: Any, limit: int) -> List[Any]:
    if not isinstance(value, list):
        return []
    items: List[Any] = []
    for item in value[:limit]:
        if isinstance(item, dict):
            items.append({
                "id": _short_text(item.get("technique_id") or item.get("attack_id")),
                "name": _short_text(item.get("name") or item.get("technique_name")),
            })
        else:
            items.append(_short_text(item))
    return items
