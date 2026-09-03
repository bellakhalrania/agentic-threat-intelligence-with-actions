"""Deterministic, environment-configured response risk scoring."""

from dataclasses import dataclass
from typing import Any, Dict, List

from config import config


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    factors: List[str]
    version: str


def _bounded_number(value: Any) -> float:
    try:
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return 0.0


def calculate_risk_score(
    threat_summary: Dict[str, Any],
    iocs: List[Dict[str, Any]],
) -> RiskAssessment:
    """Calculate a reproducible 0-100 score from observed evidence only."""
    campaign = threat_summary.get("campaign") or {}
    severity = str(campaign.get("severity") or "").lower()
    severity_weights = {
        "low": config.RISK_WEIGHT_SEVERITY_LOW,
        "medium": config.RISK_WEIGHT_SEVERITY_MEDIUM,
        "high": config.RISK_WEIGHT_SEVERITY_HIGH,
        "critical": config.RISK_WEIGHT_SEVERITY_HIGH,
    }
    severity_points = severity_weights.get(severity, 0)

    techniques = threat_summary.get("top_mitre_techniques") or []
    observed_confidence = max(
        (_bounded_number(item.get("confidence")) for item in techniques),
        default=0.0,
    )
    technique_points = round(observed_confidence * config.RISK_WEIGHT_TECHNIQUE_CONFIDENCE)

    try:
        failed_logins = max(0, int(threat_summary.get("failed_login_count", 0)))
    except (TypeError, ValueError):
        failed_logins = 0
    repetition_points = min(
        failed_logins * config.RISK_POINTS_PER_FAILED_LOGIN,
        config.RISK_MAX_REPETITION_POINTS,
    )

    success_points = (
        config.RISK_WEIGHT_SUCCESS_AFTER_FAILURE
        if threat_summary.get("successful_authentication_after_failures") is True
        else 0
    )

    malicious_ioc = any(
        str(ioc.get("reputation") or ioc.get("verdict") or "").lower() == "malicious"
        and _bounded_number(ioc.get("confidence"))
        >= config.RISK_MALICIOUS_IOC_MIN_CONFIDENCE
        for ioc in iocs
    )
    reputation_points = config.RISK_WEIGHT_MALICIOUS_IOC if malicious_ioc else 0

    campaign_confidence = _bounded_number(campaign.get("confidence"))
    campaign_points = round(
        campaign_confidence * config.RISK_WEIGHT_CAMPAIGN_CONFIDENCE
    )

    factors = [
        f"severity:{severity_points}",
        f"observed_technique_confidence:{technique_points}",
        f"failed_login_repetition:{repetition_points}",
        f"successful_authentication_after_failures:{success_points}",
        f"malicious_ioc:{reputation_points}",
        f"campaign_confidence:{campaign_points}",
    ]
    score = min(
        100,
        max(
            0,
            severity_points
            + technique_points
            + repetition_points
            + success_points
            + reputation_points
            + campaign_points,
        ),
    )
    return RiskAssessment(
        score=score,
        factors=factors,
        version=config.RISK_SCORE_VERSION,
    )
