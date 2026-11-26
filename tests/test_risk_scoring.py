from unittest.mock import patch

from actions.risk_scoring import calculate_risk_score
from config import config


def test_risk_score_uses_observed_evidence_and_configured_weights():
    summary = {
        "campaign": {"severity": "high", "confidence": 0.36},
        "failed_login_count": 2,
        "successful_authentication_after_failures": True,
        "top_mitre_techniques": [{"id": "T1110", "confidence": 0.7}],
        "prediction": {"likely_next_techniques": [{"id": "T1003"}]},
    }
    with patch.multiple(
        config,
        RISK_WEIGHT_SEVERITY_HIGH=25,
        RISK_WEIGHT_TECHNIQUE_CONFIDENCE=20,
        RISK_POINTS_PER_FAILED_LOGIN=3,
        RISK_MAX_REPETITION_POINTS=15,
        RISK_WEIGHT_SUCCESS_AFTER_FAILURE=20,
        RISK_WEIGHT_MALICIOUS_IOC=15,
        RISK_MALICIOUS_IOC_MIN_CONFIDENCE=0.8,
        RISK_WEIGHT_CAMPAIGN_CONFIDENCE=5,
        RISK_SCORE_VERSION="test",
    ):
        result = calculate_risk_score(summary, [{"reputation": "benign", "confidence": 1.0}])

    assert result.score == 67
    assert result.version == "test"
    assert "malicious_ioc:0" in result.factors


def test_malicious_ioc_adds_configured_points_and_score_is_capped():
    summary = {
        "campaign": {"severity": "high", "confidence": 1.0},
        "failed_login_count": 10,
        "successful_authentication_after_failures": True,
        "top_mitre_techniques": [{"confidence": 1.0}],
    }
    result = calculate_risk_score(
        summary,
        [{"reputation": "malicious", "confidence": 1.0}],
    )
    assert result.score == 100
    assert any(factor.startswith("malicious_ioc:") for factor in result.factors)
