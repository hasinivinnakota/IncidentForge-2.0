from backend.app.ml.model import (
    BaselineLogisticRiskModel,
    probability_to_score_and_level,
)


def test_probability_to_score_and_level_thresholds() -> None:
    # 0 - 24 = low
    score, level = probability_to_score_and_level(0.10)
    assert score == 10
    assert level == "low"

    score, level = probability_to_score_and_level(0.24)
    assert score == 24
    assert level == "low"

    # 25 - 49 = medium
    score, level = probability_to_score_and_level(0.25)
    assert score == 25
    assert level == "medium"

    score, level = probability_to_score_and_level(0.48)
    assert score == 48
    assert level == "medium"

    # 50 - 74 = high
    score, level = probability_to_score_and_level(0.50)
    assert score == 50
    assert level == "high"

    score, level = probability_to_score_and_level(0.74)
    assert score == 74
    assert level == "high"

    # 75 - 100 = critical
    score, level = probability_to_score_and_level(0.75)
    assert score == 75
    assert level == "critical"

    score, level = probability_to_score_and_level(0.99)
    assert score == 99
    assert level == "critical"


def test_probability_clamping() -> None:
    score, level = probability_to_score_and_level(1.50)
    assert score == 100
    assert level == "critical"

    score, level = probability_to_score_and_level(-0.20)
    assert score == 0
    assert level == "low"


def test_baseline_logistic_model_prediction_structure() -> None:
    model = BaselineLogisticRiskModel()
    pred = model.predict(
        {
            "incident_severity": 10.0,
            "correlation_severity": 10.0,
            "alert_count": 3.0,
            "event_count": 5.0,
            "correlation_count": 1.0,
            "mitre_count": 2.0,
            "has_auth_attack": 1.0,
            "has_suspicious_process": 1.0,
            "has_network_activity": 0.0,
            "has_privilege_escalation": 0.0,
            "time_span_seconds": 60.0,
            "entity_diversity": 2.0,
        }
    )
    assert 0 <= pred.risk_score <= 100
    assert pred.risk_level in ["low", "medium", "high", "critical"]
    assert 0.0 <= pred.probability <= 1.0
    assert isinstance(pred.reason_codes, list)
    assert isinstance(pred.feature_contributions, dict)
    assert pred.model_name == "baseline_logistic_regression"
    assert pred.model_version == "v1.0"
    assert pred.feature_version == "v2.0"


def test_model_deterministic_prediction() -> None:
    model = BaselineLogisticRiskModel()
    input_data = {
        "incident_severity": 12.0,
        "correlation_severity": 12.0,
        "alert_count": 4.0,
        "event_count": 8.0,
        "correlation_count": 2.0,
        "mitre_count": 3.0,
        "has_auth_attack": 1.0,
        "has_suspicious_process": 1.0,
        "has_network_activity": 1.0,
        "has_privilege_escalation": 1.0,
        "time_span_seconds": 300.0,
        "entity_diversity": 3.0,
    }
    p1 = model.predict(input_data)
    p2 = model.predict(input_data)
    assert p1.risk_score == p2.risk_score
    assert p1.risk_level == p2.risk_level
    assert p1.probability == p2.probability
    assert p1.reason_codes == p2.reason_codes
    assert p1.feature_contributions == p2.feature_contributions


def test_low_vs_critical_scoring_separation() -> None:
    model = BaselineLogisticRiskModel()
    low_input = {
        "incident_severity": 2.0,
        "correlation_severity": 2.0,
        "alert_count": 1.0,
        "event_count": 1.0,
        "correlation_count": 1.0,
        "mitre_count": 0.0,
        "has_auth_attack": 0.0,
        "has_suspicious_process": 0.0,
        "has_network_activity": 0.0,
        "has_privilege_escalation": 0.0,
        "time_span_seconds": 0.0,
        "entity_diversity": 1.0,
    }
    crit_input = {
        "incident_severity": 14.0,
        "correlation_severity": 14.0,
        "alert_count": 6.0,
        "event_count": 12.0,
        "correlation_count": 2.0,
        "mitre_count": 4.0,
        "has_auth_attack": 1.0,
        "has_suspicious_process": 1.0,
        "has_network_activity": 1.0,
        "has_privilege_escalation": 1.0,
        "time_span_seconds": 600.0,
        "entity_diversity": 4.0,
    }
    low_pred = model.predict(low_input)
    crit_pred = model.predict(crit_input)

    assert low_pred.risk_level == "low"
    assert low_pred.risk_score < 25
    assert crit_pred.risk_level in ["high", "critical"]
    assert crit_pred.risk_score >= 50
    assert crit_pred.risk_score > low_pred.risk_score
