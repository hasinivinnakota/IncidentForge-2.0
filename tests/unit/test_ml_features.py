from datetime import datetime, timedelta, timezone

from backend.app.ml.features import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    extract_features,
    generate_reason_codes,
)
from backend.app.models.correlation import Correlation, CorrelationStatus
from backend.app.models.incidents import Incident, IncidentStatus


def make_test_incident(
    severity: int = 10,
    tags: list[str] | None = None,
    alerts: list[str] | None = None,
) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id="inc-feat-1",
        title="Security Incident: Multiple Failed Logins",
        description="Password failure for admin, executed /tmp/bad.sh password=secret123 token=abc",
        severity=severity,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
        first_seen=now - timedelta(minutes=10),
        last_seen=now,
        correlation_ids=["corr-1"],
        alert_ids=alerts or ["a1", "a2", "a3"],
        event_ids=["e1", "e2"],
        mitre_techniques=["T1110", "T1059"],
        evidence={"alert_count": 3},
        tags=tags or ["auth_attack_sequence", "host-01"],
    )


def test_extract_features_all_numeric_bounded() -> None:
    inc = make_test_incident()
    feats = extract_features(inc)

    for name in FEATURE_NAMES:
        assert name in feats
        assert isinstance(feats[name], float)
        assert not math_isnan(feats[name])
        assert feats[name] >= 0.0


def test_extract_features_handles_missing_correlation() -> None:
    inc = make_test_incident()
    feats = extract_features(inc, correlation=None)
    assert feats["correlation_severity"] == float(inc.severity)
    assert feats["alert_count"] == 3.0
    assert feats["mitre_count"] == 2.0


def test_extract_features_with_correlation() -> None:
    now = datetime.now(timezone.utc)
    corr = Correlation(
        correlation_id="corr-1",
        correlation_type="privilege_escalation_sequence",
        entity_key="host:workstation",
        title="Privilege Escalation Detected",
        description="root privilege escalation",
        severity=14,
        status=CorrelationStatus.OPEN,
        first_seen=now,
        last_seen=now,
        alert_ids=["a1"],
        event_ids=["e1"],
        alert_count=1,
    )
    inc = make_test_incident()
    feats = extract_features(inc, correlation=corr)
    assert feats["correlation_severity"] == 14.0
    assert feats["has_privilege_escalation"] == 1.0


def test_extract_features_no_secrets_leakage() -> None:
    inc = make_test_incident()
    feats = extract_features(inc)
    features_str = str(feats).lower()
    assert "secret123" not in features_str
    assert "password" not in features_str
    assert "token" not in features_str


def test_feature_names_matches_schema_version() -> None:
    assert FEATURE_VERSION == "v2.0"
    assert len(FEATURE_NAMES) == 23


def test_reason_codes_generation_deterministic() -> None:
    feats = {
        "incident_severity": 12.0,
        "correlation_severity": 12.0,
        "alert_count": 4.0,
        "mitre_count": 2.0,
        "has_auth_attack": 1.0,
        "has_suspicious_process": 1.0,
        "has_network_activity": 1.0,
        "has_privilege_escalation": 1.0,
    }
    reasons = generate_reason_codes(feats, risk_score=85)
    assert "AUTHENTICATION_ATTACK" in reasons
    assert "PRIVILEGE_ESCALATION" in reasons
    assert "HIGH_ALERT_VOLUME" in reasons
    assert "MULTIPLE_MITRE_TECHNIQUES" in reasons
    assert "HIGH_INCIDENT_SEVERITY" in reasons
    assert reasons == sorted(reasons)


def test_reason_codes_fallback_baseline() -> None:
    reasons = generate_reason_codes({}, risk_score=5)
    assert reasons == ["BASELINE_RISK_FACTORS"]


def math_isnan(v: float) -> bool:
    import math

    return math.isnan(v)
