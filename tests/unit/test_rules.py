from datetime import datetime, timezone

from backend.app.models.events import NormalizedEvent
from backend.app.rules import (
    AuthenticationFailureRule,
    HighSeverityRule,
    NetworkConnectionAnomalyRule,
    PrivilegeEscalationRule,
    SuspiciousProcessRule,
    get_default_rules,
)


def make_event(
    event_id: str = "evt-1",
    event_type: str = "process_start",
    severity: int = 3,
    message: str = "Test message",
    **kwargs,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type=event_type,
        severity=severity,
        message=message,
        **kwargs,
    )


def test_high_severity_rule_matches_above_threshold() -> None:
    rule = HighSeverityRule()
    event = make_event(severity=10)
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "builtin-001"
    assert match.severity == 10
    assert match.evidence["matched_field"] == "severity"


def test_high_severity_rule_ignores_low_severity() -> None:
    rule = HighSeverityRule()
    event = make_event(severity=9)
    assert rule.evaluate(event) is None


def test_suspicious_process_rule_matches_suspicious_path() -> None:
    rule = SuspiciousProcessRule()
    event = make_event(event_type="process_start", message="executed /tmp/evil.sh")
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "builtin-002"
    assert "T1059" in match.mitre_techniques
    assert "/tmp/" in match.evidence["indicators_matched"]


def test_suspicious_process_rule_ignores_normal_process() -> None:
    rule = SuspiciousProcessRule()
    event = make_event(event_type="process_start", message="executed /usr/bin/python")
    assert rule.evaluate(event) is None


def test_suspicious_process_rule_ignores_non_process_event() -> None:
    rule = SuspiciousProcessRule()
    event = make_event(event_type="file_read", message="read /tmp/somefile")
    assert rule.evaluate(event) is None


def test_auth_failure_rule_matches() -> None:
    rule = AuthenticationFailureRule()
    event = make_event(event_type="authentication_failure", user="admin", source_ip="10.0.0.1")
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "builtin-003"
    assert "T1110" in match.mitre_techniques
    assert match.evidence["user"] == "admin"


def test_auth_failure_rule_ignores_other_types() -> None:
    rule = AuthenticationFailureRule()
    event = make_event(event_type="login", user="admin")
    assert rule.evaluate(event) is None


def test_network_rule_matches_with_destination() -> None:
    rule = NetworkConnectionAnomalyRule()
    event = make_event(
        event_type="network_connection",
        source_ip="192.168.1.5",
        destination_ip="198.51.100.2",
    )
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "builtin-004"
    assert "T1071" in match.mitre_techniques
    assert match.evidence["destination_ip"] == "198.51.100.2"


def test_network_rule_ignores_without_destination() -> None:
    rule = NetworkConnectionAnomalyRule()
    event = make_event(event_type="network_connection", destination_ip=None)
    assert rule.evaluate(event) is None


def test_privilege_escalation_rule_matches_by_type() -> None:
    rule = PrivilegeEscalationRule()
    event = make_event(event_type="privilege_escalation", user="root")
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "builtin-005"
    assert "T1548" in match.mitre_techniques


def test_privilege_escalation_rule_matches_by_message() -> None:
    rule = PrivilegeEscalationRule()
    event = make_event(event_type="custom_audit", message="detected privilege change")
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_id == "builtin-005"


def test_all_rules_have_unique_ids() -> None:
    rules = get_default_rules()
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids))
    assert len(rules) == 11


def test_evidence_contains_no_raw_metadata() -> None:
    rules = get_default_rules()
    event = make_event(
        event_type="process_start",
        severity=12,
        message="executed /tmp/exploit.sh with privilege elevation",
        destination_ip="10.0.0.1",
        metadata={"secret_token": "secret-12345", "raw_dump": "sensitive data"},
    )
    for rule in rules:
        match = rule.evaluate(event)
        if match is not None:
            # Evidence must not contain raw metadata dict or secret keys
            assert "secret_token" not in match.evidence
            assert "raw_dump" not in match.evidence
            assert "metadata" not in match.evidence
