from datetime import datetime, timedelta, timezone

from backend.app.models.correlation import CorrelatableAlert
from backend.app.rules import (
    AuthenticationAttackSequenceRule,
    PrivilegeEscalationSequenceRule,
    ProcessNetworkSequenceRule,
    SameEntityCorrelationRule,
    get_default_correlation_rules,
)


def make_alert(
    alert_id: str,
    event_id: str = "evt-1",
    rule_id: str = "builtin-003",
    rule_name: str = "Authentication Failure",
    severity: int = 6,
    timestamp: datetime | None = None,
    host: str | None = "host-01",
    user: str | None = "admin",
    source_ip: str | None = "192.168.1.10",
    destination_ip: str | None = None,
    mitre: list[str] | None = None,
    evidence: dict | None = None,
) -> CorrelatableAlert:
    return CorrelatableAlert(
        alert_id=alert_id,
        event_id=event_id,
        timestamp=timestamp or datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        source="test",
        host=host,
        user=user,
        source_ip=source_ip,
        destination_ip=destination_ip,
        mitre_techniques=mitre or [],
        evidence=evidence or {},
    )


def test_auth_sequence_matches_multiple_failures_within_window() -> None:
    rule = AuthenticationAttackSequenceRule(window_seconds=900)
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    prior = make_alert("a1", timestamp=base_time, user="admin")
    incoming = make_alert("a2", timestamp=base_time + timedelta(minutes=5), user="admin")

    match = rule.evaluate(incoming, [prior])
    assert match is not None
    assert match.correlation_type == "auth_attack_sequence"
    assert match.entity_key == "user:admin"
    assert match.matched_alert_ids == ["a1", "a2"]
    assert "T1110" in match.mitre_techniques


def test_auth_sequence_does_not_match_single_failure() -> None:
    rule = AuthenticationAttackSequenceRule()
    incoming = make_alert("a1", user="admin")
    match = rule.evaluate(incoming, [])
    assert match is None


def test_auth_sequence_does_not_match_outside_window() -> None:
    rule = AuthenticationAttackSequenceRule(window_seconds=900)
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    prior = make_alert("a1", timestamp=base_time, user="admin")
    incoming = make_alert("a2", timestamp=base_time + timedelta(minutes=20), user="admin")

    match = rule.evaluate(incoming, [prior])
    assert match is None


def test_auth_sequence_does_not_match_different_entities() -> None:
    rule = AuthenticationAttackSequenceRule()
    prior = make_alert("a1", user="alice")
    incoming = make_alert("a2", user="bob")

    match = rule.evaluate(incoming, [prior])
    assert match is None


def test_process_network_matches_on_same_host() -> None:
    rule = ProcessNetworkSequenceRule(window_seconds=1800)
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    process_alert = make_alert(
        "proc-1",
        rule_id="builtin-002",
        rule_name="Suspicious Process Execution",
        severity=10,
        host="workstation-01",
        timestamp=base_time,
    )
    network_alert = make_alert(
        "net-1",
        rule_id="builtin-004",
        rule_name="Network Connection Anomaly",
        severity=6,
        host="workstation-01",
        timestamp=base_time + timedelta(minutes=10),
    )

    match = rule.evaluate(network_alert, [process_alert])
    assert match is not None
    assert match.correlation_type == "process_network_sequence"
    assert match.entity_key == "host:workstation-01"
    assert "proc-1" in match.matched_alert_ids
    assert "net-1" in match.matched_alert_ids
    assert "T1059" in match.mitre_techniques
    assert "T1071" in match.mitre_techniques


def test_process_network_does_not_match_different_hosts() -> None:
    rule = ProcessNetworkSequenceRule()
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    process_alert = make_alert("proc-1", rule_id="builtin-002", host="host-A", timestamp=base_time)
    network_alert = make_alert("net-1", rule_id="builtin-004", host="host-B", timestamp=base_time)

    match = rule.evaluate(network_alert, [process_alert])
    assert match is None


def test_process_network_does_not_match_outside_window() -> None:
    rule = ProcessNetworkSequenceRule(window_seconds=1800)
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    process_alert = make_alert("proc-1", rule_id="builtin-002", host="host-A", timestamp=base_time)
    network_alert = make_alert(
        "net-1", rule_id="builtin-004", host="host-A", timestamp=base_time + timedelta(minutes=45)
    )

    match = rule.evaluate(network_alert, [process_alert])
    assert match is None


def test_privilege_escalation_sequence_matches() -> None:
    rule = PrivilegeEscalationSequenceRule(window_seconds=1800)
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    proc_alert = make_alert(
        "proc-1", rule_id="builtin-002", user="attacker", host="srv-1", timestamp=base_time
    )
    priv_alert = make_alert(
        "priv-1",
        rule_id="builtin-005",
        rule_name="Privilege Escalation Indicator",
        user="attacker",
        host="srv-1",
        severity=12,
        timestamp=base_time + timedelta(minutes=5),
    )

    match = rule.evaluate(priv_alert, [proc_alert])
    assert match is not None
    assert match.correlation_type == "privilege_escalation_sequence"
    assert match.entity_key == "user:attacker"
    assert "T1548" in match.mitre_techniques
    assert match.severity == 14


def test_privilege_escalation_does_not_match_without_prior_activity() -> None:
    rule = PrivilegeEscalationSequenceRule()
    priv_alert = make_alert("priv-1", rule_id="builtin-005")
    match = rule.evaluate(priv_alert, [])
    assert match is None


def test_same_entity_correlation_matches_distinct_rules() -> None:
    rule = SameEntityCorrelationRule(window_seconds=1800)
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    alert1 = make_alert("a1", rule_id="builtin-001", host="server-01", timestamp=base_time)
    alert2 = make_alert(
        "a2", rule_id="builtin-003", host="server-01", timestamp=base_time + timedelta(minutes=2)
    )

    match = rule.evaluate(alert2, [alert1])
    assert match is not None
    assert match.correlation_type == "same_entity"
    assert match.entity_key == "host:server-01"
    assert match.matched_alert_ids == ["a1", "a2"]


def test_same_entity_correlation_does_not_match_single_alert() -> None:
    rule = SameEntityCorrelationRule()
    alert = make_alert("a1", host="server-01")
    assert rule.evaluate(alert, []) is None


def test_safe_evidence_no_sensitive_fields() -> None:
    rules = get_default_correlation_rules()
    alert1 = make_alert(
        "a1",
        evidence={"password": "secret", "token": "abc", "matched_field": "test"},
        host="srv-1",
    )
    alert2 = make_alert("a2", host="srv-1")

    for rule in rules:
        match = rule.evaluate(alert2, [alert1])
        if match is not None:
            evidence_str = str(match.evidence).lower()
            assert "password" not in evidence_str
            assert "secret" not in evidence_str
            assert "token" not in evidence_str
