from datetime import datetime, timedelta, timezone

from backend.app.models.alerts import Alert, AlertStatus
from backend.app.models.events import NormalizedEvent
from backend.app.persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
)
from backend.app.rules.correlation_builtin import get_default_correlation_rules
from backend.app.services.correlation import CorrelationEngine


def make_event(event_id: str, host: str = "srv-1", user: str = "admin") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type="authentication_failure",
        severity=6,
        message="Auth failure",
        host=host,
        user=user,
    )


def make_alert(
    alert_id: str,
    event_id: str,
    rule_id: str = "builtin-003",
    timestamp: datetime | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        event_id=event_id,
        timestamp=timestamp or datetime.now(timezone.utc),
        rule_id=rule_id,
        rule_name="Authentication Failure",
        severity=6,
        description="Auth fail",
        source="test",
        evidence={"user": "admin"},
        mitre_techniques=["T1110"],
        status=AlertStatus.NEW,
    )


def test_generate_correlation_id_is_deterministic() -> None:
    id1 = CorrelationEngine.generate_correlation_id("auth_attack_sequence", "user:admin", "a1")
    id2 = CorrelationEngine.generate_correlation_id("auth_attack_sequence", "user:admin", "a1")
    assert id1 == id2
    assert id1.startswith("corr-")


def test_different_inputs_generate_different_correlation_ids() -> None:
    id1 = CorrelationEngine.generate_correlation_id("auth_attack_sequence", "user:admin", "a1")
    id2 = CorrelationEngine.generate_correlation_id("auth_attack_sequence", "user:root", "a1")
    id3 = CorrelationEngine.generate_correlation_id("same_entity", "user:admin", "a1")
    id4 = CorrelationEngine.generate_correlation_id("auth_attack_sequence", "user:admin", "a2")
    assert len({id1, id2, id3, id4}) == 4


def test_correlation_engine_creates_new_correlation(db_session) -> None:
    event_repo = EventRepository(db_session)
    alert_repo = AlertRepository(db_session)
    corr_repo = CorrelationRepository(db_session)

    engine = CorrelationEngine(
        rules=get_default_correlation_rules(),
        correlation_repository=corr_repo,
        alert_repository=alert_repo,
        event_repository=event_repo,
    )

    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    # Event 1 + Alert 1
    e1 = make_event("e1", user="target_user")
    e1.timestamp = base_time
    event_repo.create_event(e1)
    alert_repo.create_alert(make_alert("a1", "e1", timestamp=base_time))

    # Event 2 + Alert 2
    e2 = make_event("e2", user="target_user")
    event_repo.create_event(e2)
    alert_repo.create_alert(make_alert("a2", "e2"))

    result = engine.correlate_event_alerts(e2, ["a2"])
    assert len(result.correlations_created) >= 1
    created_id = result.correlations_created[0]

    stored = corr_repo.get_correlation(created_id)
    assert stored is not None
    assert stored.correlation_type == "auth_attack_sequence"
    assert stored.entity_key == "user:target_user"
    assert stored.alert_count == 2

    # Check audit
    audits = event_repo.list_audit_events(created_id)
    assert len(audits) == 1
    assert audits[0].action == "correlation.created"


def test_correlation_engine_updates_existing_open_correlation(db_session) -> None:
    event_repo = EventRepository(db_session)
    alert_repo = AlertRepository(db_session)
    corr_repo = CorrelationRepository(db_session)

    engine = CorrelationEngine(
        rules=get_default_correlation_rules(),
        correlation_repository=corr_repo,
        alert_repository=alert_repo,
        event_repository=event_repo,
    )

    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)

    # First pair
    e1 = make_event("e10", user="target_user2")
    e1.timestamp = base_time
    event_repo.create_event(e1)
    alert_repo.create_alert(make_alert("a10", "e10", timestamp=base_time))

    e2 = make_event("e20", user="target_user2")
    event_repo.create_event(e2)
    alert_repo.create_alert(make_alert("a20", "e20"))

    res1 = engine.correlate_event_alerts(e2, ["a20"])
    assert len(res1.correlations_created) == 1
    corr_id = res1.correlations_created[0]

    # Third alert arrives
    e3 = make_event("e30", user="target_user2")
    event_repo.create_event(e3)
    alert_repo.create_alert(make_alert("a30", "e30"))

    res2 = engine.correlate_event_alerts(e3, ["a30"])
    assert corr_id in res2.correlations_updated

    stored = corr_repo.get_correlation(corr_id)
    assert stored is not None
    assert stored.alert_count == 3

    audits = event_repo.list_audit_events(corr_id)
    assert len(audits) == 2
    actions = [a.action for a in audits]
    assert "correlation.created" in actions
    assert "correlation.updated" in actions
