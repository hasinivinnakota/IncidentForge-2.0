from datetime import datetime, timezone

from backend.app.models.events import NormalizedEvent
from backend.app.models.rules import DetectionMatch
from backend.app.persistence.repositories import AlertRepository, EventRepository
from backend.app.services.alerts import AlertService


def make_event(event_id: str = "evt-1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type="process_start",
        severity=10,
        message="Suspicious process",
    )


def make_match(event_id: str = "evt-1", rule_id: str = "builtin-001") -> DetectionMatch:
    return DetectionMatch(
        rule_id=rule_id,
        rule_name="Test Rule",
        event_id=event_id,
        severity=10,
        description="Matched test rule",
        mitre_techniques=["T1059"],
        evidence={"matched_field": "severity"},
    )


def test_alert_id_is_deterministic() -> None:
    id1 = AlertService.generate_alert_id("evt-1", "builtin-001")
    id2 = AlertService.generate_alert_id("evt-1", "builtin-001")
    assert id1 == id2
    assert id1.startswith("alert-")


def test_different_inputs_produce_different_ids() -> None:
    id1 = AlertService.generate_alert_id("evt-1", "builtin-001")
    id2 = AlertService.generate_alert_id("evt-2", "builtin-001")
    id3 = AlertService.generate_alert_id("evt-1", "builtin-002")
    assert id1 != id2
    assert id1 != id3


def test_alert_created_from_match(db_session) -> None:
    event_repo = EventRepository(db_session)
    alert_repo = AlertRepository(db_session)
    service = AlertService(alert_repo, event_repo)

    event = make_event("evt-10")
    event_repo.create_event(event)

    matches = [make_match("evt-10", "builtin-001")]
    alert_ids = service.create_alerts_from_matches(event, matches)

    assert len(alert_ids) == 1
    alert_id = alert_ids[0]

    stored = alert_repo.get_alert(alert_id)
    assert stored is not None
    assert stored.event_id == "evt-10"
    assert stored.rule_id == "builtin-001"

    audits = event_repo.list_audit_events(alert_id)
    assert len(audits) == 1
    assert audits[0].action == "alert.created"


def test_duplicate_match_produces_duplicate_audit(db_session) -> None:
    event_repo = EventRepository(db_session)
    alert_repo = AlertRepository(db_session)
    service = AlertService(alert_repo, event_repo)

    event = make_event("evt-20")
    event_repo.create_event(event)

    matches = [make_match("evt-20", "builtin-001")]
    # First time
    ids1 = service.create_alerts_from_matches(event, matches)
    # Second time (same event and rule)
    ids2 = service.create_alerts_from_matches(event, matches)

    assert ids1 == ids2
    alert_id = ids1[0]

    # Only 1 alert row stored
    assert len(alert_repo.list_alerts_by_event("evt-20")) == 1

    # 2 audit events: alert.created, alert.duplicate
    audits = event_repo.list_audit_events(alert_id)
    assert len(audits) == 2
    actions = [a.action for a in audits]
    assert "alert.created" in actions
    assert "alert.duplicate" in actions
