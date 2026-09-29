from datetime import datetime, timezone

from sqlmodel import SQLModel

from backend.app.database import init_db
from backend.app.models.alerts import Alert as DomainAlert, AlertStatus
from backend.app.models.events import NormalizedEvent
from backend.app.persistence.models import AuditEvent
from backend.app.persistence.repositories import AlertRepository, EventRepository


def make_event(event_id: str) -> NormalizedEvent:
    return NormalizedEvent(event_id=event_id, timestamp=datetime.now(timezone.utc), source="test", event_type="login", severity=4, message="observed", metadata={"raw": True})


def make_alert(alert_id: str, event_id: str = "evt-1") -> DomainAlert:
    return DomainAlert(
        alert_id=alert_id,
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        rule_id="builtin-001",
        rule_name="High Severity Event",
        severity=10,
        description="High severity detected",
        source="test",
        evidence={"threshold": 10},
        mitre_techniques=[],
        status=AlertStatus.NEW,
    )


def test_database_initializes_successfully(test_engine) -> None:
    init_db(test_engine)
    assert "event" in SQLModel.metadata.tables
    assert "alert" in SQLModel.metadata.tables


def test_database_initializes_and_persists_event(db_session) -> None:
    repository = EventRepository(db_session)
    stored = repository.create_event(make_event("evt-1")).event
    assert stored.id is not None
    assert repository.get_event("evt-1").message == "observed"


def test_recent_events_are_listed(db_session) -> None:
    repository = EventRepository(db_session)
    repository.create_event(make_event("evt-1"))
    repository.create_event(make_event("evt-2"))
    assert {event.event_id for event in repository.list_recent_events()} == {"evt-1", "evt-2"}


def test_duplicate_event_id_returns_existing_record(db_session) -> None:
    repository = EventRepository(db_session)
    first = repository.create_event(make_event("evt-1")).event
    second = repository.create_event(make_event("evt-1")).event
    assert second.id == first.id
    assert len(repository.list_recent_events()) == 1


def test_audit_event_persists(db_session) -> None:
    repository = EventRepository(db_session)
    audit = AuditEvent(audit_id="audit-1", timestamp=datetime.now(timezone.utc), actor="test", action="accept", target="evt-1", result="ok")
    stored = repository.create_audit_event(audit)
    assert stored.id is not None


def test_alert_persists_and_retrieves(db_session) -> None:
    repository = AlertRepository(db_session)
    result = repository.create_alert(make_alert("alert-001"))
    assert result.created is True
    assert result.alert.id is not None

    fetched = repository.get_alert("alert-001")
    assert fetched is not None
    assert fetched.rule_id == "builtin-001"
    assert fetched.severity == 10


def test_duplicate_alert_id_returns_existing(db_session) -> None:
    repository = AlertRepository(db_session)
    first = repository.create_alert(make_alert("alert-dup"))
    second = repository.create_alert(make_alert("alert-dup"))
    assert first.created is True
    assert second.created is False
    assert second.alert.id == first.alert.id
    assert len(repository.list_alerts()) == 1


def test_list_alerts_by_event(db_session) -> None:
    repository = AlertRepository(db_session)
    repository.create_alert(make_alert("alert-e1-a", event_id="evt-100"))
    repository.create_alert(make_alert("alert-e1-b", event_id="evt-100"))
    repository.create_alert(make_alert("alert-e2-a", event_id="evt-200"))

    e1_alerts = repository.list_alerts_by_event("evt-100")
    assert len(e1_alerts) == 2
    assert {a.alert_id for a in e1_alerts} == {"alert-e1-a", "alert-e1-b"}

    e2_alerts = repository.list_alerts_by_event("evt-200")
    assert len(e2_alerts) == 1
    assert e2_alerts[0].alert_id == "alert-e2-a"