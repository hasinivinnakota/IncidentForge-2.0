from datetime import datetime, timedelta, timezone

from sqlmodel import SQLModel

from backend.app.database import init_db
from backend.app.models.incidents import Incident, IncidentStatus
from backend.app.persistence.repositories import IncidentRepository


def make_incident(
    incident_id: str = "inc-001",
    correlation_id: str = "corr-001",
    status: IncidentStatus = IncidentStatus.OPEN,
    severity: int = 10,
) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=incident_id,
        title=f"Incident {incident_id}",
        description=f"Description for {incident_id}",
        severity=severity,
        status=status,
        created_at=now,
        updated_at=now,
        first_seen=now - timedelta(minutes=10),
        last_seen=now,
        correlation_ids=[correlation_id],
        alert_ids=["a1", "a2"],
        event_ids=["e1", "e2"],
        mitre_techniques=["T1110"],
        evidence={"alert_count": 2},
        tags=["auth_attack_sequence"],
    )


def test_incident_table_initializes(test_engine) -> None:
    init_db(test_engine)
    assert "incident" in SQLModel.metadata.tables


def test_incident_persists_and_retrieves(db_session) -> None:
    repo = IncidentRepository(db_session)
    inc = make_incident("inc-p1")
    result = repo.create_incident(inc)
    assert result.created is True
    assert result.incident.id is not None

    fetched = repo.get_incident("inc-p1")
    assert fetched is not None
    assert fetched.incident_id == "inc-p1"
    assert fetched.severity == 10
    assert fetched.status == "open"


def test_duplicate_incident_id_returns_existing(db_session) -> None:
    repo = IncidentRepository(db_session)
    first = repo.create_incident(make_incident("inc-dup"))
    second = repo.create_incident(make_incident("inc-dup"))
    assert first.created is True
    assert second.created is False
    assert second.incident.id == first.incident.id
    assert len(repo.list_incidents()) == 1


def test_update_incident_updates_fields(db_session) -> None:
    repo = IncidentRepository(db_session)
    initial = make_incident("inc-upd")
    repo.create_incident(initial)

    updated_inc = make_incident("inc-upd", severity=14)
    updated_inc.description = "Updated description"
    updated_inc.alert_ids = ["a1", "a2", "a3"]

    rec = repo.update_incident(updated_inc)
    assert rec is not None
    assert rec.severity == 14
    assert rec.description == "Updated description"

    fetched = repo.get_incident("inc-upd")
    assert fetched is not None
    assert "a3" in fetched.alert_ids_json


def test_update_incident_status(db_session) -> None:
    repo = IncidentRepository(db_session)
    repo.create_incident(make_incident("inc-status"))

    updated = repo.update_incident_status("inc-status", "investigating")
    assert updated is not None
    assert updated.status == "investigating"

    # Non-existent
    assert repo.update_incident_status("nonexistent", "closed") is None


def test_find_by_correlation_id(db_session) -> None:
    repo = IncidentRepository(db_session)
    repo.create_incident(make_incident("inc-corr", correlation_id="corr-xyz-99"))

    found = repo.find_by_correlation_id("corr-xyz-99")
    assert found is not None
    assert found.incident_id == "inc-corr"

    assert repo.find_by_correlation_id("nonexistent-corr") is None


def test_list_incidents_filters(db_session) -> None:
    repo = IncidentRepository(db_session)
    repo.create_incident(
        make_incident("i1", correlation_id="c1", status=IncidentStatus.OPEN, severity=8)
    )
    repo.create_incident(
        make_incident("i2", correlation_id="c2", status=IncidentStatus.CLOSED, severity=14)
    )

    open_incidents = repo.list_incidents(status="open")
    assert len(open_incidents) == 1
    assert open_incidents[0].incident_id == "i1"

    high_sev = repo.list_incidents(min_severity=10)
    assert len(high_sev) == 1
    assert high_sev[0].incident_id == "i2"

    by_corr = repo.list_incidents(correlation_id="c1")
    assert len(by_corr) == 1
    assert by_corr[0].incident_id == "i1"
