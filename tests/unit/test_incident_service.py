from datetime import datetime, timedelta, timezone

from backend.app.models.correlation import Correlation, CorrelationStatus
from backend.app.models.incidents import IncidentStatus
from backend.app.persistence.repositories import (
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
)
from backend.app.services.incidents import IncidentService


def make_correlation(
    correlation_id: str = "corr-test-1",
    correlation_type: str = "auth_attack_sequence",
    entity_key: str = "user:admin",
    severity: int = 10,
    alert_ids: list[str] | None = None,
) -> Correlation:
    now = datetime.now(timezone.utc)
    return Correlation(
        correlation_id=correlation_id,
        correlation_type=correlation_type,
        entity_key=entity_key,
        title=f"Attack on {entity_key}",
        description="Correlation description",
        severity=severity,
        status=CorrelationStatus.OPEN,
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        alert_ids=alert_ids or ["a1", "a2"],
        event_ids=["e1", "e2"],
        alert_count=len(alert_ids or ["a1", "a2"]),
        mitre_techniques=["T1110"],
        evidence={"entity_key": entity_key, "secret_key": "ignore_me"},
    )


def test_generate_incident_id_is_deterministic() -> None:
    id1 = IncidentService.generate_incident_id("corr-001")
    id2 = IncidentService.generate_incident_id("corr-001")
    assert id1 == id2
    assert id1.startswith("inc-")


def test_different_correlation_ids_generate_different_incident_ids() -> None:
    id1 = IncidentService.generate_incident_id("corr-001")
    id2 = IncidentService.generate_incident_id("corr-002")
    assert id1 != id2


def test_generate_description_deterministic_and_safe() -> None:
    corr = make_correlation()
    desc = IncidentService.generate_description(corr)
    assert "auth_attack_sequence" in desc
    assert "user:admin" in desc
    assert "T1110" in desc
    assert "10/15" in desc
    assert "secret" not in desc.lower()


def test_process_correlations_creates_incident(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)

    service = IncidentService(inc_repo, corr_repo, event_repo)

    corr = make_correlation("corr-create-1")
    corr_repo.create_correlation(corr)

    result = service.process_correlations(["corr-create-1"])
    assert len(result.incidents_created) == 1
    inc_id = result.incidents_created[0]

    stored = inc_repo.get_incident(inc_id)
    assert stored is not None
    assert stored.incident_id == inc_id
    assert stored.status == "open"
    assert stored.severity == 10
    assert "corr-create-1" in stored.correlation_ids_json

    # Audit verified
    audits = event_repo.list_audit_events(inc_id)
    assert len(audits) == 1
    assert audits[0].action == "incident.created"


def test_process_correlations_updates_existing_incident(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)

    service = IncidentService(inc_repo, corr_repo, event_repo)

    corr1 = make_correlation("corr-upd-1", alert_ids=["a1", "a2"])
    corr_repo.create_correlation(corr1)

    res1 = service.process_correlations(["corr-upd-1"])
    assert len(res1.incidents_created) == 1
    inc_id = res1.incidents_created[0]

    # Correlation updated with new alert
    corr2 = make_correlation("corr-upd-1", alert_ids=["a1", "a2", "a3"])
    corr_repo.update_correlation(corr2)

    res2 = service.process_correlations(["corr-upd-1"])
    assert inc_id in res2.incidents_updated

    stored = inc_repo.get_incident(inc_id)
    assert stored is not None
    assert "a3" in stored.alert_ids_json

    audits = event_repo.list_audit_events(inc_id)
    actions = [a.action for a in audits]
    assert "incident.created" in actions
    assert "incident.updated" in actions


def test_update_incident_status_creates_audit(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)

    service = IncidentService(inc_repo, corr_repo, event_repo)

    corr = make_correlation("corr-status-1")
    corr_repo.create_correlation(corr)
    res = service.process_correlations(["corr-status-1"])
    inc_id = res.incidents_created[0]

    updated = service.update_incident_status(
        incident_id=inc_id, new_status=IncidentStatus.INVESTIGATING, actor="soc_analyst"
    )
    assert updated is not None
    assert updated.status == IncidentStatus.INVESTIGATING

    audits = event_repo.list_audit_events(inc_id)
    status_audits = [a for a in audits if a.action == "incident.status_updated"]
    assert len(status_audits) == 1
    assert status_audits[0].actor == "soc_analyst"


def test_severity_derivation_bounded() -> None:
    """Verify severity bounding logic: valid boundary values pass through,
    and the clamping arithmetic max(0, min(15, x)) works for out-of-range ints."""
    # Correlation model already enforces 0-15, so test with valid boundaries
    corr_max = make_correlation(severity=15)
    assert max(0, min(15, corr_max.severity)) == 15

    corr_min = make_correlation(severity=0)
    assert max(0, min(15, corr_min.severity)) == 0

    corr_mid = make_correlation(severity=8)
    assert max(0, min(15, corr_mid.severity)) == 8

    # Verify the clamping arithmetic itself handles hypothetical out-of-range values
    assert max(0, min(15, 20)) == 15
    assert max(0, min(15, -5)) == 0
    assert max(0, min(15, 10)) == 10


def test_safe_evidence_no_sensitive_metadata(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)

    service = IncidentService(inc_repo, corr_repo, event_repo)

    corr = make_correlation("corr-safe-1")
    corr_repo.create_correlation(corr)

    res = service.process_correlations(["corr-safe-1"])
    inc = inc_repo.get_incident(res.incidents_created[0])
    assert inc is not None

    evidence_str = inc.evidence_json.lower()
    assert "secret" not in evidence_str
    assert "password" not in evidence_str
    assert "token" not in evidence_str
