from datetime import datetime, timedelta, timezone

from backend.app.models.correlation import Correlation, CorrelationStatus
from backend.app.models.incidents import Incident, IncidentStatus
from backend.app.models.risk import RiskLevel
from backend.app.persistence.repositories import (
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    RiskAssessmentRepository,
)
from backend.app.services.risk import RiskScoringService


def make_test_incident_for_db(
    incident_id: str = "inc-risk-001",
    severity: int = 12,
    correlation_id: str = "corr-risk-001",
) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=incident_id,
        title=f"Incident {incident_id}",
        description="Correlated incident description",
        severity=severity,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        correlation_ids=[correlation_id],
        alert_ids=["a1", "a2", "a3"],
        event_ids=["e1", "e2"],
        mitre_techniques=["T1110", "T1059"],
        evidence={"alert_count": 3},
        tags=["auth_attack_sequence", "host-01"],
    )


def test_risk_scoring_service_scores_incident(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)
    risk_repo = RiskAssessmentRepository(db_session)

    service = RiskScoringService(risk_repo, inc_repo, corr_repo, event_repo)

    incident = make_test_incident_for_db("inc-r1", severity=10)
    inc_repo.create_incident(incident)

    assessment = service.score_incident("inc-r1")
    assert assessment is not None
    assert assessment.incident_id == "inc-r1"
    assert 0 <= assessment.risk_score <= 100
    assert assessment.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert assessment.model_name == "baseline_logistic_regression"

    # Verify persisted in repository
    fetched = risk_repo.get_latest_for_incident("inc-r1")
    assert fetched is not None
    assert fetched.assessment_id == assessment.assessment_id
    assert fetched.risk_score == assessment.risk_score


def test_risk_scoring_preserves_incident_severity(db_session) -> None:
    """CRITICAL TEST: ML Risk scoring must NOT modify or overwrite Incident severity."""
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)
    risk_repo = RiskAssessmentRepository(db_session)

    service = RiskScoringService(risk_repo, inc_repo, corr_repo, event_repo)

    original_severity = 9
    incident = make_test_incident_for_db("inc-preserve-sev", severity=original_severity)
    inc_repo.create_incident(incident)

    assessment = service.score_incident("inc-preserve-sev")
    assert assessment is not None

    # Verify original incident record in database still has its original severity
    db_incident = inc_repo.get_incident("inc-preserve-sev")
    assert db_incident is not None
    assert db_incident.severity == original_severity
    assert db_incident.severity != assessment.risk_score or original_severity == assessment.risk_score


def test_repeated_scoring_updates_existing_assessment(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)
    risk_repo = RiskAssessmentRepository(db_session)

    service = RiskScoringService(risk_repo, inc_repo, corr_repo, event_repo)

    incident = make_test_incident_for_db("inc-repeat")
    inc_repo.create_incident(incident)

    a1 = service.score_incident("inc-repeat")
    a2 = service.score_incident("inc-repeat")

    assert a1 is not None and a2 is not None
    assert a1.assessment_id == a2.assessment_id

    # Verify only one assessment exists in database for this ID
    all_for_inc = risk_repo.list_assessments(incident_id="inc-repeat")
    assert len(all_for_inc) == 1


def test_deterministic_assessment_id() -> None:
    id1 = RiskScoringService.generate_assessment_id("inc-xyz")
    id2 = RiskScoringService.generate_assessment_id("inc-xyz")
    id3 = RiskScoringService.generate_assessment_id("inc-abc")
    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("risk-")


def test_audit_event_logged_on_scoring(db_session) -> None:
    inc_repo = IncidentRepository(db_session)
    corr_repo = CorrelationRepository(db_session)
    event_repo = EventRepository(db_session)
    risk_repo = RiskAssessmentRepository(db_session)

    service = RiskScoringService(risk_repo, inc_repo, corr_repo, event_repo)

    incident = make_test_incident_for_db("inc-audit-1")
    inc_repo.create_incident(incident)

    assessment = service.score_incident("inc-audit-1")
    assert assessment is not None

    audits = event_repo.list_audit_events(assessment.assessment_id)
    assert len(audits) >= 1
    assert audits[0].action == "risk_assessment.created"
