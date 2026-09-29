"""Unit tests for AIInvestigatorService."""

from datetime import datetime, timezone
import json
import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.alerts import Alert, AlertStatus
from backend.app.models.events import NormalizedEvent
from backend.app.models.incidents import Incident, IncidentStatus
from backend.app.models.investigation import FindingType, InvestigationResult
from backend.app.models.risk import RiskAssessment, RiskLevel
from backend.app.persistence.models import Incident as PersistenceIncident
from backend.app.persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    InvestigationRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from backend.app.services.ai_investigator import AIInvestigatorService
from backend.app.services.llm_provider import LocalDevLLMProvider


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def repos(session):
    return {
        "investigation": InvestigationRepository(session),
        "incident": IncidentRepository(session),
        "event": EventRepository(session),
        "alert": AlertRepository(session),
        "correlation": CorrelationRepository(session),
        "risk": RiskAssessmentRepository(session),
        "threat_intel": ThreatIntelRepository(session),
    }


def test_investigate_non_existent_incident(repos):
    service = AIInvestigatorService(
        investigation_repository=repos["investigation"],
        incident_repository=repos["incident"],
        event_repository=repos["event"],
    )
    result = service.investigate_incident("inc-non-existent")
    assert result is None


def test_investigate_incident_creates_and_audits(repos):
    now = datetime.now(timezone.utc)
    # Create incident in repo
    incident = Incident(
        incident_id="inc-svc-001",
        title="High Volume Brute Force against DC01",
        description="Correlation rule triggered multiple failed logons",
        severity=4,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
        correlation_ids=["corr-001"],
        alert_ids=["alt-001"],
        event_ids=["evt-001"],
        mitre_techniques=["T1110"],
        evidence={"entity_key": "DC01"},
    )
    repos["incident"].create_incident(incident)

    service = AIInvestigatorService(
        investigation_repository=repos["investigation"],
        incident_repository=repos["incident"],
        event_repository=repos["event"],
        alert_repository=repos["alert"],
        correlation_repository=repos["correlation"],
        risk_repository=repos["risk"],
        threat_intel_repository=repos["threat_intel"],
    )

    result = service.investigate_incident("inc-svc-001")
    assert isinstance(result, InvestigationResult)
    assert result.investigation_id == service.generate_investigation_id("inc-svc-001")
    assert result.incident_id == "inc-svc-001"
    assert "DC01" in result.summary or any("DC01" in f.description for f in result.findings)

    # Check audit events recorded
    audit_events = repos["event"].list_audit_events(target=result.investigation_id)
    actions = [a.action for a in audit_events]
    assert "investigation.requested" in actions
    assert "investigation.completed" in actions


def test_investigation_idempotency_and_force(repos):
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-svc-002",
        title="Command Injection Attempt",
        description="Web attack detected",
        severity=3,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
        evidence={"entity_key": "WEB-SRV"},
    )
    repos["incident"].create_incident(incident)

    service = AIInvestigatorService(
        investigation_repository=repos["investigation"],
        incident_repository=repos["incident"],
        event_repository=repos["event"],
    )

    # First run
    res1 = service.investigate_incident("inc-svc-002", force=False)
    assert res1 is not None

    # Second run without force should return existing
    res2 = service.investigate_incident("inc-svc-002", force=False)
    assert res2.investigation_id == res1.investigation_id
    assert res2.generated_at == res1.generated_at

    # Audit events should only have one requested/completed pair
    audits = repos["event"].list_audit_events(target=res1.investigation_id)
    completed_audits = [a for a in audits if a.action == "investigation.completed"]
    assert len(completed_audits) == 1

    # Third run WITH force=True should re-run
    res3 = service.investigate_incident("inc-svc-002", force=True)
    assert res3.investigation_id == res1.investigation_id

    audits_after_force = repos["event"].list_audit_events(target=res1.investigation_id)
    completed_audits_force = [a for a in audits_after_force if a.action == "investigation.completed"]
    assert len(completed_audits_force) == 2


def test_investigation_never_modifies_incident_severity(repos):
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-svc-003",
        title="Test Severity Preserved",
        description="Description",
        severity=2,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
    )
    repos["incident"].create_incident(incident)

    service = AIInvestigatorService(
        investigation_repository=repos["investigation"],
        incident_repository=repos["incident"],
        event_repository=repos["event"],
    )

    service.investigate_incident("inc-svc-003")

    # Confirm incident severity is still 2
    inc_record = repos["incident"].get_incident("inc-svc-003")
    assert inc_record.severity == 2


def test_sensitive_telemetry_redacted(repos):
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-svc-004",
        title="Admin password leaked in command line",
        description="User ran login with token secret",
        severity=4,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
        evidence={"entity_key": "DC-PASSWD"},
    )
    repos["incident"].create_incident(incident)

    service = AIInvestigatorService(
        investigation_repository=repos["investigation"],
        incident_repository=repos["incident"],
        event_repository=repos["event"],
    )

    ctx = service._build_context(repos["incident"].get_incident("inc-svc-004"))
    assert "password" not in ctx.incident_title.lower()
    assert "[REDACTED]" in ctx.incident_title
