"""Unit tests for CaseService layer."""

from datetime import datetime, timezone
import json
import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.cases import CasePriority, CaseStatus, EvidenceType
from backend.app.models.incidents import Incident, IncidentStatus
from backend.app.persistence.repositories import (
    CaseRepository,
    EventRepository,
    IncidentRepository,
    InvestigationRepository,
)
from backend.app.services.cases import CaseService


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def repos(session):
    return {
        "case": CaseRepository(session),
        "event": EventRepository(session),
        "incident": IncidentRepository(session),
        "investigation": InvestigationRepository(session),
    }


def test_incident_seeded_case_deterministic_id(repos):
    service = CaseService(
        case_repository=repos["case"],
        event_repository=repos["event"],
        incident_repository=repos["incident"],
    )

    now = datetime.now(timezone.utc)
    inc = Incident(
        incident_id="inc-test-seeded-100",
        title="DDoS Attack on Ingress Gateway",
        description="High volume SYN flood detected",
        severity=10,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
        tags=["ddos", "network"],
    )
    repos["incident"].create_incident(inc)

    # 1. Create seeded case
    case1 = service.create_case(
        title="Investigate Ingress DDoS",
        description="Customer facing services impacted",
        severity=10,
        incident_id="inc-test-seeded-100",
    )

    expected_id = service.generate_incident_seeded_case_id("inc-test-seeded-100")
    assert case1.case_id == expected_id
    assert "inc-test-seeded-100" in case1.incident_ids
    assert "ddos" in case1.tags

    # Check evidence reference was automatically created
    evidence_refs = repos["case"].list_evidence_by_case(case1.case_id)
    assert any(e.reference_key == "inc-test-seeded-100" for e in evidence_refs)

    # 2. Duplicate create returns existing (idempotent)
    case2 = service.create_case(
        title="Duplicate call",
        description="Desc",
        severity=10,
        incident_id="inc-test-seeded-100",
    )
    assert case2.case_id == case1.case_id

    # 3. Incident severity is NOT modified
    inc_record = repos["incident"].get_incident("inc-test-seeded-100")
    assert inc_record.severity == 10


def test_standalone_case_collision_safe_id(repos):
    service = CaseService(
        case_repository=repos["case"],
        event_repository=repos["event"],
    )
    c1 = service.create_case(title="Proactive Threat Hunt", description="Hunt for T1059", severity=4)
    c2 = service.create_case(title="Proactive Threat Hunt", description="Hunt for T1059", severity=4)

    assert c1.case_id != c2.case_id
    assert c1.case_id.startswith("case-")
    assert c2.case_id.startswith("case-")


def test_secret_redaction_in_notes_and_titles(repos):
    service = CaseService(
        case_repository=repos["case"],
        event_repository=repos["event"],
    )
    case = service.create_case(
        title="Leaked password on internal git",
        description="User stored secret token in repo",
        severity=8,
    )
    assert "password" not in case.title.lower()
    assert "[REDACTED]" in case.title

    note = service.add_note(
        case_id=case.case_id,
        content="Found api_key: 12345 and authorization bearer token",
        author="alice",
    )
    assert "api_key" not in note.content.lower()
    assert "bearer" not in note.content.lower()
    assert "[REDACTED]" in note.content


def test_evidence_linking_and_deduplication(repos):
    service = CaseService(
        case_repository=repos["case"],
        event_repository=repos["event"],
    )
    case = service.create_case(title="Case with Evidence", description="desc", severity=5)

    ref1 = service.link_evidence(
        case_id=case.case_id,
        evidence_type=EvidenceType.ALERT,
        reference_key="alt-101",
        description="First alert",
        added_by="analyst",
    )
    assert ref1.reference_key == "alt-101"

    # Linking the same evidence again is idempotent and returns existing
    ref2 = service.link_evidence(
        case_id=case.case_id,
        evidence_type=EvidenceType.ALERT,
        reference_key="alt-101",
        description="Duplicate link attempt",
        added_by="analyst",
    )
    assert ref2.evidence_id == ref1.evidence_id

    # Check case evidence list
    c = service.get_case(case.case_id)
    assert len(c.evidence_references) == 1


def test_timeline_reconstruction_from_audit(repos):
    service = CaseService(
        case_repository=repos["case"],
        event_repository=repos["event"],
    )
    case = service.create_case(title="Timeline Test", description="desc", severity=5)
    service.assign_case(case.case_id, assignee="alice")
    service.transition_status(case.case_id, CaseStatus.IN_PROGRESS)
    service.add_note(case.case_id, content="First note", author="alice")
    service.resolve_case(
        case.case_id,
        summary="Threat eradicated",
        root_cause="Phish",
        action_taken="Blocked",
        resolver="alice",
    )

    timeline = service.get_timeline(case.case_id)
    assert len(timeline) >= 4

    actions = [t.action for t in timeline]
    assert "case.created" in actions
    assert "case.assigned" in actions
    assert "case.status_changed" in actions
    assert "case.note_added" in actions
    assert "case.resolved" in actions
