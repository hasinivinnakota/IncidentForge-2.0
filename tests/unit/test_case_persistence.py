"""Unit tests for CaseRepository and SQLModel persistence."""

from datetime import datetime, timezone
import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.cases import (
    Case as DomainCase,
    CaseNote as DomainCaseNote,
    CasePriority,
    CaseStatus,
    EvidenceReference as DomainEvidenceReference,
    EvidenceType,
)
from backend.app.persistence.repositories import CaseRepository


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_create_and_retrieve_case(session):
    repo = CaseRepository(session)
    now = datetime.now(timezone.utc)

    domain_case = DomainCase(
        case_id="case-pers-1",
        title="Lateral Movement Detected",
        description="PsExec execution on finance workstation",
        severity=9,
        priority=CasePriority.HIGH,
        status=CaseStatus.OPEN,
        created_at=now,
        updated_at=now,
        incident_ids=["inc-101"],
        tags=["lateral_movement"],
    )

    write_res = repo.create_case(domain_case)
    assert write_res.created is True
    assert write_res.case.case_id == "case-pers-1"

    # Duplicate create returns existing
    dup_res = repo.create_case(domain_case)
    assert dup_res.created is False

    # Get by ID
    record = repo.get_case("case-pers-1")
    assert record is not None
    assert record.title == "Lateral Movement Detected"
    assert record.priority == "high"


def test_update_case(session):
    repo = CaseRepository(session)
    now = datetime.now(timezone.utc)

    domain_case = DomainCase(
        case_id="case-pers-2",
        title="Initial Title",
        description="Initial Desc",
        severity=5,
        priority=CasePriority.MEDIUM,
        status=CaseStatus.OPEN,
        created_at=now,
        updated_at=now,
    )
    repo.create_case(domain_case)

    # Update
    domain_case.title = "Updated Title"
    domain_case.priority = CasePriority.CRITICAL
    domain_case.status = CaseStatus.IN_PROGRESS

    updated = repo.update_case(domain_case)
    assert updated is not None
    assert updated.title == "Updated Title"
    assert updated.priority == "critical"
    assert updated.status == "in_progress"


def test_list_cases_filtering(session):
    repo = CaseRepository(session)
    now = datetime.now(timezone.utc)

    c1 = DomainCase(
        case_id="case-list-1",
        title="Case 1",
        description="Desc",
        severity=4,
        priority=CasePriority.LOW,
        status=CaseStatus.OPEN,
        assignee="analyst1",
        created_at=now,
        updated_at=now,
    )
    c2 = DomainCase(
        case_id="case-list-2",
        title="Case 2",
        description="Desc",
        severity=10,
        priority=CasePriority.CRITICAL,
        status=CaseStatus.IN_PROGRESS,
        assignee="analyst2",
        created_at=now,
        updated_at=now,
    )
    repo.create_case(c1)
    repo.create_case(c2)

    all_cases = repo.list_cases()
    assert len(all_cases) == 2

    filtered_status = repo.list_cases(status="in_progress")
    assert len(filtered_status) == 1
    assert filtered_status[0].case_id == "case-list-2"

    filtered_assignee = repo.list_cases(assignee="analyst1")
    assert len(filtered_assignee) == 1
    assert filtered_assignee[0].case_id == "case-list-1"


def test_normalized_notes_and_evidence(session):
    repo = CaseRepository(session)
    now = datetime.now(timezone.utc)

    # Add notes
    n1 = DomainCaseNote(
        note_id="note-1",
        case_id="case-norm-1",
        author="alice",
        content="Note 1",
        created_at=now,
        updated_at=now,
    )
    repo.add_note(n1)

    notes = repo.list_notes_by_case("case-norm-1")
    assert len(notes) == 1
    assert notes[0].content == "Note 1"

    # Add evidence reference
    e1 = DomainEvidenceReference(
        evidence_id="evref-1",
        case_id="case-norm-1",
        evidence_type=EvidenceType.ALERT,
        reference_key="alt-999",
        description="First alert",
        added_by="bob",
        added_at=now,
    )
    repo.add_evidence_reference(e1)

    # Duplicate evidence reference linking is idempotent
    repo.add_evidence_reference(e1)

    evidence_list = repo.list_evidence_by_case("case-norm-1")
    assert len(evidence_list) == 1
    assert evidence_list[0].reference_key == "alt-999"
