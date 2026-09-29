"""Unit tests for Case domain models, validations, and bounds."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from backend.app.models.cases import (
    Case,
    CaseNote,
    CasePriority,
    CaseResolution,
    CaseStatus,
    CaseTimelineEntry,
    EvidenceReference,
    EvidenceType,
)


def test_case_model_valid():
    now = datetime.now(timezone.utc)
    case = Case(
        case_id="case-001",
        title="Active Ransomware Outbreak on Fileserver",
        description="High volume encryption event detected",
        severity=12,
        priority=CasePriority.CRITICAL,
        status=CaseStatus.OPEN,
        assignee="analyst1",
        created_at=now,
        updated_at=now,
        incident_ids=["inc-100", "inc-101"],
        investigation_ids=["inv-500"],
        tags=["ransomware", "critical"],
    )
    assert case.case_id == "case-001"
    assert case.severity == 12
    assert case.priority == CasePriority.CRITICAL
    assert case.status == CaseStatus.OPEN
    assert len(case.incident_ids) == 2


def test_case_severity_bounds():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        Case(
            case_id="case-bad-sev",
            title="Invalid severity",
            description="desc",
            severity=16,  # max is 15
            created_at=now,
            updated_at=now,
        )

    with pytest.raises(ValidationError):
        Case(
            case_id="case-bad-sev-neg",
            title="Invalid negative severity",
            description="desc",
            severity=-1,  # min is 0
            created_at=now,
            updated_at=now,
        )


def test_case_extra_fields_forbidden():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        Case(
            case_id="case-extra",
            title="Title",
            description="Desc",
            severity=5,
            created_at=now,
            updated_at=now,
            extra_field="not_allowed",  # extra="forbid"
        )


def test_case_note_model():
    now = datetime.now(timezone.utc)
    note = CaseNote(
        note_id="note-001",
        case_id="case-001",
        author="alice",
        content="Analyzed endpoint memory dump; identified malicious injected DLL.",
        created_at=now,
        updated_at=now,
    )
    assert note.note_id == "note-001"
    assert note.author == "alice"


def test_evidence_reference_model():
    now = datetime.now(timezone.utc)
    ref = EvidenceReference(
        evidence_id="evref-001",
        case_id="case-001",
        evidence_type=EvidenceType.ALERT,
        reference_key="alt-12345",
        description="Initial brute force alert",
        added_by="bob",
        added_at=now,
    )
    assert ref.evidence_type == EvidenceType.ALERT
    assert ref.reference_key == "alt-12345"


def test_case_resolution_model():
    now = datetime.now(timezone.utc)
    res = CaseResolution(
        summary="Attacker contained; credentials rotated.",
        root_cause="Compromised service account password",
        action_taken="Revoked session tokens and rebuilt host from golden image",
        resolved_by="charlie",
        resolved_at=now,
    )
    assert res.summary.startswith("Attacker contained")
    assert res.resolved_by == "charlie"
