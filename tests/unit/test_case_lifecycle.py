"""Unit tests for Case lifecycle state machine transitions."""

import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.cases import CasePriority, CaseStatus
from backend.app.persistence.repositories import (
    CaseRepository,
    EventRepository,
)
from backend.app.services.cases import CaseService


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def case_service(session):
    case_repo = CaseRepository(session)
    event_repo = EventRepository(session)
    return CaseService(case_repository=case_repo, event_repository=event_repo)


def test_valid_lifecycle_transitions(case_service):
    # 1. Create case -> OPEN
    case = case_service.create_case(
        title="Phishing investigation",
        description="User reported suspicious link",
        severity=6,
        priority=CasePriority.HIGH,
    )
    assert case.status == CaseStatus.OPEN

    # 2. OPEN -> IN_PROGRESS
    case = case_service.transition_status(case.case_id, CaseStatus.IN_PROGRESS)
    assert case.status == CaseStatus.IN_PROGRESS

    # 3. IN_PROGRESS -> PENDING
    case = case_service.transition_status(case.case_id, CaseStatus.PENDING, reason="Waiting for user interview")
    assert case.status == CaseStatus.PENDING

    # 4. PENDING -> IN_PROGRESS
    case = case_service.transition_status(case.case_id, CaseStatus.IN_PROGRESS, reason="Interview completed")
    assert case.status == CaseStatus.IN_PROGRESS

    # 5. IN_PROGRESS -> RESOLVED (via resolve_case)
    case = case_service.resolve_case(
        case.case_id,
        summary="User clicked link but 2FA prevented credential reuse; password reset performed.",
        root_cause="Credential harvesting landing page",
        action_taken="Blocked sender domain and reset password",
        resolver="soc_lead",
    )
    assert case.status == CaseStatus.RESOLVED
    assert case.resolution is not None

    # 6. RESOLVED -> CLOSED
    case = case_service.transition_status(case.case_id, CaseStatus.CLOSED)
    assert case.status == CaseStatus.CLOSED

    # 7. Reopening CLOSED -> IN_PROGRESS
    case = case_service.transition_status(case.case_id, CaseStatus.IN_PROGRESS, reason="Follow-up telemetry found")
    assert case.status == CaseStatus.IN_PROGRESS


def test_invalid_transitions_rejected(case_service):
    case = case_service.create_case(
        title="Unauthorized SSH Access",
        description="SSH login from external IP",
        severity=8,
    )
    assert case.status == CaseStatus.OPEN

    # OPEN cannot jump directly to PENDING
    with pytest.raises(ValueError, match="Invalid status transition"):
        case_service.transition_status(case.case_id, CaseStatus.PENDING)

    # OPEN cannot jump directly to RESOLVED without IN_PROGRESS
    with pytest.raises(ValueError, match="Invalid status transition"):
        case_service.transition_status(case.case_id, CaseStatus.RESOLVED)

    # OPEN cannot jump directly to CLOSED
    with pytest.raises(ValueError, match="Invalid status transition"):
        case_service.transition_status(case.case_id, CaseStatus.CLOSED)


def test_close_without_prior_resolution_rejected(case_service):
    case = case_service.create_case(
        title="Test Close Validation",
        description="Desc",
        severity=5,
    )
    case = case_service.transition_status(case.case_id, CaseStatus.IN_PROGRESS)

    # Cannot close from IN_PROGRESS directly
    with pytest.raises(ValueError, match="Invalid status transition"):
        case_service.transition_status(case.case_id, CaseStatus.CLOSED)


def test_resolve_requires_summary(case_service):
    case = case_service.create_case(
        title="Test Summary Requirement",
        description="Desc",
        severity=5,
    )
    case = case_service.transition_status(case.case_id, CaseStatus.IN_PROGRESS)

    with pytest.raises(ValueError, match="Resolution summary is required"):
        case_service.resolve_case(case.case_id, summary="")
