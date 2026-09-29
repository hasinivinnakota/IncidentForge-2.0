"""Unit tests for Investigation persistence and repository operations."""

from datetime import datetime, timezone
import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.investigation import (
    FindingItem,
    FindingType,
    InvestigationResult,
    RecommendedAction,
    TimelineItem,
)
from backend.app.persistence.repositories import InvestigationRepository


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def sample_investigation():
    return InvestigationResult(
        investigation_id="inv-pers-01",
        incident_id="inc-pers-01",
        summary="Test investigation summary",
        confidence=0.85,
        findings=[
            FindingItem(
                finding_type=FindingType.OBSERVED,
                description="Observed alert activity",
                evidence=["alert_id=alt-1"],
            ),
            FindingItem(
                finding_type=FindingType.INFERRED,
                description="Inferred lateral movement attempt",
                evidence=["T1021"],
            ),
        ],
        timeline=[
            TimelineItem(
                timestamp=datetime.now(timezone.utc),
                event_type="test_event",
                description="Test event occurred",
                source_entity="HOST-01",
            )
        ],
        mitre_techniques=["T1059", "T1021"],
        threat_intel_summary={"total_indicators": 1, "malicious_count": 1},
        investigation_gaps=["Missing memory dump"],
        recommended_next_steps=["Inspect host"],
        possible_response_actions=[
            RecommendedAction(
                action_type="isolate_endpoint",
                description="Isolate endpoint",
                target_entity="HOST-01",
                analyst_approval_required=True,
                inert_proposed_only=True,
            )
        ],
        provider="local_dev",
        model_name="heuristic_deterministic_v1",
        generated_at=datetime.now(timezone.utc),
    )


def test_save_and_retrieve_investigation(session, sample_investigation):
    repo = InvestigationRepository(session)

    # Save new
    write_res = repo.save_investigation(sample_investigation)
    assert write_res.created is True
    assert write_res.investigation.investigation_id == "inv-pers-01"

    # Retrieve by ID
    record = repo.get_investigation("inv-pers-01")
    assert record is not None
    assert record.incident_id == "inc-pers-01"
    assert record.confidence == 0.85
    assert record.provider == "local_dev"


def test_update_existing_investigation(session, sample_investigation):
    repo = InvestigationRepository(session)
    repo.save_investigation(sample_investigation)

    # Modify and update
    updated_inv = sample_investigation.model_copy(update={"confidence": 0.95, "summary": "Updated summary"})
    write_res = repo.save_investigation(updated_inv)
    assert write_res.created is False

    record = repo.get_investigation("inv-pers-01")
    assert record is not None
    assert record.confidence == 0.95
    assert record.summary == "Updated summary"


def test_get_latest_for_incident(session, sample_investigation):
    repo = InvestigationRepository(session)
    repo.save_investigation(sample_investigation)

    latest = repo.get_latest_for_incident("inc-pers-01")
    assert latest is not None
    assert latest.investigation_id == "inv-pers-01"

    assert repo.get_latest_for_incident("non-existent-inc") is None


def test_list_by_incident(session, sample_investigation):
    repo = InvestigationRepository(session)
    repo.save_investigation(sample_investigation)

    items = repo.list_by_incident("inc-pers-01")
    assert len(items) == 1
    assert items[0].investigation_id == "inv-pers-01"
