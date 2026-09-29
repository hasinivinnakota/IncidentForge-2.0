"""Unit tests for ResponseActionRepository and SQLModel persistence."""

from datetime import datetime, timezone
import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.response import ResponseAction as DomainResponseAction, ResponseActionStatus
from backend.app.persistence.repositories import ResponseActionRepository


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_create_and_retrieve_response_action(session):
    repo = ResponseActionRepository(session)
    now = datetime.now(timezone.utc)

    action = DomainResponseAction(
        action_id="resp-test-001",
        incident_id="inc-test-100",
        action_type="isolate_endpoint",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
    )

    write_res = repo.create_response_action(action)
    assert write_res.created is True
    assert write_res.response_action.action_id == "resp-test-001"
    assert write_res.response_action.status == "proposed"

    # Duplicate create returns existing (idempotent)
    dup_res = repo.create_response_action(action)
    assert dup_res.created is False
    assert dup_res.response_action.action_id == "resp-test-001"

    # Retrieve by ID
    record = repo.get_response_action("resp-test-001")
    assert record is not None
    assert record.action_id == "resp-test-001"
    assert record.action_type == "isolate_endpoint"


def test_update_response_action(session):
    repo = ResponseActionRepository(session)
    now = datetime.now(timezone.utc)

    action = DomainResponseAction(
        action_id="resp-test-002",
        incident_id="inc-test-100",
        action_type="quarantine_file",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
    )
    repo.create_response_action(action)

    # Approve
    action.status = ResponseActionStatus.APPROVED
    action.approved_by = "senior_analyst"

    updated = repo.update_response_action(action)
    assert updated is not None
    assert updated.status == "approved"
    assert updated.approved_by == "senior_analyst"

    # Non-existent update returns None
    missing_action = DomainResponseAction(
        action_id="resp-missing",
        incident_id="inc-100",
        action_type="revoke_credentials",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
    )
    assert repo.update_response_action(missing_action) is None


def test_list_response_actions(session):
    repo = ResponseActionRepository(session)
    now = datetime.now(timezone.utc)

    a1 = DomainResponseAction(
        action_id="resp-list-1",
        incident_id="inc-A",
        action_type="isolate_endpoint",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
    )
    a2 = DomainResponseAction(
        action_id="resp-list-2",
        incident_id="inc-A",
        action_type="revoke_credentials",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
    )
    a3 = DomainResponseAction(
        action_id="resp-list-3",
        incident_id="inc-B",
        action_type="quarantine_file",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
    )

    repo.create_response_action(a1)
    repo.create_response_action(a2)
    repo.create_response_action(a3)

    all_actions = repo.list_response_actions()
    assert len(all_actions) == 3

    inc_a_actions = repo.list_response_actions(incident_id="inc-A")
    assert len(inc_a_actions) == 2
    assert {a.action_id for a in inc_a_actions} == {"resp-list-1", "resp-list-2"}

    inc_b_actions = repo.list_response_actions(incident_id="inc-B")
    assert len(inc_b_actions) == 1
    assert inc_b_actions[0].action_id == "resp-list-3"
