"""Unit tests for ResponseService: state machine, approval, simulation, audit, and security."""

from datetime import datetime, timezone
import json
import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.app.models.incidents import Incident as DomainIncident, IncidentStatus
from backend.app.models.response import (
    ALLOWED_ACTION_TYPES,
    ResponseActionStatus,
    ResponseActionType,
)
from backend.app.persistence.repositories import (
    EventRepository,
    IncidentRepository,
    ResponseActionRepository,
)
from backend.app.services.response import (
    ResponseNotFoundError,
    ResponseService,
    ResponseTransitionError,
    ResponseValidationError,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def incident_id(session):
    repo = IncidentRepository(session)
    now = datetime.now(timezone.utc)
    inc = DomainIncident(
        incident_id="inc-sec-001",
        title="Suspicious Remote Code Execution",
        description="Cobalt Strike beaconing detected",
        severity=12,
        status=IncidentStatus.OPEN,
        created_at=now,
        updated_at=now,
    )
    repo.create_incident(inc)
    return inc.incident_id


@pytest.fixture
def service(session):
    return ResponseService(
        event_repository=EventRepository(session),
        incident_repository=IncidentRepository(session),
        response_repository=ResponseActionRepository(session),
    )


# ---------------------------------------------------------------------------
# Creation & Idempotency
# ---------------------------------------------------------------------------

def test_create_action_success(service, incident_id, session):
    action = service.create_action(
        incident_id=incident_id,
        action_type="isolate_endpoint",
        actor="analyst_alice",
    )
    assert action.action_id.startswith("resp-")
    assert action.incident_id == incident_id
    assert action.action_type == "isolate_endpoint"
    assert action.status == ResponseActionStatus.PROPOSED
    assert action.approved_by is None
    assert action.executed_at is None
    assert action.result is None

    # Verify audit trail
    event_repo = EventRepository(session)
    audits = event_repo.list_audit_events(target=action.action_id)
    assert len(audits) == 1
    assert audits[0].action == "response_action.proposed"
    assert audits[0].actor == "analyst_alice"
    assert audits[0].result == "proposed"


def test_create_action_deterministic_id_and_idempotent(service, incident_id):
    action1 = service.create_action(
        incident_id=incident_id,
        action_type="isolate_endpoint",
        actor="analyst1",
    )
    action2 = service.create_action(
        incident_id=incident_id,
        action_type="isolate_endpoint",
        actor="analyst2",
    )
    assert action1.action_id == action2.action_id
    assert action1.requested_at == action2.requested_at


def test_create_action_missing_incident_rejected(service):
    with pytest.raises(ResponseValidationError) as exc:
        service.create_action(
            incident_id="inc-nonexistent",
            action_type="isolate_endpoint",
        )
    assert "was not found" in str(exc.value)


def test_create_action_invalid_action_type_rejected(service, incident_id):
    with pytest.raises(ResponseValidationError) as exc:
        service.create_action(
            incident_id=incident_id,
            action_type="arbitrary_exploit",
        )
    assert "Unsupported response action type" in str(exc.value)


# ---------------------------------------------------------------------------
# Approval Flow
# ---------------------------------------------------------------------------

def test_approve_action(service, incident_id, session):
    action = service.create_action(
        incident_id=incident_id,
        action_type="isolate_endpoint",
        actor="analyst_alice",
    )

    approved = service.approve(action.action_id, actor="lead_analyst_bob")
    assert approved.status == ResponseActionStatus.APPROVED
    assert approved.approved_by == "lead_analyst_bob"

    # Verify audit
    event_repo = EventRepository(session)
    audits = event_repo.list_audit_events(target=action.action_id)
    assert len(audits) == 2
    actions = [a.action for a in audits]
    assert "response_action.proposed" in actions
    assert "response_action.approved" in actions


# ---------------------------------------------------------------------------
# Rejection Flow
# ---------------------------------------------------------------------------

def test_reject_action(service, incident_id, session):
    action = service.create_action(
        incident_id=incident_id,
        action_type="quarantine_file",
        actor="analyst_alice",
    )

    rejected = service.reject(
        action.action_id,
        actor="lead_analyst_bob",
        reason="Host is a mission-critical DC; offline triage requested instead.",
    )
    assert rejected.status == ResponseActionStatus.REJECTED
    assert "mission-critical DC" in rejected.result

    # Verify audit
    event_repo = EventRepository(session)
    audits = event_repo.list_audit_events(target=action.action_id)
    assert len(audits) == 2
    actions = [a.action for a in audits]
    assert "response_action.rejected" in actions


# ---------------------------------------------------------------------------
# Simulation Execution Flow
# ---------------------------------------------------------------------------

def test_execute_simulation_requires_approval(service, incident_id):
    action = service.create_action(
        incident_id=incident_id,
        action_type="revoke_credentials",
        actor="analyst_alice",
    )
    # Direct execution of PROPOSED must fail
    with pytest.raises(ResponseTransitionError) as exc:
        service.execute(action.action_id, actor="analyst_alice")
    assert "Invalid response transition: proposed -> executed" in str(exc.value)


def test_execute_simulation_all_three_types(service, incident_id, session):
    for atype in (
        ResponseActionType.ISOLATE_ENDPOINT.value,
        ResponseActionType.QUARANTINE_FILE.value,
        ResponseActionType.REVOKE_CREDENTIALS.value,
    ):
        act = service.create_action(incident_id=incident_id, action_type=atype)
        service.approve(act.action_id, actor="approver")
        executed = service.execute(act.action_id, actor="executor")

        assert executed.status == ResponseActionStatus.EXECUTED
        assert executed.executed_at is not None
        assert executed.result.startswith("SIMULATION ONLY:")

        # Verify simulation_only flag in audit metadata
        event_repo = EventRepository(session)
        audits = event_repo.list_audit_events(target=act.action_id)
        exec_audit = [a for a in audits if a.action == "response_action.executed"][0]
        meta = json.loads(exec_audit.metadata_json)
        assert meta.get("simulation_only") is True


# ---------------------------------------------------------------------------
# State Machine Transitions
# ---------------------------------------------------------------------------

def test_state_machine_terminal_states(service, incident_id):
    # 1. Terminal EXECUTED
    act1 = service.create_action(incident_id=incident_id, action_type="isolate_endpoint")
    service.approve(act1.action_id, actor="approver")
    service.execute(act1.action_id, actor="executor")

    # Cannot approve, reject, or execute already executed action
    with pytest.raises(ResponseTransitionError):
        service.approve(act1.action_id, actor="someone")
    with pytest.raises(ResponseTransitionError):
        service.reject(act1.action_id, actor="someone")
    with pytest.raises(ResponseTransitionError):
        service.execute(act1.action_id, actor="someone")

    # 2. Terminal REJECTED
    act2 = service.create_action(incident_id=incident_id, action_type="quarantine_file")
    service.reject(act2.action_id, actor="rejector")

    # Cannot approve or execute rejected action
    with pytest.raises(ResponseTransitionError):
        service.approve(act2.action_id, actor="someone")
    with pytest.raises(ResponseTransitionError):
        service.execute(act2.action_id, actor="someone")


# ---------------------------------------------------------------------------
# Security & Credential Redaction
# ---------------------------------------------------------------------------

def test_sensitive_data_redaction(service, incident_id):
    # Passwords or tokens in rejection reason
    act = service.create_action(incident_id=incident_id, action_type="revoke_credentials")
    leaked_reason = (
        "Rejection note with password=SuperSecretPassword123! "
        "and authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test and api_key=ak_live_12345"
    )
    rejected = service.reject(act.action_id, actor="admin", reason=leaked_reason)
    assert "SuperSecretPassword123!" not in rejected.result
    assert "Bearer eyJhbGci" not in rejected.result
    assert "ak_live_12345" not in rejected.result
    assert "[REDACTED]" in rejected.result


def test_actor_redaction_and_validation(service, incident_id):
    with pytest.raises(ResponseValidationError):
        service.create_action(incident_id=incident_id, action_type="isolate_endpoint", actor="")

    with pytest.raises(ResponseValidationError):
        service.create_action(
            incident_id=incident_id,
            action_type="isolate_endpoint",
            actor="a" * 257,
        )

    # Actor containing a password pattern is redacted
    act = service.create_action(
        incident_id=incident_id,
        action_type="quarantine_file",
        actor="analyst token:secret_token_123",
    )
    approved = service.approve(act.action_id, actor="approver password:mysecretpassword")
    assert "mysecretpassword" not in approved.approved_by
    assert "[REDACTED]" in approved.approved_by
