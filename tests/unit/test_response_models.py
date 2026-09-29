"""Unit tests for ResponseAction domain models, validations, and bounds."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from backend.app.models.response import (
    ALLOWED_ACTION_TYPES,
    ResponseAction,
    ResponseActionStatus,
    ResponseActionType,
)


def test_response_action_valid():
    now = datetime.now(timezone.utc)
    action = ResponseAction(
        action_id="resp-001",
        incident_id="inc-100",
        action_type="isolate_endpoint",
        status=ResponseActionStatus.PROPOSED,
        requested_at=now,
        approved_by=None,
        executed_at=None,
        result=None,
    )
    assert action.action_id == "resp-001"
    assert action.incident_id == "inc-100"
    assert action.action_type == "isolate_endpoint"
    assert action.status == ResponseActionStatus.PROPOSED
    assert action.requested_at == now
    assert action.approved_by is None
    assert action.executed_at is None
    assert action.result is None


def test_all_allowlisted_action_types():
    now = datetime.now(timezone.utc)
    for atype in (
        ResponseActionType.ISOLATE_ENDPOINT,
        ResponseActionType.QUARANTINE_FILE,
        ResponseActionType.REVOKE_CREDENTIALS,
    ):
        action = ResponseAction(
            action_id=f"resp-{atype.value}",
            incident_id="inc-100",
            action_type=atype.value,
            status=ResponseActionStatus.PROPOSED,
            requested_at=now,
        )
        assert action.action_type == atype.value


def test_allowlisted_action_types_membership():
    assert "isolate_endpoint" in ALLOWED_ACTION_TYPES
    assert "quarantine_file" in ALLOWED_ACTION_TYPES
    assert "revoke_credentials" in ALLOWED_ACTION_TYPES
    assert "delete_root_directory" not in ALLOWED_ACTION_TYPES
    assert "isolate_host" not in ALLOWED_ACTION_TYPES


def test_response_action_extra_fields_forbidden():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        ResponseAction(
            action_id="resp-extra",
            incident_id="inc-100",
            action_type="isolate_endpoint",
            status=ResponseActionStatus.PROPOSED,
            requested_at=now,
            unauthorized_field="malicious_payload",  # extra="forbid"
        )


def test_response_action_oversized_values_rejected():
    now = datetime.now(timezone.utc)
    # action_id max_length is 256
    with pytest.raises(ValidationError):
        ResponseAction(
            action_id="r" * 257,
            incident_id="inc-100",
            action_type="isolate_endpoint",
            requested_at=now,
        )

    # incident_id max_length is 256
    with pytest.raises(ValidationError):
        ResponseAction(
            action_id="resp-valid",
            incident_id="i" * 257,
            action_type="isolate_endpoint",
            requested_at=now,
        )

    # result max_length is 10000
    with pytest.raises(ValidationError):
        ResponseAction(
            action_id="resp-valid",
            incident_id="inc-100",
            action_type="isolate_endpoint",
            requested_at=now,
            result="x" * 10001,
        )
