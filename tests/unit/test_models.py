from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.app.models import (
    Alert,
    AuditEvent,
    Incident,
    InvestigationResult,
    NormalizedEvent,
    ResponseAction,
)


def test_normalized_event_requires_core_fields() -> None:
    event = NormalizedEvent(
        event_id="evt-1",
        timestamp="2026-01-01T00:00:00Z",
        source="fixture",
        event_type="login",
        severity=4,
        message="login observed",
    )
    assert event.timestamp.tzinfo is not None


def test_alert_rejects_out_of_range_severity() -> None:
    with pytest.raises(ValidationError):
        Alert(alert_id="a", event_id="e", timestamp=datetime.now(timezone.utc), rule_id="r", rule_name="rule", severity=16, description="x", source="test")


def test_incident_defaults_to_open() -> None:
    incident = Incident(incident_id="i", title="Title", description="Description", severity=5, created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
    assert incident.status == "open"


def test_investigation_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        InvestigationResult(investigation_id="x", incident_id="i", summary="s", confidence=1.1, generated_at=datetime.now(timezone.utc))


def test_response_action_is_data_only() -> None:
    action = ResponseAction(action_id="a", incident_id="i", action_type="isolate_host", requested_at=datetime.now(timezone.utc))
    assert action.status == "proposed"


def test_audit_event_accepts_metadata() -> None:
    audit = AuditEvent(audit_id="a", timestamp=datetime.now(timezone.utc), actor="system", action="accept", target="event", result="ok", metadata={"source": "fixture"})
    assert audit.metadata["source"] == "fixture"