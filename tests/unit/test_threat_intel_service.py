"""Tests for ThreatIntelligenceService."""

import json
from datetime import datetime, timezone

import pytest

from backend.app.models.incidents import Incident, IncidentStatus
from backend.app.models.threat_intel import IOCType
from backend.app.persistence.models import Incident as PersistenceIncident, Event as PersistenceEvent
from backend.app.persistence.repositories import (
    EventRepository,
    IncidentRepository,
    ThreatIntelRepository,
)
from backend.app.services.threat_intel import ThreatIntelligenceService


def test_enrich_incident_with_no_iocs(db_session):
    incident_repo = IncidentRepository(db_session)
    event_repo = EventRepository(db_session)
    ti_repo = ThreatIntelRepository(db_session)

    # Create an incident with no IOCs in evidence
    incident_repo.create_incident(
        Incident(
            incident_id="inc-no-iocs",
            title="Test",
            description="Test",
            severity=5,
            status=IncidentStatus.OPEN,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            event_ids=[],
            evidence={"some_key": "safe_value"},
        )
    )

    service = ThreatIntelligenceService(ti_repo, incident_repo, event_repo)
    result = service.enrich_incident("inc-no-iocs")

    assert result.iocs_extracted == 0
    assert len(result.enrichments_created) == 0
    assert len(result.enrichments_updated) == 0


def test_enrich_incident_with_iocs(db_session):
    incident_repo = IncidentRepository(db_session)
    event_repo = EventRepository(db_session)
    ti_repo = ThreatIntelRepository(db_session)

    now = datetime.now(timezone.utc)

    # Create an event with an IOC
    db_session.add(
        PersistenceEvent(
            event_id="evt-1",
            timestamp=now,
            source="test",
            event_type="test",
            severity=5,
            message="test",
            source_ip="203.0.113.50",  # Malicious synthetic IP
            metadata_json=json.dumps({"domain": "evil.synthetic.example"}),
        )
    )
    db_session.commit()

    # Create an incident pointing to the event
    incident_repo.create_incident(
        Incident(
            incident_id="inc-with-iocs",
            title="Test",
            description="Test",
            severity=5,
            status=IncidentStatus.OPEN,
            created_at=now,
            updated_at=now,
            event_ids=["evt-1"],
            evidence={},
        )
    )

    service = ThreatIntelligenceService(ti_repo, incident_repo, event_repo)
    result = service.enrich_incident("inc-with-iocs")

    # 1 IP, 1 domain
    assert result.iocs_extracted == 2
    assert len(result.enrichments_created) == 2

    # Verify persistence
    enrichments = ti_repo.list_by_incident("inc-with-iocs")
    assert len(enrichments) == 2

    # Check IP enrichment
    ip_enrichment = next(e for e in enrichments if e.ioc_type == IOCType.IPV4.value)
    assert ip_enrichment.classification == "malicious"

    # Check domain enrichment
    domain_enrichment = next(e for e in enrichments if e.ioc_type == IOCType.DOMAIN.value)
    assert domain_enrichment.classification == "malicious"


def test_enrich_incident_idempotency(db_session):
    incident_repo = IncidentRepository(db_session)
    event_repo = EventRepository(db_session)
    ti_repo = ThreatIntelRepository(db_session)

    now = datetime.now(timezone.utc)

    db_session.add(
        PersistenceEvent(
            event_id="evt-1",
            timestamp=now,
            source="test",
            event_type="test",
            severity=5,
            message="test",
            source_ip="203.0.113.50",
            metadata_json="{}",
        )
    )
    db_session.commit()

    incident_repo.create_incident(
        Incident(
            incident_id="inc-idempotent",
            title="Test",
            description="Test",
            severity=5,
            status=IncidentStatus.OPEN,
            created_at=now,
            updated_at=now,
            event_ids=["evt-1"],
        )
    )

    service = ThreatIntelligenceService(ti_repo, incident_repo, event_repo)

    # First run
    result1 = service.enrich_incident("inc-idempotent")
    assert len(result1.enrichments_created) == 1
    assert len(result1.enrichments_updated) == 0

    # Second run
    result2 = service.enrich_incident("inc-idempotent")
    assert len(result2.enrichments_created) == 0
    assert len(result2.enrichments_updated) == 1  # Should update, not duplicate

    # Verify persistence
    enrichments = ti_repo.list_by_incident("inc-idempotent")
    assert len(enrichments) == 1
