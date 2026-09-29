"""Threat Intelligence API endpoints."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from ...database import get_session
from ...models.threat_intel import IOCType, ThreatClassification, ThreatIntelResult
from ...persistence.models import ThreatIntelEnrichment as PersistenceThreatIntelEnrichment
from ...persistence.repositories import ThreatIntelRepository

router = APIRouter(tags=["threat-intelligence"])
logger = logging.getLogger(__name__)


def _to_domain_result(record: PersistenceThreatIntelEnrichment) -> ThreatIntelResult:
    """Convert persistence record to domain model."""
    return ThreatIntelResult(
        enrichment_id=record.enrichment_id,
        incident_id=record.incident_id,
        ioc_type=IOCType(record.ioc_type),
        ioc_value=record.ioc_value,
        classification=ThreatClassification(record.classification),
        confidence=record.confidence,
        reputation=record.reputation,
        threat_category=record.threat_category or "",
        provider=record.provider,
        source_count=record.source_count,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        tags=json.loads(record.tags_json) if record.tags_json else [],
        explanation=record.explanation or "No explanation available.",
        lookup_timestamp=record.lookup_timestamp,
    )


@router.get(
    "/api/v1/incidents/{incident_id}/threat-intelligence",
    response_model=list[ThreatIntelResult],
)
def get_incident_threat_intelligence(
    incident_id: str, session: Session = Depends(get_session)
) -> list[ThreatIntelResult]:
    """Retrieve all threat intelligence enrichments associated with an incident."""
    repository = ThreatIntelRepository(session)
    records = repository.list_by_incident(incident_id)
    return [_to_domain_result(r) for r in records]


@router.get(
    "/api/v1/threat-intelligence/{enrichment_id}",
    response_model=ThreatIntelResult,
)
def get_threat_intelligence_by_id(
    enrichment_id: str, session: Session = Depends(get_session)
) -> ThreatIntelResult:
    """Retrieve a single threat intelligence enrichment by its ID."""
    repository = ThreatIntelRepository(session)
    record = repository.get_enrichment(enrichment_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat intelligence enrichment {enrichment_id} not found",
        )
    return _to_domain_result(record)


@router.get(
    "/api/v1/threat-intelligence/ioc/{ioc_type}/{ioc_value:path}",
    response_model=list[ThreatIntelResult],
)
def get_threat_intelligence_by_ioc(
    ioc_type: str, ioc_value: str, session: Session = Depends(get_session)
) -> list[ThreatIntelResult]:
    """Retrieve threat intelligence enrichments by IOC type and value."""
    # Validate ioc_type
    try:
        IOCType(ioc_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IOC type: {ioc_type}. Valid types: {[t.value for t in IOCType]}",
        )
    repository = ThreatIntelRepository(session)
    records = repository.find_by_ioc(ioc_type, ioc_value)
    return [_to_domain_result(r) for r in records]
