"""Incident management endpoints."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session

from ...database import get_session
from ...models.incidents import Incident, IncidentStatus
from ...persistence.models import Incident as PersistenceIncident
from ...persistence.repositories import (
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
)
from ...services.incidents import IncidentService

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])
logger = logging.getLogger(__name__)


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: IncidentStatus


def _to_domain_incident(record: PersistenceIncident) -> Incident:
    return Incident(
        incident_id=record.incident_id,
        title=record.title,
        description=record.description,
        severity=record.severity,
        status=IncidentStatus(record.status),
        created_at=record.created_at,
        updated_at=record.updated_at,
        correlation_ids=json.loads(record.correlation_ids_json)
        if record.correlation_ids_json
        else [],
        alert_ids=json.loads(record.alert_ids_json) if record.alert_ids_json else [],
        event_ids=json.loads(record.event_ids_json) if record.event_ids_json else [],
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        mitre_techniques=json.loads(record.mitre_techniques_json)
        if record.mitre_techniques_json
        else [],
        evidence=json.loads(record.evidence_json) if record.evidence_json else {},
        tags=json.loads(record.tags_json) if record.tags_json else [],
    )


@router.get("", response_model=list[Incident])
def list_incidents(
    status: str | None = None,
    correlation_id: str | None = None,
    severity: int | None = None,
    limit: int = 100,
    session: Session = Depends(get_session),
) -> list[Incident]:
    repository = IncidentRepository(session)
    records = repository.list_incidents(
        status=status,
        correlation_id=correlation_id,
        min_severity=severity,
        limit=limit,
    )
    return [_to_domain_incident(record) for record in records]


@router.get("/{incident_id}", response_model=Incident)
def get_incident(
    incident_id: str, session: Session = Depends(get_session)
) -> Incident:
    repository = IncidentRepository(session)
    record = repository.get_incident(incident_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return _to_domain_incident(record)


@router.patch("/{incident_id}/status", response_model=Incident)
def update_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    session: Session = Depends(get_session),
) -> Incident:
    service = IncidentService(
        incident_repository=IncidentRepository(session),
        correlation_repository=CorrelationRepository(session),
        event_repository=EventRepository(session),
    )
    updated = service.update_incident_status(
        incident_id=incident_id, new_status=update.status, actor="analyst"
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return updated
