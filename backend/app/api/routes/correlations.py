"""Correlation query endpoints."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from ...database import get_session
from ...models.correlation import Correlation, CorrelationStatus
from ...persistence.models import Correlation as PersistenceCorrelation
from ...persistence.repositories import CorrelationRepository

router = APIRouter(prefix="/api/v1/correlations", tags=["correlations"])
logger = logging.getLogger(__name__)


def _to_domain_correlation(record: PersistenceCorrelation) -> Correlation:
    return Correlation(
        correlation_id=record.correlation_id,
        correlation_type=record.correlation_type,
        entity_key=record.entity_key,
        title=record.title,
        description=record.description,
        severity=record.severity,
        status=CorrelationStatus(record.status),
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        alert_ids=json.loads(record.alert_ids_json) if record.alert_ids_json else [],
        event_ids=json.loads(record.event_ids_json) if record.event_ids_json else [],
        alert_count=record.alert_count,
        mitre_techniques=json.loads(record.mitre_techniques_json)
        if record.mitre_techniques_json
        else [],
        evidence=json.loads(record.evidence_json) if record.evidence_json else {},
    )


@router.get("", response_model=list[Correlation])
def list_correlations(
    status: str | None = None,
    alert_id: str | None = None,
    event_id: str | None = None,
    limit: int = 100,
    session: Session = Depends(get_session),
) -> list[Correlation]:
    repository = CorrelationRepository(session)
    records = repository.list_correlations(
        status=status, alert_id=alert_id, event_id=event_id, limit=limit
    )
    return [_to_domain_correlation(record) for record in records]


@router.get("/{correlation_id}", response_model=Correlation)
def get_correlation(
    correlation_id: str, session: Session = Depends(get_session)
) -> Correlation:
    repository = CorrelationRepository(session)
    record = repository.get_correlation(correlation_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation {correlation_id} not found",
        )
    return _to_domain_correlation(record)
