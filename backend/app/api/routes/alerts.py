"""Alert query endpoints."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from ...database import get_session
from ...models.alerts import Alert, AlertStatus
from ...persistence.models import Alert as PersistenceAlert
from ...persistence.repositories import AlertRepository

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])
logger = logging.getLogger(__name__)


def _to_domain_alert(record: PersistenceAlert) -> Alert:
    evidence = json.loads(record.evidence_json) if record.evidence_json else {}
    mitre = json.loads(record.mitre_techniques_json) if record.mitre_techniques_json else []
    return Alert(
        alert_id=record.alert_id,
        event_id=record.event_id,
        timestamp=record.timestamp,
        rule_id=record.rule_id,
        rule_name=record.rule_name,
        severity=record.severity,
        description=record.description,
        source=record.source,
        evidence=evidence,
        mitre_techniques=mitre,
        status=AlertStatus(record.status),
    )


@router.get("", response_model=list[Alert])
def list_alerts(
    limit: int = 100,
    event_id: str | None = None,
    session: Session = Depends(get_session),
) -> list[Alert]:
    repository = AlertRepository(session)
    if event_id is not None:
        records = repository.list_alerts_by_event(event_id)
    else:
        records = repository.list_alerts(limit=limit)
    return [_to_domain_alert(record) for record in records]


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, session: Session = Depends(get_session)) -> Alert:
    repository = AlertRepository(session)
    record = repository.get_alert(alert_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    return _to_domain_alert(record)
