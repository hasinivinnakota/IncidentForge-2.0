"""Event intake endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from ...adapters.fixtures import FixtureAdapter
from ...database import get_session
from ...models.events import NormalizedEvent
from ...models.processing import PipelineResult
from ...persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from ...rules import get_default_correlation_rules, get_default_rules
from ...services.alerts import AlertService
from ...services.correlation import CorrelationEngine
from ...services.detection import DetectionEngine
from ...services.incidents import IncidentService
from ...services.normalization import NormalizationService
from ...services.pipeline import EventPipeline
from ...services.processing import EventProcessingService
from ...services.risk import RiskScoringService
from ...services.threat_intel import ThreatIntelligenceService

router = APIRouter(prefix="/api/v1/events", tags=["events"])
logger = logging.getLogger(__name__)
normalizer = NormalizationService()
detection_engine = DetectionEngine(get_default_rules())
correlation_rules = get_default_correlation_rules()


@router.post("", response_model=PipelineResult, status_code=status.HTTP_202_ACCEPTED)
def accept_event(
    event: NormalizedEvent, session: Session = Depends(get_session)
) -> PipelineResult:
    try:
        normalized = normalizer.normalize(event.model_dump())
        event_repo = EventRepository(session)
        alert_repo = AlertRepository(session)
        correlation_repo = CorrelationRepository(session)
        incident_repo = IncidentRepository(session)
        risk_repo = RiskAssessmentRepository(session)
        threat_intel_repo = ThreatIntelRepository(session)

        correlation_engine = CorrelationEngine(
            rules=correlation_rules,
            correlation_repository=correlation_repo,
            alert_repository=alert_repo,
            event_repository=event_repo,
        )
        incident_service = IncidentService(
            incident_repository=incident_repo,
            correlation_repository=correlation_repo,
            event_repository=event_repo,
        )
        risk_service = RiskScoringService(
            risk_repository=risk_repo,
            incident_repository=incident_repo,
            correlation_repository=correlation_repo,
            event_repository=event_repo,
        )
        threat_intel_service = ThreatIntelligenceService(
            threat_intel_repository=threat_intel_repo,
            incident_repository=incident_repo,
            event_repository=event_repo,
        )
        pipeline = EventPipeline(
            processing_service=EventProcessingService(event_repo),
            detection_engine=detection_engine,
            alert_service=AlertService(alert_repo, event_repo),
            correlation_engine=correlation_engine,
            incident_service=incident_service,
            risk_service=risk_service,
            threat_intel_service=threat_intel_service,
        )
        result = pipeline.ingest(normalized)
    except SQLAlchemyError as exc:
        logger.exception("Event persistence failed", extra={"event_id": event.event_id})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Event could not be accepted",
        ) from exc
    logger.info(
        "Accepted event",
        extra={"event_id": result.event_id, "source": normalized.source},
    )
    return result


@router.get("/example", response_model=NormalizedEvent)
def example_event() -> NormalizedEvent:
    return normalizer.normalize(FixtureAdapter().get_events()[0])
