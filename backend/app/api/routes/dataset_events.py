"""Dataset event intake endpoint.

Accepts raw DatasetActivity records, converts them via DatasetActivityAdapter
into NormalizedEvent instances, and runs them through the existing EventPipeline.

POST /api/v1/data-assets/events   - Ingest dataset activity telemetry
POST /api/v1/data-assets/simulate - Run the reproducible expo demo scenario (clearly synthetic)
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from ...adapters.dataset import DatasetActivityAdapter
from ...database import get_session
from ...models.dataset import DatasetActivity
from ...models.processing import PipelineResult
from ...persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    DatasetRepository,
    EventRepository,
    IncidentRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from ...rules import get_all_correlation_rules, get_default_rules
from ...services.alerts import AlertService
from ...services.correlation import CorrelationEngine
from ...services.dataset import DatasetService
from ...services.detection import DetectionEngine
from ...services.incidents import IncidentService
from ...services.normalization import NormalizationService
from ...services.pipeline import EventPipeline
from ...services.processing import EventProcessingService
from ...services.risk import RiskScoringService
from ...services.threat_intel import ThreatIntelligenceService

router = APIRouter(prefix="/api/v1/data-assets", tags=["data-assets"])
logger = logging.getLogger(__name__)

normalizer = NormalizationService()
detection_engine = DetectionEngine(get_default_rules())
correlation_rules = get_all_correlation_rules()


def build_pipeline(session: Session) -> EventPipeline:
    event_repo = EventRepository(session)
    alert_repo = AlertRepository(session)
    correlation_repo = CorrelationRepository(session)
    incident_repo = IncidentRepository(session)
    risk_repo = RiskAssessmentRepository(session)
    threat_intel_repo = ThreatIntelRepository(session)

    return EventPipeline(
        processing_service=EventProcessingService(event_repo),
        detection_engine=detection_engine,
        alert_service=AlertService(alert_repo, event_repo),
        correlation_engine=CorrelationEngine(
            rules=correlation_rules,
            correlation_repository=correlation_repo,
            alert_repository=alert_repo,
            event_repository=event_repo,
        ),
        incident_service=IncidentService(
            incident_repository=incident_repo,
            correlation_repository=correlation_repo,
            event_repository=event_repo,
        ),
        risk_service=RiskScoringService(
            risk_repository=risk_repo,
            incident_repository=incident_repo,
            correlation_repository=correlation_repo,
            event_repository=event_repo,
        ),
        threat_intel_service=ThreatIntelligenceService(
            threat_intel_repository=threat_intel_repo,
            incident_repository=incident_repo,
            event_repository=event_repo,
        ),
    )


@router.post("/events", response_model=list[PipelineResult], status_code=status.HTTP_202_ACCEPTED)
def ingest_dataset_events(
    activities: list[DatasetActivity],
    session: Session = Depends(get_session),
) -> list[PipelineResult]:
    """Ingest dataset activity telemetry into the IncidentForge pipeline.

    Activities are converted via DatasetActivityAdapter into NormalizedEvents
    and processed by the existing EventPipeline (detection, correlation, incident, ML risk, TI).
    """
    if not activities:
        return []

    adapter = DatasetActivityAdapter(activities=activities, normalizer=normalizer)
    normalized_events = adapter.get_normalized_events()

    dataset_repo = DatasetRepository(session)
    ds_svc = DatasetService(dataset_repo)
    for act in activities:
        try:
            ds_svc.record_activity(act)
        except Exception:
            logger.warning("Failed to record dataset activity %s", act.activity_id)

    results: list[PipelineResult] = []
    pipeline = build_pipeline(session)
    for event in normalized_events:
        try:
            result = pipeline.ingest(event)
            results.append(result)
        except SQLAlchemyError as exc:
            logger.exception("Pipeline ingestion failed for dataset event %s", event.event_id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Dataset event could not be accepted",
            ) from exc

    return results


@router.post("/simulate", response_model=list[PipelineResult], status_code=status.HTTP_202_ACCEPTED)
def run_expo_simulation(
    session: Session = Depends(get_session),
) -> list[PipelineResult]:
    """Run the reproducible expo demo scenario (SYNTHETIC DATA ONLY).

    This endpoint generates a deterministic sequence of synthetic dataset activities:
    1. Normal dataset open / read
    2. Sensitive column access on HIGH-sensitivity dataset
    3. Bulk access (100,000 records)
    4. Dataset export to external destination

    All data is synthetic and safe. No real files are read or modified.
    """
    base_ts = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)

    synthetic_activities = [
        DatasetActivity(
            activity_id="demo-act-001",
            timestamp=base_ts,
            dataset_id="demo-financial-records",
            dataset_name="financial_records.parquet",
            operation="dataset_opened",
            actor="analyst_demo",
            actor_host="demo-workstation",
            source_ip="192.168.10.45",
            records_accessed=0,
            records_modified=0,
            context={"sensitivity": "HIGH", "demo": True},
        ),
        DatasetActivity(
            activity_id="demo-act-002",
            timestamp=base_ts.replace(minute=5),
            dataset_id="demo-financial-records",
            dataset_name="financial_records.parquet",
            operation="sensitive_column_access",
            actor="analyst_demo",
            actor_host="demo-workstation",
            source_ip="192.168.10.45",
            records_accessed=5000,
            sensitive_columns=["account_number", "account_balance", "routing_number"],
            context={"sensitivity": "HIGH", "demo": True},
        ),
        DatasetActivity(
            activity_id="demo-act-003",
            timestamp=base_ts.replace(minute=12),
            dataset_id="demo-financial-records",
            dataset_name="financial_records.parquet",
            operation="bulk_access",
            actor="analyst_demo",
            actor_host="demo-workstation",
            source_ip="192.168.10.45",
            records_accessed=100000,
            sensitive_columns=["account_number", "account_balance"],
            context={"sensitivity": "HIGH", "demo": True},
        ),
        DatasetActivity(
            activity_id="demo-act-004",
            timestamp=base_ts.replace(minute=18),
            dataset_id="demo-financial-records",
            dataset_name="financial_records.parquet",
            operation="dataset_exported",
            actor="analyst_demo",
            actor_host="demo-workstation",
            source_ip="192.168.10.45",
            destination_ip="203.0.113.88",
            records_accessed=100000,
            export_size_bytes=52428800,
            export_destination="ftp://203.0.113.88/upload/financial_records.parquet",
            sensitive_columns=["account_number", "account_balance"],
            context={"sensitivity": "HIGH", "demo": True},
        ),
    ]

    adapter = DatasetActivityAdapter(activities=synthetic_activities, normalizer=normalizer)
    normalized_events = adapter.get_normalized_events()

    dataset_repo = DatasetRepository(session)
    ds_svc = DatasetService(dataset_repo)
    for act in synthetic_activities:
        try:
            ds_svc.record_activity(act)
        except Exception:
            pass

    results: list[PipelineResult] = []
    pipeline = build_pipeline(session)
    for event in normalized_events:
        try:
            result = pipeline.ingest(event)
            results.append(result)
        except SQLAlchemyError as exc:
            logger.exception("Demo pipeline ingestion failed for event %s", event.event_id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Demo simulation failed",
            ) from exc

    return results
