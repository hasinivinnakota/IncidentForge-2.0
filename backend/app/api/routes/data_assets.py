"""Data Assets API routes.

Provides:
  POST   /api/v1/data-assets             - Register a dataset (profile from file or supply metadata)
  GET    /api/v1/data-assets             - List registered datasets
  GET    /api/v1/data-assets/{asset_id}  - Get specific dataset profile
  GET    /api/v1/data-assets/{asset_id}/profile   - Get detailed column profile
  GET    /api/v1/data-assets/{asset_id}/activity  - List activity for dataset
  POST   /api/v1/data-assets/{asset_id}/assess    - Re-run security assessment on registered dataset
  POST   /api/v1/data-assets/{asset_id}/simulate  - Simulate suspicious activity for a dataset

Does NOT expose raw dataset row contents.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from ...database import get_session
from ...models.cases import CasePriority
from ...models.dataset import DatasetAsset, DatasetActivity
from ...models.dataset_assessment import DatasetSecurityAssessment, DatasetSimulationResult
from ...models.processing import PipelineResult
from ...models.dataset_overview import DatasetOverview
from ...persistence.repositories import (
    AlertRepository,
    CaseRepository,
    CorrelationRepository,
    DatasetRepository,
    EventRepository,
    IncidentRepository,
    ResponseActionRepository,
    InvestigationRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from ...rules import get_all_correlation_rules, get_default_rules
from ...services.alerts import AlertService
from ...services.correlation import CorrelationEngine
from ...services.dataset import DatasetService
from ...services.dataset_assessment import DatasetAssessmentService
from ...services.detection import DetectionEngine
from ...services.incidents import IncidentService
from ...services.normalization import NormalizationService
from ...services.pipeline import EventPipeline
from ...services.processing import EventProcessingService
from ...services.risk import RiskScoringService
from ...services.threat_intel import ThreatIntelligenceService
from ...services.cases import CaseService
from ...adapters.dataset import DatasetActivityAdapter

router = APIRouter(prefix="/api/v1/data-assets", tags=["data-assets"])
logger = logging.getLogger(__name__)

_normalizer = NormalizationService()
_detection_engine = DetectionEngine(get_default_rules())
_correlation_rules = get_all_correlation_rules()


def get_dataset_service(session: Session = Depends(get_session)) -> DatasetService:
    return DatasetService(DatasetRepository(session))


def _build_pipeline(session: Session) -> EventPipeline:
    return EventPipeline(
        processing_service=EventProcessingService(EventRepository(session)),
        detection_engine=_detection_engine,
        alert_service=AlertService(AlertRepository(session), EventRepository(session)),
        correlation_engine=CorrelationEngine(
            rules=_correlation_rules,
            correlation_repository=CorrelationRepository(session),
            alert_repository=AlertRepository(session),
            event_repository=EventRepository(session),
        ),
        incident_service=IncidentService(
            incident_repository=IncidentRepository(session),
            correlation_repository=CorrelationRepository(session),
            event_repository=EventRepository(session),
        ),
        risk_service=RiskScoringService(
            risk_repository=RiskAssessmentRepository(session),
            incident_repository=IncidentRepository(session),
            correlation_repository=CorrelationRepository(session),
            event_repository=EventRepository(session),
        ),
        threat_intel_service=ThreatIntelligenceService(
            threat_intel_repository=ThreatIntelRepository(session),
            incident_repository=IncidentRepository(session),
            event_repository=EventRepository(session),
        ),
    )


class DatasetRegisterRequest(DatasetAsset):
    """Request body for registering a dataset from an already-profiled asset."""
    pass


@router.post("", response_model=DatasetAsset, status_code=status.HTTP_201_CREATED)
def register_dataset(
    asset: DatasetAsset,
    svc: DatasetService = Depends(get_dataset_service),
) -> DatasetAsset:
    """Register a dataset asset in the catalog.

    Supply a fully-formed DatasetAsset including columns, sensitivity, and schema metadata.
    No raw dataset contents are stored.
    """
    try:
        return svc.register_asset(asset)
    except SQLAlchemyError as exc:
        logger.exception("Failed to register dataset", extra={"dataset_id": asset.dataset_id})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dataset registration failed",
        ) from exc


@router.get("", response_model=list[DatasetAsset])
def list_datasets(
    limit: int = 100,
    svc: DatasetService = Depends(get_dataset_service),
) -> list[DatasetAsset]:
    """List all registered datasets with classification metadata."""
    return svc.list_assets(limit=limit)


@router.get("/{asset_id}", response_model=DatasetAsset)
def get_dataset(
    asset_id: str,
    svc: DatasetService = Depends(get_dataset_service),
) -> DatasetAsset:
    """Get a specific dataset profile."""
    asset = svc.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{asset_id}' not found",
        )
    return asset


@router.get("/{asset_id}/profile", response_model=dict)
def get_dataset_profile(
    asset_id: str,
    svc: DatasetService = Depends(get_dataset_service),
) -> dict:
    """Get the detailed column schema and sensitivity profile for a dataset.

    Does NOT expose raw row data - only column names, types, and classifications.
    """
    asset = svc.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{asset_id}' not found",
        )
    return {
        "dataset_id": asset.dataset_id,
        "name": asset.name,
        "format": asset.format.value,
        "sensitivity": asset.sensitivity.value,
        "record_count": asset.record_count,
        "column_count": asset.column_count,
        "schema_hash": asset.schema_hash,
        "sensitive_columns": asset.sensitive_columns,
        "columns": [
            {
                "name": c.name,
                "data_type": c.data_type,
                "is_sensitive": c.is_sensitive,
                "pii_type": c.pii_type,
                "sensitivity": c.sensitivity.value,
            }
            for c in asset.columns
        ],
        "metadata": asset.metadata,
    }


@router.get("/{asset_id}/activity", response_model=list[dict])
def get_dataset_activity(
    asset_id: str,
    limit: int = 50,
    svc: DatasetService = Depends(get_dataset_service),
) -> list[dict]:
    """List recent activity events for a dataset."""
    asset = svc.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{asset_id}' not found",
        )
    return svc.list_activities(dataset_id=asset_id, limit=limit)


@router.post("/{asset_id}/assess", response_model=DatasetSecurityAssessment, status_code=status.HTTP_200_OK)
def assess_dataset(
    asset_id: str,
    svc: DatasetService = Depends(get_dataset_service),
) -> DatasetSecurityAssessment:
    """Re-run the security assessment on a registered dataset using its stored metadata.

    This performs a deterministic heuristic analysis on sanitized column metadata.
    No raw dataset file is required — the assessment runs on the registered profile.
    """
    asset = svc.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{asset_id}' not found",
        )

    assessor = DatasetAssessmentService()
    assessment = assessor.assess(asset)
    logger.info(
        "Dataset security assessment completed",
        extra={
            "dataset_id": asset_id,
            "score": assessment.security_score.score,
            "findings": len(assessment.findings),
        },
    )
    return assessment


@router.post("/{asset_id}/simulate", response_model=DatasetSimulationResult, status_code=status.HTTP_202_ACCEPTED)
def simulate_dataset_attack(
    asset_id: str,
    svc: DatasetService = Depends(get_dataset_service),
    session: Session = Depends(get_session),
) -> DatasetSimulationResult:
    """Simulate suspicious dataset access activity for a registered dataset.

    Generates a deterministic sequence of synthetic events:
      dataset_opened → sensitive_column_access → bulk_access → dataset_exported

    These events are fed through the EXISTING IncidentForge SOC pipeline
    (EventPipeline → Detection → Correlation → Incident → ML Risk → TI).

    ALL data is synthetic. No real files are accessed.
    """
    asset = svc.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{asset_id}' not found",
        )

    # A simulation represents one reproducible scenario for this dataset.
    # Reusing the dataset creation time prevents each button click from
    # changing the incident feature window and risk score.
    base_ts = asset.created_at.astimezone(timezone.utc).replace(second=0, microsecond=0)
    sim_actor = "external-user-demo"
    sim_host = "external-workstation-99"
    sim_src_ip = "198.51.100.42"   # TEST-NET — clearly synthetic
    sim_dst_ip = "203.0.113.99"    # TEST-NET — clearly synthetic

    # Stable suffix makes repeated simulations resolve to the same events.
    import hashlib
    run_hash = hashlib.sha256(asset_id.encode()).hexdigest()[:8]

    # Sensitive columns from the actual registered asset (sanitized names only)
    sensitive_cols = asset.sensitive_columns[:5]

    synthetic_activities = [
        DatasetActivity(
            activity_id=f"sim-{asset_id[:8]}-{run_hash}-open",
            timestamp=base_ts,
            dataset_id=asset_id,
            dataset_name=asset.name,
            operation="dataset_opened",
            actor=sim_actor,
            actor_host=sim_host,
            source_ip=sim_src_ip,
            records_accessed=0,
            records_modified=0,
            context={"sensitivity": asset.sensitivity.value, "simulated": True},
        ),
        DatasetActivity(
            activity_id=f"sim-{asset_id[:8]}-{run_hash}-col-access",
            timestamp=base_ts + timedelta(minutes=3),
            dataset_id=asset_id,
            dataset_name=asset.name,
            operation="sensitive_column_access",
            actor=sim_actor,
            actor_host=sim_host,
            source_ip=sim_src_ip,
            records_accessed=max(1000, asset.record_count // 10),
            sensitive_columns=sensitive_cols,
            context={"sensitivity": asset.sensitivity.value, "simulated": True},
        ),
        DatasetActivity(
            activity_id=f"sim-{asset_id[:8]}-{run_hash}-bulk",
            timestamp=base_ts + timedelta(minutes=8),
            dataset_id=asset_id,
            dataset_name=asset.name,
            operation="bulk_access",
            actor=sim_actor,
            actor_host=sim_host,
            source_ip=sim_src_ip,
            records_accessed=max(50000, asset.record_count),
            sensitive_columns=sensitive_cols,
            context={"sensitivity": asset.sensitivity.value, "simulated": True},
        ),
        DatasetActivity(
            activity_id=f"sim-{asset_id[:8]}-{run_hash}-export",
            timestamp=base_ts + timedelta(minutes=14),
            dataset_id=asset_id,
            dataset_name=asset.name,
            operation="dataset_exported",
            actor=sim_actor,
            actor_host=sim_host,
            source_ip=sim_src_ip,
            destination_ip=sim_dst_ip,
            records_accessed=max(50000, asset.record_count),
            export_size_bytes=max(asset.size_bytes, 10 * 1024 * 1024),
            export_destination=f"ftp://{sim_dst_ip}/exfil/{asset_id}.parquet",
            sensitive_columns=sensitive_cols,
            context={"sensitivity": asset.sensitivity.value, "simulated": True},
        ),
    ]

    # Feed through existing pipeline via DatasetActivityAdapter
    adapter = DatasetActivityAdapter(activities=synthetic_activities, normalizer=_normalizer)
    normalized_events = adapter.get_normalized_events()

    # Record activities in the dataset audit log
    for act in synthetic_activities:
        try:
            svc.record_activity(act)
        except Exception:
            logger.warning("Failed to record simulation activity %s (duplicate or constraint error — skipping)", act.activity_id)
            session.rollback()

    # Process through the existing SOC pipeline
    pipeline = _build_pipeline(session)
    pipeline_results: list[dict] = []
    alerts_created = 0
    correlations_created = 0
    incidents_created = 0

    for event in normalized_events:
        try:
            result: PipelineResult = pipeline.ingest(event)
            result_dict = result.model_dump(mode="json") if hasattr(result, "model_dump") else {}
            pipeline_results.append(result_dict)
            alerts_created += len(result_dict.get("alerts", []))
            correlations_created += len(result_dict.get("correlations", []))
            incidents_created += len(result_dict.get("incidents_created", []))
        except SQLAlchemyError as exc:
            logger.exception("Pipeline failed for sim event %s", event.event_id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Dataset simulation pipeline error",
            ) from exc

    # Seed one analyst case per affected incident. IDs are deterministic per
    # incident, so repeated simulations enrich the same case instead of
    # creating duplicate records.
    case_service = CaseService(
        case_repository=CaseRepository(session),
        event_repository=EventRepository(session),
        incident_repository=IncidentRepository(session),
        investigation_repository=InvestigationRepository(session),
    )
    affected_incident_ids = sorted({
        incident_id
        for result in pipeline_results
        for incident_id in result.get("incidents_created", []) + result.get("incidents_updated", [])
    })
    for incident_id in affected_incident_ids:
        incident = IncidentRepository(session).get_incident(incident_id)
        if incident is None:
            continue
        priority = (
            CasePriority.CRITICAL if incident.severity >= 12
            else CasePriority.HIGH if incident.severity >= 8
            else CasePriority.MEDIUM if incident.severity >= 4
            else CasePriority.LOW
        )
        case_service.create_case(
            title=f"Dataset security case: {asset.name}",
            description=(
                f"Dataset security activity generated incident {incident_id}. "
                "Review the linked alerts, correlations, risk assessment, and export activity."
            ),
            severity=incident.severity,
            priority=priority,
            incident_id=incident_id,
            tags=[f"dataset:{asset_id}", "simulated-dataset-activity"],
            actor="system",
        )

    logger.info(
        "Dataset attack simulation complete",
        extra={
            "dataset_id": asset_id,
            "events": len(normalized_events),
            "alerts": alerts_created,
            "incidents": incidents_created,
        },
    )

    return DatasetSimulationResult(
        dataset_id=asset_id,
        dataset_name=asset.name,
        events_generated=len(normalized_events),
        alerts_created=alerts_created,
        correlations_created=correlations_created,
        incidents_created=incidents_created,
        simulation_actor=sim_actor,
        pipeline_results=pipeline_results,
    )


from .alerts import _to_domain_alert
from .correlations import _to_domain_correlation
from .incidents import _to_domain_incident
from .risk import _to_domain_assessment
from .threat_intel import _to_domain_result as _to_domain_intel
from ...services.response import ResponseService

@router.get("/{asset_id}/overview", response_model=DatasetOverview)
def get_dataset_overview(
    asset_id: str,
    svc: DatasetService = Depends(get_dataset_service),
    session: Session = Depends(get_session),
) -> DatasetOverview:
    """Get a comprehensive security overview for a dataset."""
    asset = svc.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{asset_id}' not found",
        )
    
    assessor = DatasetAssessmentService()
    assessment = assessor.assess(asset)
    
    # Repositories
    alert_repo = AlertRepository(session)
    corr_repo = CorrelationRepository(session)
    inc_repo = IncidentRepository(session)
    risk_repo = RiskAssessmentRepository(session)
    ti_repo = ThreatIntelRepository(session)
    
    # Services for cases and response which return domain models natively
    case_svc = CaseService(
        CaseRepository(session),
        EventRepository(session),
        IncidentRepository(session),
        InvestigationRepository(session),
    )
    resp_svc = ResponseService(ResponseActionRepository(session), IncidentRepository(session))
    
    urn_tag = f"dataset:{asset_id}"
    
    # 1. Activities
    activities = svc.list_activities(asset_id, limit=500)
    
    # 2. Alerts (filter by evidence.dataset_id)
    all_alerts_pers = alert_repo.list_alerts(limit=1000)
    alerts = []
    for p_alert in all_alerts_pers:
        d_alert = _to_domain_alert(p_alert)
        if d_alert.evidence and d_alert.evidence.get("dataset_id") == asset_id:
            alerts.append(d_alert)
    
    # 3. Correlations
    all_corrs_pers = corr_repo.list_correlations(limit=1000)
    correlations = []
    for p_corr in all_corrs_pers:
        d_corr = _to_domain_correlation(p_corr)
        if d_corr.evidence and urn_tag in str(d_corr.evidence.get("entity_key", "")):
            correlations.append(d_corr)
            
    # 4. Incidents
    all_incs_pers = inc_repo.list_incidents(limit=1000)
    incidents = []
    for p_inc in all_incs_pers:
        d_inc = _to_domain_incident(p_inc)
        if d_inc.tags and any(urn_tag in tag for tag in d_inc.tags):
            incidents.append(d_inc)
            
    # 5. Risk Assessments (sorted newest-first by scored_at)
    all_risks_pers = risk_repo.list_assessments(limit=1000)
    matching_inc_ids = {inc.incident_id for inc in incidents}
    risk_assessments = [
        _to_domain_assessment(p_risk)
        for p_risk in all_risks_pers
        if p_risk.incident_id in matching_inc_ids
    ]
    risk_assessments.sort(key=lambda r: r.scored_at, reverse=True)
            
    # 6. Threat Intel
    all_ti_pers = []
    for inc in incidents:
        all_ti_pers.extend(ti_repo.list_by_incident(inc.incident_id))
    threat_intel = []
    for p_ti in all_ti_pers:
        d_ti = _to_domain_intel(p_ti)
        if d_ti.tags and any(urn_tag in tag for tag in d_ti.tags):
            threat_intel.append(d_ti)
            
    # 7. Cases
    all_cases = case_svc.list_cases(limit=1000)
    cases = []
    for c in all_cases:
        has_tag = c.tags and any(urn_tag in tag for tag in c.tags)
        has_ref = c.evidence_references and any(urn_tag in ref.reference_key for ref in c.evidence_references)
        if has_tag or has_ref:
            cases.append(c)
            
    # 8. Response Actions
    all_resp = []
    for inc in incidents:
        all_resp.extend(resp_svc.list_actions(inc.incident_id))
    response_records = [r for r in all_resp if r.entity_key and urn_tag in r.entity_key]
    
    return DatasetOverview(
        dataset_id=asset_id,
        asset=asset,
        assessment=assessment,
        activities=activities,
        alerts=alerts,
        correlations=correlations,
        incidents=incidents,
        risk_assessments=risk_assessments,
        threat_intel=threat_intel,
        cases=cases,
        response_records=response_records
    )
