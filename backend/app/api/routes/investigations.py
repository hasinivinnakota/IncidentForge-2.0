"""AI Investigation API endpoints."""

from datetime import timezone
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlmodel import Session

from ...database import get_session
from ...models.investigation import (
    FindingItem,
    InvestigationResult,
    RecommendedAction,
    TimelineItem,
)
from ...persistence.models import Investigation as PersistenceInvestigation
from ...persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    InvestigationRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from ...services.ai_investigator import AIInvestigatorService

router = APIRouter(tags=["investigations"])
logger = logging.getLogger(__name__)


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    force: bool = False


def _to_domain_result(record: PersistenceInvestigation) -> InvestigationResult:
    """Convert persistence record to domain model."""
    findings_data = json.loads(record.findings_json) if record.findings_json else []
    findings = [FindingItem(**f) for f in findings_data]

    timeline_data = json.loads(record.timeline_json) if record.timeline_json else []
    timeline = [TimelineItem(**t) for t in timeline_data]

    mitre_techniques = (
        json.loads(record.mitre_techniques_json)
        if record.mitre_techniques_json
        else []
    )
    threat_intel_summary = (
        json.loads(record.threat_intel_summary_json)
        if record.threat_intel_summary_json
        else {}
    )
    investigation_gaps = (
        json.loads(record.investigation_gaps_json)
        if record.investigation_gaps_json
        else []
    )
    recommended_next_steps = (
        json.loads(record.recommended_next_steps_json)
        if record.recommended_next_steps_json
        else []
    )
    response_actions_data = (
        json.loads(record.possible_response_actions_json)
        if record.possible_response_actions_json
        else []
    )
    possible_response_actions = [
        RecommendedAction(**a) for a in response_actions_data
    ]

    return InvestigationResult(
        investigation_id=record.investigation_id,
        incident_id=record.incident_id,
        summary=record.summary,
        confidence=record.confidence,
        findings=findings,
        timeline=timeline,
        mitre_techniques=mitre_techniques,
        threat_intel_summary=threat_intel_summary,
        investigation_gaps=investigation_gaps,
        recommended_next_steps=recommended_next_steps,
        possible_response_actions=possible_response_actions,
        provider=record.provider,
        model_name=record.model_name,
        generated_at=record.generated_at.replace(tzinfo=timezone.utc)
        if record.generated_at and record.generated_at.tzinfo is None
        else record.generated_at,
    )


@router.post(
    "/api/v1/incidents/{incident_id}/investigate",
    response_model=InvestigationResult,
    status_code=status.HTTP_200_OK,
)
def trigger_investigation(
    incident_id: str,
    request: InvestigateRequest | None = None,
    session: Session = Depends(get_session),
) -> InvestigationResult:
    """Trigger or retrieve an AI investigation for a specific incident."""
    force = request.force if request else False

    inv_repo = InvestigationRepository(session)
    inc_repo = IncidentRepository(session)
    ev_repo = EventRepository(session)
    al_repo = AlertRepository(session)
    cr_repo = CorrelationRepository(session)
    rk_repo = RiskAssessmentRepository(session)
    ti_repo = ThreatIntelRepository(session)

    # Check incident exists
    incident = inc_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    service = AIInvestigatorService(
        investigation_repository=inv_repo,
        incident_repository=inc_repo,
        event_repository=ev_repo,
        alert_repository=al_repo,
        correlation_repository=cr_repo,
        risk_repository=rk_repo,
        threat_intel_repository=ti_repo,
    )

    result = service.investigate_incident(incident_id, force=force)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Investigation could not be generated",
        )
    return result


@router.get(
    "/api/v1/incidents/{incident_id}/investigation",
    response_model=InvestigationResult,
)
def get_incident_latest_investigation(
    incident_id: str, session: Session = Depends(get_session)
) -> InvestigationResult:
    """Get the latest AI investigation for a given incident."""
    inv_repo = InvestigationRepository(session)
    inc_repo = IncidentRepository(session)

    incident = inc_repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    record = inv_repo.get_latest_for_incident(incident_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No investigation found for incident '{incident_id}'",
        )
    return _to_domain_result(record)


@router.get(
    "/api/v1/investigations/{investigation_id}",
    response_model=InvestigationResult,
)
def get_investigation_by_id(
    investigation_id: str, session: Session = Depends(get_session)
) -> InvestigationResult:
    """Retrieve an AI investigation result by its unique investigation ID."""
    inv_repo = InvestigationRepository(session)
    record = inv_repo.get_investigation(investigation_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    return _to_domain_result(record)
