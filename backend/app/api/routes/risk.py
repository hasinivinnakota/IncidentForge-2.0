"""Risk assessment API endpoints."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from ...database import get_session
from ...models.risk import RiskAssessment, RiskLevel
from ...persistence.models import RiskAssessment as PersistenceRiskAssessment
from ...persistence.repositories import RiskAssessmentRepository

router = APIRouter(tags=["risk"])
logger = logging.getLogger(__name__)


def _to_domain_assessment(record: PersistenceRiskAssessment) -> RiskAssessment:
    return RiskAssessment(
        assessment_id=record.assessment_id,
        incident_id=record.incident_id,
        risk_score=record.risk_score,
        risk_level=RiskLevel(record.risk_level),
        model_name=record.model_name,
        model_version=record.model_version,
        feature_version=record.feature_version,
        scored_at=record.scored_at,
        features=json.loads(record.features_json) if record.features_json else {},
        reasons=json.loads(record.reasons_json) if record.reasons_json else [],
        feature_contributions=json.loads(record.feature_contributions_json)
        if record.feature_contributions_json
        else {},
    )


@router.get("/api/v1/incidents/{incident_id}/risk", response_model=RiskAssessment)
def get_incident_risk(
    incident_id: str, session: Session = Depends(get_session)
) -> RiskAssessment:
    """Retrieve the latest ML risk assessment for an incident."""
    repository = RiskAssessmentRepository(session)
    record = repository.get_latest_for_incident(incident_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment for incident {incident_id} not found",
        )
    return _to_domain_assessment(record)


@router.get("/api/v1/risk-assessments/{assessment_id}", response_model=RiskAssessment)
def get_risk_assessment_by_id(
    assessment_id: str, session: Session = Depends(get_session)
) -> RiskAssessment:
    """Retrieve a risk assessment by its unique assessment ID."""
    repository = RiskAssessmentRepository(session)
    record = repository.get_assessment(assessment_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment {assessment_id} not found",
        )
    return _to_domain_assessment(record)
