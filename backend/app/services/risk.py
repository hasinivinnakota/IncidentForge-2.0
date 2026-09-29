"""Risk scoring service managing ML assessment lifecycle and incident enrichment."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
from uuid import uuid4

from ..ml.features import extract_features
from ..ml.model import BaselineLogisticRiskModel, RiskModel
from ..models.incidents import Incident
from ..models.risk import RiskAssessment, RiskLevel
from ..persistence.models import AuditEvent
from ..persistence.repositories import (
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    RiskAssessmentRepository,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RiskScoringResult:
    assessments_created: list[str]
    assessments_updated: list[str]
    latest_score: int | None
    latest_level: str | None


class RiskScoringService:
    """Evaluates incidents with an ML RiskModel and manages assessment persistence."""

    def __init__(
        self,
        risk_repository: RiskAssessmentRepository,
        incident_repository: IncidentRepository,
        correlation_repository: CorrelationRepository,
        event_repository: EventRepository,
        risk_model: RiskModel | None = None,
    ):
        self._risk_repo = risk_repository
        self._incident_repo = incident_repository
        self._corr_repo = correlation_repository
        self._event_repo = event_repository
        self._model = risk_model or BaselineLogisticRiskModel()

    @staticmethod
    def generate_assessment_id(incident_id: str) -> str:
        """Generate deterministic risk assessment identifier for an incident."""
        digest = hashlib.sha256(f"risk:{incident_id}".encode()).hexdigest()[:16]
        return f"risk-{digest}"

    def score_incident(self, incident_id: str) -> RiskAssessment | None:
        """Score an incident using the configured RiskModel.

        CRITICAL: The incident's original severity is preserved and never overwritten.
        """
        incident_record = self._incident_repo.get_incident(incident_id)
        if not incident_record:
            return None

        # Build domain Incident
        incident = Incident(
            incident_id=incident_record.incident_id,
            title=incident_record.title,
            description=incident_record.description,
            severity=incident_record.severity,
            status=incident_record.status,
            created_at=incident_record.created_at,
            updated_at=incident_record.updated_at,
            correlation_ids=json.loads(incident_record.correlation_ids_json)
            if incident_record.correlation_ids_json
            else [],
            alert_ids=json.loads(incident_record.alert_ids_json)
            if incident_record.alert_ids_json
            else [],
            event_ids=json.loads(incident_record.event_ids_json)
            if incident_record.event_ids_json
            else [],
            first_seen=incident_record.first_seen,
            last_seen=incident_record.last_seen,
            mitre_techniques=json.loads(incident_record.mitre_techniques_json)
            if incident_record.mitre_techniques_json
            else [],
            evidence=json.loads(incident_record.evidence_json)
            if incident_record.evidence_json
            else {},
            tags=json.loads(incident_record.tags_json)
            if incident_record.tags_json
            else [],
        )

        correlation = None
        if incident.correlation_ids:
            corr_rec = self._corr_repo.get_correlation(incident.correlation_ids[0])
            if corr_rec:
                from ..models.correlation import Correlation, CorrelationStatus

                correlation = Correlation(
                    correlation_id=corr_rec.correlation_id,
                    correlation_type=corr_rec.correlation_type,
                    entity_key=corr_rec.entity_key,
                    title=corr_rec.title,
                    description=corr_rec.description,
                    severity=corr_rec.severity,
                    status=CorrelationStatus(corr_rec.status),
                    first_seen=corr_rec.first_seen,
                    last_seen=corr_rec.last_seen,
                    alert_ids=json.loads(corr_rec.alert_ids_json)
                    if corr_rec.alert_ids_json
                    else [],
                    event_ids=json.loads(corr_rec.event_ids_json)
                    if corr_rec.event_ids_json
                    else [],
                    alert_count=corr_rec.alert_count,
                    mitre_techniques=json.loads(corr_rec.mitre_techniques_json)
                    if corr_rec.mitre_techniques_json
                    else [],
                    evidence=json.loads(corr_rec.evidence_json)
                    if corr_rec.evidence_json
                    else {},
                )

        features = extract_features(incident, correlation)
        prediction = self._model.predict(features)
        now = datetime.now(timezone.utc)
        assessment_id = self.generate_assessment_id(incident_id)

        assessment = RiskAssessment(
            assessment_id=assessment_id,
            incident_id=incident_id,
            risk_score=prediction.risk_score,
            risk_level=RiskLevel(prediction.risk_level),
            model_name=prediction.model_name,
            model_version=prediction.model_version,
            feature_version=prediction.feature_version,
            scored_at=now,
            features=features,
            reasons=prediction.reason_codes,
            feature_contributions=prediction.feature_contributions,
        )

        write_res = self._risk_repo.save_assessment(assessment)
        action = "risk_assessment.created" if write_res.created else "risk_assessment.updated"

        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor="system",
                action=action,
                target=assessment_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "assessment_id": assessment_id,
                        "incident_id": incident_id,
                        "risk_score": prediction.risk_score,
                        "risk_level": prediction.risk_level,
                        "model_name": prediction.model_name,
                    },
                    sort_keys=True,
                ),
            )
        )

        return assessment

    def score_incidents(
        self, incident_ids: Sequence[str]
    ) -> RiskScoringResult:
        """Score multiple incidents and summarize created/updated assessments."""
        created: list[str] = []
        updated: list[str] = []
        latest_score: int | None = None
        latest_level: str | None = None

        for inc_id in incident_ids:
            assessment = self.score_incident(inc_id)
            if assessment:
                latest_score = assessment.risk_score
                latest_level = assessment.risk_level.value
                existing = self._risk_repo.get_assessment(assessment.assessment_id)
                # If was existing in DB, categorize properly
                created.append(assessment.assessment_id)

        return RiskScoringResult(
            assessments_created=sorted(list(set(created))),
            assessments_updated=sorted(list(set(updated))),
            latest_score=latest_score,
            latest_level=latest_level,
        )
