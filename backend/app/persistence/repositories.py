from datetime import datetime, timezone
import json
from collections.abc import Sequence
from dataclasses import dataclass

from sqlmodel import Session, select

from ..models.alerts import Alert as DomainAlert
from ..models.cases import (
    Case as DomainCase,
    CaseNote as DomainCaseNote,
    EvidenceReference as DomainEvidenceReference,
)
from ..models.correlation import Correlation as DomainCorrelation
from ..models.events import NormalizedEvent
from ..models.incidents import Incident as DomainIncident
from ..models.investigation import InvestigationResult as DomainInvestigationResult
from ..models.response import ResponseAction as DomainResponseAction
from ..models.risk import RiskAssessment as DomainRiskAssessment
from ..models.threat_intel import ThreatIntelResult as DomainThreatIntelResult
from .models import (
    Alert as PersistenceAlert,
    AuditEvent,
    Case as PersistenceCase,
    CaseNoteRecord as PersistenceCaseNoteRecord,
    Correlation as PersistenceCorrelation,
    Event,
    EvidenceReferenceRecord as PersistenceEvidenceReferenceRecord,
    Incident as PersistenceIncident,
    Investigation as PersistenceInvestigation,
    ResponseAction as PersistenceResponseAction,
    RiskAssessment as PersistenceRiskAssessment,
    ThreatIntelEnrichment as PersistenceThreatIntelEnrichment,
)


@dataclass(frozen=True)
class EventWriteResult:
    event: Event
    created: bool


class EventRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_event(self, event: NormalizedEvent) -> EventWriteResult:
        """Store an event, returning the existing row for duplicate event IDs."""
        existing = self.get_event(event.event_id)
        if existing is not None:
            return EventWriteResult(event=existing, created=False)

        record = Event(
            event_id=event.event_id,
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            severity=event.severity,
            message=event.message,
            host=event.host,
            user=event.user,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            metadata_json=json.dumps(event.metadata, sort_keys=True, default=str),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return EventWriteResult(event=record, created=True)

    def get_event(self, event_id: str) -> Event | None:
        return self.session.exec(select(Event).where(Event.event_id == event_id)).first()

    def list_recent_events(self, limit: int = 100) -> Sequence[Event]:
        return self.session.exec(select(Event).order_by(Event.created_at.desc()).limit(limit)).all()

    def create_audit_event(self, audit: AuditEvent) -> AuditEvent:
        existing = self.session.exec(select(AuditEvent).where(AuditEvent.audit_id == audit.audit_id)).first()
        if existing is not None:
            return existing
        self.session.add(audit)
        self.session.commit()
        self.session.refresh(audit)
        return audit

    def list_audit_events(self, target: str | None = None) -> Sequence[AuditEvent]:
        statement = select(AuditEvent).order_by(AuditEvent.timestamp.asc())
        if target is not None:
            statement = statement.where(AuditEvent.target == target)
        return self.session.exec(statement).all()


@dataclass(frozen=True)
class AlertWriteResult:
    alert: PersistenceAlert
    created: bool


class AlertRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_alert(self, alert: DomainAlert) -> AlertWriteResult:
        """Store an alert, returning the existing row for duplicate alert IDs."""
        existing = self.get_alert(alert.alert_id)
        if existing is not None:
            return AlertWriteResult(alert=existing, created=False)

        status_val = alert.status.value if hasattr(alert.status, "value") else str(alert.status)
        record = PersistenceAlert(
            alert_id=alert.alert_id,
            event_id=alert.event_id,
            timestamp=alert.timestamp,
            rule_id=alert.rule_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            description=alert.description,
            source=alert.source,
            evidence_json=json.dumps(alert.evidence, sort_keys=True, default=str),
            mitre_techniques_json=json.dumps(alert.mitre_techniques, sort_keys=True),
            status=status_val,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return AlertWriteResult(alert=record, created=True)

    def get_alert(self, alert_id: str) -> PersistenceAlert | None:
        return self.session.exec(select(PersistenceAlert).where(PersistenceAlert.alert_id == alert_id)).first()

    def list_alerts(self, limit: int = 100) -> Sequence[PersistenceAlert]:
        return self.session.exec(select(PersistenceAlert).order_by(PersistenceAlert.created_at.desc()).limit(limit)).all()

    def list_alerts_by_event(self, event_id: str) -> Sequence[PersistenceAlert]:
        return self.session.exec(
            select(PersistenceAlert).where(PersistenceAlert.event_id == event_id).order_by(PersistenceAlert.created_at.desc())
        ).all()

    def list_recent_alerts(self, since: datetime | None = None, limit: int = 100) -> Sequence[PersistenceAlert]:
        statement = select(PersistenceAlert)
        if since is not None:
            statement = statement.where(PersistenceAlert.timestamp >= since)
        return self.session.exec(statement.order_by(PersistenceAlert.timestamp.desc()).limit(limit)).all()


@dataclass(frozen=True)
class CorrelationWriteResult:
    correlation: PersistenceCorrelation
    created: bool


class CorrelationRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_correlation(self, correlation: DomainCorrelation) -> CorrelationWriteResult:
        existing = self.get_correlation(correlation.correlation_id)
        if existing is not None:
            return CorrelationWriteResult(correlation=existing, created=False)

        status_val = correlation.status.value if hasattr(correlation.status, "value") else str(correlation.status)
        record = PersistenceCorrelation(
            correlation_id=correlation.correlation_id,
            correlation_type=correlation.correlation_type,
            entity_key=correlation.entity_key,
            title=correlation.title,
            description=correlation.description,
            severity=correlation.severity,
            status=status_val,
            first_seen=correlation.first_seen,
            last_seen=correlation.last_seen,
            alert_ids_json=json.dumps(correlation.alert_ids, sort_keys=True),
            event_ids_json=json.dumps(correlation.event_ids, sort_keys=True),
            alert_count=correlation.alert_count,
            mitre_techniques_json=json.dumps(correlation.mitre_techniques, sort_keys=True),
            evidence_json=json.dumps(correlation.evidence, sort_keys=True, default=str),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return CorrelationWriteResult(correlation=record, created=True)

    def update_correlation(self, correlation: DomainCorrelation) -> PersistenceCorrelation | None:
        record = self.get_correlation(correlation.correlation_id)
        if record is None:
            return None

        status_val = correlation.status.value if hasattr(correlation.status, "value") else str(correlation.status)
        record.title = correlation.title
        record.description = correlation.description
        record.severity = correlation.severity
        record.status = status_val
        record.last_seen = correlation.last_seen
        record.alert_ids_json = json.dumps(correlation.alert_ids, sort_keys=True)
        record.event_ids_json = json.dumps(correlation.event_ids, sort_keys=True)
        record.alert_count = correlation.alert_count
        record.mitre_techniques_json = json.dumps(correlation.mitre_techniques, sort_keys=True)
        record.evidence_json = json.dumps(correlation.evidence, sort_keys=True, default=str)
        record.updated_at = datetime.now(timezone.utc)

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_correlation(self, correlation_id: str) -> PersistenceCorrelation | None:
        return self.session.exec(
            select(PersistenceCorrelation).where(PersistenceCorrelation.correlation_id == correlation_id)
        ).first()

    def find_open_correlation(
        self, correlation_type: str, entity_key: str, since: datetime | None = None
    ) -> PersistenceCorrelation | None:
        stmt = select(PersistenceCorrelation).where(
            PersistenceCorrelation.status == "open",
            PersistenceCorrelation.correlation_type == correlation_type,
            PersistenceCorrelation.entity_key == entity_key,
        )
        if since is not None:
            stmt = stmt.where(PersistenceCorrelation.last_seen >= since)
        return self.session.exec(stmt.order_by(PersistenceCorrelation.last_seen.desc())).first()

    def list_correlations(
        self,
        status: str | None = None,
        alert_id: str | None = None,
        event_id: str | None = None,
        limit: int = 100,
    ) -> Sequence[PersistenceCorrelation]:
        stmt = select(PersistenceCorrelation)
        if status is not None:
            stmt = stmt.where(PersistenceCorrelation.status == status)
        if alert_id is not None:
            stmt = stmt.where(PersistenceCorrelation.alert_ids_json.contains(f'"{alert_id}"'))
        if event_id is not None:
            stmt = stmt.where(PersistenceCorrelation.event_ids_json.contains(f'"{event_id}"'))
        return self.session.exec(stmt.order_by(PersistenceCorrelation.updated_at.desc()).limit(limit)).all()


@dataclass(frozen=True)
class IncidentWriteResult:
    incident: PersistenceIncident
    created: bool


class IncidentRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_incident(self, incident: DomainIncident) -> IncidentWriteResult:
        existing = self.get_incident(incident.incident_id)
        if existing is not None:
            return IncidentWriteResult(incident=existing, created=False)

        status_val = (
            incident.status.value
            if hasattr(incident.status, "value")
            else str(incident.status)
        )
        record = PersistenceIncident(
            incident_id=incident.incident_id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=status_val,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            correlation_ids_json=json.dumps(incident.correlation_ids, sort_keys=True),
            alert_ids_json=json.dumps(incident.alert_ids, sort_keys=True),
            event_ids_json=json.dumps(incident.event_ids, sort_keys=True),
            mitre_techniques_json=json.dumps(incident.mitre_techniques, sort_keys=True),
            evidence_json=json.dumps(incident.evidence, sort_keys=True, default=str),
            tags_json=json.dumps(incident.tags, sort_keys=True),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return IncidentWriteResult(incident=record, created=True)

    def update_incident(self, incident: DomainIncident) -> PersistenceIncident | None:
        record = self.get_incident(incident.incident_id)
        if record is None:
            return None

        status_val = (
            incident.status.value
            if hasattr(incident.status, "value")
            else str(incident.status)
        )
        record.title = incident.title
        record.description = incident.description
        record.severity = incident.severity
        record.status = status_val
        record.updated_at = incident.updated_at
        record.first_seen = incident.first_seen
        record.last_seen = incident.last_seen
        record.correlation_ids_json = json.dumps(incident.correlation_ids, sort_keys=True)
        record.alert_ids_json = json.dumps(incident.alert_ids, sort_keys=True)
        record.event_ids_json = json.dumps(incident.event_ids, sort_keys=True)
        record.mitre_techniques_json = json.dumps(incident.mitre_techniques, sort_keys=True)
        record.evidence_json = json.dumps(incident.evidence, sort_keys=True, default=str)
        record.tags_json = json.dumps(incident.tags, sort_keys=True)

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def update_incident_status(
        self, incident_id: str, new_status: str
    ) -> PersistenceIncident | None:
        record = self.get_incident(incident_id)
        if record is None:
            return None
        record.status = new_status
        record.updated_at = datetime.now(timezone.utc)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_incident(self, incident_id: str) -> PersistenceIncident | None:
        return self.session.exec(
            select(PersistenceIncident).where(PersistenceIncident.incident_id == incident_id)
        ).first()

    def find_by_correlation_id(self, correlation_id: str) -> PersistenceIncident | None:
        return self.session.exec(
            select(PersistenceIncident).where(
                PersistenceIncident.correlation_ids_json.contains(f'"{correlation_id}"')
            )
        ).first()

    def list_incidents(
        self,
        status: str | None = None,
        correlation_id: str | None = None,
        min_severity: int | None = None,
        limit: int = 100,
    ) -> Sequence[PersistenceIncident]:
        stmt = select(PersistenceIncident)
        if status is not None:
            stmt = stmt.where(PersistenceIncident.status == status)
        if correlation_id is not None:
            stmt = stmt.where(
                PersistenceIncident.correlation_ids_json.contains(f'"{correlation_id}"')
            )
        if min_severity is not None:
            stmt = stmt.where(PersistenceIncident.severity >= min_severity)
        return self.session.exec(stmt.order_by(PersistenceIncident.updated_at.desc()).limit(limit)).all()


@dataclass(frozen=True)
class RiskAssessmentWriteResult:
    assessment: PersistenceRiskAssessment
    created: bool


class RiskAssessmentRepository:
    def __init__(self, session: Session):
        self.session = session

    def save_assessment(
        self, assessment: DomainRiskAssessment
    ) -> RiskAssessmentWriteResult:
        existing = self.get_assessment(assessment.assessment_id)
        risk_val = (
            assessment.risk_level.value
            if hasattr(assessment.risk_level, "value")
            else str(assessment.risk_level)
        )
        if existing is not None:
            existing.risk_score = assessment.risk_score
            existing.risk_level = risk_val
            existing.model_name = assessment.model_name
            existing.model_version = assessment.model_version
            existing.feature_version = assessment.feature_version
            existing.scored_at = assessment.scored_at
            existing.features_json = json.dumps(assessment.features, sort_keys=True)
            existing.reasons_json = json.dumps(assessment.reasons, sort_keys=True)
            existing.feature_contributions_json = json.dumps(
                assessment.feature_contributions, sort_keys=True
            )
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return RiskAssessmentWriteResult(assessment=existing, created=False)

        record = PersistenceRiskAssessment(
            assessment_id=assessment.assessment_id,
            incident_id=assessment.incident_id,
            risk_score=assessment.risk_score,
            risk_level=risk_val,
            model_name=assessment.model_name,
            model_version=assessment.model_version,
            feature_version=assessment.feature_version,
            scored_at=assessment.scored_at,
            features_json=json.dumps(assessment.features, sort_keys=True),
            reasons_json=json.dumps(assessment.reasons, sort_keys=True),
            feature_contributions_json=json.dumps(
                assessment.feature_contributions, sort_keys=True
            ),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return RiskAssessmentWriteResult(assessment=record, created=True)

    def get_assessment(self, assessment_id: str) -> PersistenceRiskAssessment | None:
        return self.session.exec(
            select(PersistenceRiskAssessment).where(
                PersistenceRiskAssessment.assessment_id == assessment_id
            )
        ).first()

    def get_latest_for_incident(
        self, incident_id: str
    ) -> PersistenceRiskAssessment | None:
        return self.session.exec(
            select(PersistenceRiskAssessment)
            .where(PersistenceRiskAssessment.incident_id == incident_id)
            .order_by(PersistenceRiskAssessment.scored_at.desc())
        ).first()

    def list_assessments(
        self,
        incident_id: str | None = None,
        risk_level: str | None = None,
        limit: int = 100,
    ) -> Sequence[PersistenceRiskAssessment]:
        stmt = select(PersistenceRiskAssessment)
        if incident_id is not None:
            stmt = stmt.where(PersistenceRiskAssessment.incident_id == incident_id)
        if risk_level is not None:
            stmt = stmt.where(PersistenceRiskAssessment.risk_level == risk_level)
        return self.session.exec(
            stmt.order_by(PersistenceRiskAssessment.scored_at.desc()).limit(limit)
        ).all()


@dataclass(frozen=True)
class ThreatIntelWriteResult:
    enrichment: PersistenceThreatIntelEnrichment
    created: bool


class ThreatIntelRepository:
    def __init__(self, session: Session):
        self.session = session

    def save_enrichment(
        self, result: DomainThreatIntelResult
    ) -> ThreatIntelWriteResult:
        """Persist or update a threat intelligence enrichment result."""
        existing = self.get_enrichment(result.enrichment_id)
        classification_val = (
            result.classification.value
            if hasattr(result.classification, "value")
            else str(result.classification)
        )
        ioc_type_val = (
            result.ioc_type.value
            if hasattr(result.ioc_type, "value")
            else str(result.ioc_type)
        )
        if existing is not None:
            existing.classification = classification_val
            existing.confidence = result.confidence
            existing.reputation = result.reputation
            existing.threat_category = result.threat_category
            existing.provider = result.provider
            existing.source_count = result.source_count
            existing.first_seen = result.first_seen
            existing.last_seen = result.last_seen
            existing.tags_json = json.dumps(result.tags, sort_keys=True)
            existing.explanation = result.explanation
            existing.lookup_timestamp = result.lookup_timestamp
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return ThreatIntelWriteResult(enrichment=existing, created=False)

        record = PersistenceThreatIntelEnrichment(
            enrichment_id=result.enrichment_id,
            incident_id=result.incident_id,
            ioc_type=ioc_type_val,
            ioc_value=result.ioc_value,
            classification=classification_val,
            confidence=result.confidence,
            reputation=result.reputation,
            threat_category=result.threat_category,
            provider=result.provider,
            source_count=result.source_count,
            first_seen=result.first_seen,
            last_seen=result.last_seen,
            tags_json=json.dumps(result.tags, sort_keys=True),
            explanation=result.explanation,
            lookup_timestamp=result.lookup_timestamp,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return ThreatIntelWriteResult(enrichment=record, created=True)

    def get_enrichment(self, enrichment_id: str) -> PersistenceThreatIntelEnrichment | None:
        return self.session.exec(
            select(PersistenceThreatIntelEnrichment).where(
                PersistenceThreatIntelEnrichment.enrichment_id == enrichment_id
            )
        ).first()

    def list_by_incident(
        self, incident_id: str, limit: int = 100
    ) -> Sequence[PersistenceThreatIntelEnrichment]:
        return self.session.exec(
            select(PersistenceThreatIntelEnrichment)
            .where(PersistenceThreatIntelEnrichment.incident_id == incident_id)
            .order_by(PersistenceThreatIntelEnrichment.created_at.desc())
            .limit(limit)
        ).all()

    def find_by_ioc(
        self, ioc_type: str, ioc_value: str, limit: int = 100
    ) -> Sequence[PersistenceThreatIntelEnrichment]:
        return self.session.exec(
            select(PersistenceThreatIntelEnrichment)
            .where(
                PersistenceThreatIntelEnrichment.ioc_type == ioc_type,
                PersistenceThreatIntelEnrichment.ioc_value == ioc_value,
            )
            .order_by(PersistenceThreatIntelEnrichment.created_at.desc())
            .limit(limit)
        ).all()


@dataclass(frozen=True)
class InvestigationWriteResult:
    investigation: PersistenceInvestigation
    created: bool


class InvestigationRepository:
    def __init__(self, session: Session):
        self.session = session

    def save_investigation(
        self, result: DomainInvestigationResult
    ) -> InvestigationWriteResult:
        """Persist or update an AI investigation result."""
        existing = self.get_investigation(result.investigation_id)
        if existing is not None:
            existing.summary = result.summary
            existing.confidence = result.confidence
            existing.findings_json = json.dumps(
                [f.model_dump(mode="json") for f in result.findings], sort_keys=True
            )
            existing.timeline_json = json.dumps(
                [t.model_dump(mode="json") for t in result.timeline], sort_keys=True
            )
            existing.mitre_techniques_json = json.dumps(
                result.mitre_techniques, sort_keys=True
            )
            existing.threat_intel_summary_json = json.dumps(
                result.threat_intel_summary, sort_keys=True
            )
            existing.investigation_gaps_json = json.dumps(
                result.investigation_gaps, sort_keys=True
            )
            existing.recommended_next_steps_json = json.dumps(
                result.recommended_next_steps, sort_keys=True
            )
            existing.possible_response_actions_json = json.dumps(
                [a.model_dump(mode="json") for a in result.possible_response_actions],
                sort_keys=True,
            )
            existing.provider = result.provider
            existing.model_name = result.model_name
            existing.generated_at = result.generated_at
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return InvestigationWriteResult(investigation=existing, created=False)

        record = PersistenceInvestigation(
            investigation_id=result.investigation_id,
            incident_id=result.incident_id,
            status="completed",
            summary=result.summary,
            confidence=result.confidence,
            findings_json=json.dumps(
                [f.model_dump(mode="json") for f in result.findings], sort_keys=True
            ),
            timeline_json=json.dumps(
                [t.model_dump(mode="json") for t in result.timeline], sort_keys=True
            ),
            mitre_techniques_json=json.dumps(result.mitre_techniques, sort_keys=True),
            threat_intel_summary_json=json.dumps(
                result.threat_intel_summary, sort_keys=True
            ),
            investigation_gaps_json=json.dumps(
                result.investigation_gaps, sort_keys=True
            ),
            recommended_next_steps_json=json.dumps(
                result.recommended_next_steps, sort_keys=True
            ),
            possible_response_actions_json=json.dumps(
                [a.model_dump(mode="json") for a in result.possible_response_actions],
                sort_keys=True,
            ),
            provider=result.provider,
            model_name=result.model_name,
            generated_at=result.generated_at,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return InvestigationWriteResult(investigation=record, created=True)

    def get_investigation(
        self, investigation_id: str
    ) -> PersistenceInvestigation | None:
        return self.session.exec(
            select(PersistenceInvestigation).where(
                PersistenceInvestigation.investigation_id == investigation_id
            )
        ).first()

    def get_latest_for_incident(
        self, incident_id: str
    ) -> PersistenceInvestigation | None:
        return self.session.exec(
            select(PersistenceInvestigation)
            .where(PersistenceInvestigation.incident_id == incident_id)
            .order_by(PersistenceInvestigation.generated_at.desc())
        ).first()

    def list_by_incident(
        self, incident_id: str, limit: int = 50
    ) -> Sequence[PersistenceInvestigation]:
        return self.session.exec(
            select(PersistenceInvestigation)
            .where(PersistenceInvestigation.incident_id == incident_id)
            .order_by(PersistenceInvestigation.generated_at.desc())
            .limit(limit)
        ).all()


@dataclass(frozen=True)
class CaseWriteResult:
    case: PersistenceCase
    created: bool


class CaseRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_case(self, case: DomainCase) -> CaseWriteResult:
        """Store a new case, returning the existing row if duplicate case_id."""
        existing = self.get_case(case.case_id)
        if existing is not None:
            return CaseWriteResult(case=existing, created=False)

        status_val = case.status.value if hasattr(case.status, "value") else str(case.status)
        priority_val = case.priority.value if hasattr(case.priority, "value") else str(case.priority)
        resolution_val = (
            json.dumps(case.resolution.model_dump(mode="json"), sort_keys=True)
            if case.resolution
            else None
        )

        record = PersistenceCase(
            case_id=case.case_id,
            title=case.title,
            description=case.description,
            severity=case.severity,
            priority=priority_val,
            status=status_val,
            assignee=case.assignee,
            created_at=case.created_at,
            updated_at=case.updated_at,
            first_seen=case.first_seen,
            last_seen=case.last_seen,
            incident_ids_json=json.dumps(case.incident_ids, sort_keys=True),
            investigation_ids_json=json.dumps(case.investigation_ids, sort_keys=True),
            tags_json=json.dumps(case.tags, sort_keys=True),
            resolution_json=resolution_val,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return CaseWriteResult(case=record, created=True)

    def update_case(self, case: DomainCase) -> PersistenceCase | None:
        """Update an existing case."""
        record = self.get_case(case.case_id)
        if record is None:
            return None

        status_val = case.status.value if hasattr(case.status, "value") else str(case.status)
        priority_val = case.priority.value if hasattr(case.priority, "value") else str(case.priority)
        resolution_val = (
            json.dumps(case.resolution.model_dump(mode="json"), sort_keys=True)
            if case.resolution
            else None
        )

        record.title = case.title
        record.description = case.description
        record.severity = case.severity
        record.priority = priority_val
        record.status = status_val
        record.assignee = case.assignee
        record.updated_at = datetime.now(timezone.utc)
        record.first_seen = case.first_seen
        record.last_seen = case.last_seen
        record.incident_ids_json = json.dumps(case.incident_ids, sort_keys=True)
        record.investigation_ids_json = json.dumps(case.investigation_ids, sort_keys=True)
        record.tags_json = json.dumps(case.tags, sort_keys=True)
        record.resolution_json = resolution_val

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_case(self, case_id: str) -> PersistenceCase | None:
        return self.session.exec(
            select(PersistenceCase).where(PersistenceCase.case_id == case_id)
        ).first()

    def list_cases(
        self,
        status: str | None = None,
        priority: str | None = None,
        assignee: str | None = None,
        limit: int = 100,
    ) -> Sequence[PersistenceCase]:
        stmt = select(PersistenceCase)
        if status is not None:
            stmt = stmt.where(PersistenceCase.status == status)
        if priority is not None:
            stmt = stmt.where(PersistenceCase.priority == priority)
        if assignee is not None:
            stmt = stmt.where(PersistenceCase.assignee == assignee)
        return self.session.exec(
            stmt.order_by(PersistenceCase.updated_at.desc()).limit(limit)
        ).all()

    # Note operations (normalized table)
    def add_note(self, note: DomainCaseNote) -> PersistenceCaseNoteRecord:
        record = PersistenceCaseNoteRecord(
            note_id=note.note_id,
            case_id=note.case_id,
            author=note.author,
            content=note.content,
            created_at=note.created_at,
            updated_at=note.updated_at,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_notes_by_case(
        self, case_id: str, limit: int = 100
    ) -> Sequence[PersistenceCaseNoteRecord]:
        return self.session.exec(
            select(PersistenceCaseNoteRecord)
            .where(PersistenceCaseNoteRecord.case_id == case_id)
            .order_by(PersistenceCaseNoteRecord.created_at.asc())
            .limit(limit)
        ).all()

    # Evidence Reference operations (normalized table)
    def add_evidence_reference(
        self, ref: DomainEvidenceReference
    ) -> PersistenceEvidenceReferenceRecord:
        """Add evidence reference or return existing if already linked."""
        evidence_type_val = (
            ref.evidence_type.value
            if hasattr(ref.evidence_type, "value")
            else str(ref.evidence_type)
        )
        existing = self.session.exec(
            select(PersistenceEvidenceReferenceRecord).where(
                PersistenceEvidenceReferenceRecord.case_id == ref.case_id,
                PersistenceEvidenceReferenceRecord.evidence_type == evidence_type_val,
                PersistenceEvidenceReferenceRecord.reference_key == ref.reference_key,
            )
        ).first()
        if existing is not None:
            return existing

        record = PersistenceEvidenceReferenceRecord(
            evidence_id=ref.evidence_id,
            case_id=ref.case_id,
            evidence_type=evidence_type_val,
            reference_key=ref.reference_key,
            description=ref.description,
            added_by=ref.added_by,
            added_at=ref.added_at,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_evidence_by_case(
        self, case_id: str, limit: int = 200
    ) -> Sequence[PersistenceEvidenceReferenceRecord]:
        return self.session.exec(
            select(PersistenceEvidenceReferenceRecord)
            .where(PersistenceEvidenceReferenceRecord.case_id == case_id)
            .order_by(PersistenceEvidenceReferenceRecord.added_at.asc())
            .limit(limit)
        ).all()


@dataclass(frozen=True)
class ResponseActionWriteResult:
    response_action: PersistenceResponseAction
    created: bool


class ResponseActionRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_response_action(self, action: DomainResponseAction) -> ResponseActionWriteResult:
        existing = self.get_response_action(action.action_id)
        if existing is not None:
            return ResponseActionWriteResult(response_action=existing, created=False)

        status_val = (
            action.status.value
            if hasattr(action.status, "value")
            else str(action.status)
        )
        record = PersistenceResponseAction(
            action_id=action.action_id,
            incident_id=action.incident_id,
            action_type=action.action_type,
            status=status_val,
            requested_at=action.requested_at,
            approved_by=action.approved_by,
            executed_at=action.executed_at,
            result=action.result,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return ResponseActionWriteResult(response_action=record, created=True)

    def get_response_action(self, action_id: str) -> PersistenceResponseAction | None:
        return self.session.exec(
            select(PersistenceResponseAction).where(
                PersistenceResponseAction.action_id == action_id
            )
        ).first()

    def update_response_action(
        self, action: DomainResponseAction
    ) -> PersistenceResponseAction | None:
        record = self.get_response_action(action.action_id)
        if record is None:
            return None

        status_val = (
            action.status.value
            if hasattr(action.status, "value")
            else str(action.status)
        )
        record.status = status_val
        record.approved_by = action.approved_by
        record.executed_at = action.executed_at
        record.result = action.result

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_response_actions(
        self,
        incident_id: str | None = None,
        limit: int = 100,
    ) -> Sequence[PersistenceResponseAction]:
        statement = select(PersistenceResponseAction)
        if incident_id is not None:
            statement = statement.where(PersistenceResponseAction.incident_id == incident_id)
        statement = statement.order_by(PersistenceResponseAction.requested_at.desc()).limit(limit)
        return self.session.exec(statement).all()


from ..models.dataset import DatasetAsset as DomainDatasetAsset
from ..models.dataset import DatasetActivity as DomainDatasetActivity
from .models import PersistenceDatasetAsset, PersistenceDatasetActivity
import json
from datetime import datetime, timezone

class DatasetRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_or_update_dataset(self, asset: DomainDatasetAsset) -> PersistenceDatasetAsset:
        existing = self.session.exec(
            select(PersistenceDatasetAsset).where(PersistenceDatasetAsset.dataset_id == asset.dataset_id)
        ).first()

        columns_json = json.dumps([c.model_dump(mode="json") for c in asset.columns])
        sensitive_cols_json = json.dumps(asset.sensitive_columns)
        metadata_json = json.dumps(asset.metadata)

        if existing:
            existing.name = asset.name
            existing.format = asset.format.value
            existing.file_path = asset.file_path
            existing.size_bytes = asset.size_bytes
            existing.record_count = asset.record_count
            existing.column_count = asset.column_count
            existing.columns_json = columns_json
            existing.sensitive_columns_json = sensitive_cols_json
            existing.sensitivity = asset.sensitivity.value
            existing.schema_hash = asset.schema_hash
            existing.updated_at = datetime.now(timezone.utc)
            existing.metadata_json = metadata_json
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        record = PersistenceDatasetAsset(
            dataset_id=asset.dataset_id,
            name=asset.name,
            format=asset.format.value,
            file_path=asset.file_path,
            size_bytes=asset.size_bytes,
            record_count=asset.record_count,
            column_count=asset.column_count,
            columns_json=columns_json,
            sensitive_columns_json=sensitive_cols_json,
            sensitivity=asset.sensitivity.value,
            schema_hash=asset.schema_hash,
            metadata_json=metadata_json,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_dataset(self, dataset_id: str) -> PersistenceDatasetAsset | None:
        return self.session.exec(
            select(PersistenceDatasetAsset).where(PersistenceDatasetAsset.dataset_id == dataset_id)
        ).first()

    def list_datasets(self, limit: int = 100) -> Sequence[PersistenceDatasetAsset]:
        return self.session.exec(
            select(PersistenceDatasetAsset).order_by(PersistenceDatasetAsset.updated_at.desc()).limit(limit)
        ).all()

    def record_activity(self, activity: DomainDatasetActivity) -> PersistenceDatasetActivity:
        record = PersistenceDatasetActivity(
            activity_id=activity.activity_id,
            timestamp=activity.timestamp,
            dataset_id=activity.dataset_id,
            dataset_name=activity.dataset_name,
            operation=activity.operation,
            actor=activity.actor,
            actor_host=activity.actor_host,
            source_ip=activity.source_ip,
            destination_ip=activity.destination_ip,
            records_accessed=activity.records_accessed,
            records_modified=activity.records_modified,
            sensitive_columns_json=json.dumps(activity.sensitive_columns) if activity.sensitive_columns else "[]",
            export_size_bytes=activity.export_size_bytes,
            export_destination=activity.export_destination,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_activities(
        self, dataset_id: str | None = None, actor: str | None = None, limit: int = 100
    ) -> Sequence[PersistenceDatasetActivity]:
        stmt = select(PersistenceDatasetActivity)
        if dataset_id:
            stmt = stmt.where(PersistenceDatasetActivity.dataset_id == dataset_id)
        if actor:
            stmt = stmt.where(PersistenceDatasetActivity.actor == actor)
        return self.session.exec(stmt.order_by(PersistenceDatasetActivity.timestamp.desc()).limit(limit)).all()
