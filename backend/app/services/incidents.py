"""Incident creation and lifecycle service."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
from uuid import uuid4

from ..models.correlation import Correlation, CorrelationStatus
from ..models.incidents import Incident, IncidentStatus
from ..persistence.models import AuditEvent, Correlation as PersistenceCorrelation
from ..persistence.repositories import (
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IncidentProcessResult:
    incidents_created: list[str]
    incidents_updated: list[str]


class IncidentService:
    """Manages creation, enrichment, and status lifecycle of Incident records."""

    def __init__(
        self,
        incident_repository: IncidentRepository,
        correlation_repository: CorrelationRepository,
        event_repository: EventRepository,
    ):
        self._incident_repo = incident_repository
        self._correlation_repo = correlation_repository
        self._event_repo = event_repository

    @staticmethod
    def generate_incident_id(correlation_id: str) -> str:
        """Generate a deterministic incident identifier from correlation identity."""
        digest = hashlib.sha256(f"incident:{correlation_id}".encode()).hexdigest()[:16]
        return f"inc-{digest}"

    @staticmethod
    def generate_description(correlation: Correlation | PersistenceCorrelation) -> str:
        """Generate a concise deterministic summary from structured correlation attributes."""
        mitre_list = (
            correlation.mitre_techniques
            if isinstance(correlation, Correlation)
            else json.loads(correlation.mitre_techniques_json)
        )
        mitre_str = ", ".join(mitre_list) if mitre_list else "None"
        first_iso = (
            correlation.first_seen.isoformat() if correlation.first_seen else "unknown"
        )
        last_iso = (
            correlation.last_seen.isoformat() if correlation.last_seen else "unknown"
        )
        return (
            f"Correlated security incident ({correlation.correlation_type}) affecting "
            f"{correlation.entity_key}. Encompasses {correlation.alert_count} alert(s) "
            f"observed between {first_iso} and {last_iso}. "
            f"MITRE ATT&CK techniques: {mitre_str}. "
            f"Initial severity: {correlation.severity}/15."
        )

    def process_correlations(
        self, correlation_ids: Sequence[str]
    ) -> IncidentProcessResult:
        """Create or update incidents for each affected correlation."""
        created_ids: list[str] = []
        updated_ids: list[str] = []

        for corr_id in correlation_ids:
            corr_record = self._correlation_repo.get_correlation(corr_id)
            if not corr_record:
                continue

            existing_incident = self._incident_repo.find_by_correlation_id(corr_id)
            now = datetime.now(timezone.utc)

            alert_ids = json.loads(corr_record.alert_ids_json)
            event_ids = json.loads(corr_record.event_ids_json)
            mitre = json.loads(corr_record.mitre_techniques_json)

            if existing_incident is not None:
                # Update existing incident with latest correlation state
                existing_alerts = json.loads(existing_incident.alert_ids_json)
                existing_events = json.loads(existing_incident.event_ids_json)
                existing_mitre = json.loads(existing_incident.mitre_techniques_json)

                new_alerts = sorted(list(set(existing_alerts) | set(alert_ids)))
                new_events = sorted(list(set(existing_events) | set(event_ids)))
                new_mitre = sorted(list(set(existing_mitre) | set(mitre)))

                updated_domain = Incident(
                    incident_id=existing_incident.incident_id,
                    title=f"Security Incident: {corr_record.title}",
                    description=self.generate_description(corr_record),
                    severity=max(0, min(15, corr_record.severity)),
                    status=IncidentStatus(existing_incident.status),
                    created_at=existing_incident.created_at,
                    updated_at=now,
                    correlation_ids=[corr_id],
                    alert_ids=new_alerts,
                    event_ids=new_events,
                    first_seen=min(
                        [
                            ts
                            for ts in (existing_incident.first_seen, corr_record.first_seen)
                            if ts is not None
                        ],
                        default=now,
                    ),
                    last_seen=max(
                        [
                            ts
                            for ts in (existing_incident.last_seen, corr_record.last_seen)
                            if ts is not None
                        ],
                        default=now,
                    ),
                    mitre_techniques=new_mitre,
                    evidence={
                        "correlation_type": corr_record.correlation_type,
                        "entity_key": corr_record.entity_key,
                        "alert_count": len(new_alerts),
                    },
                    tags=[corr_record.correlation_type, corr_record.entity_key],
                )
                self._incident_repo.update_incident(updated_domain)
                self._event_repo.create_audit_event(
                    AuditEvent(
                        audit_id=f"audit-{uuid4()}",
                        timestamp=now,
                        actor="system",
                        action="incident.updated",
                        target=existing_incident.incident_id,
                        result="accepted",
                        metadata_json=json.dumps(
                            {
                                "incident_id": existing_incident.incident_id,
                                "correlation_id": corr_id,
                                "alert_count": len(new_alerts),
                            },
                            sort_keys=True,
                        ),
                    )
                )
                updated_ids.append(existing_incident.incident_id)
            else:
                # Create new incident
                incident_id = self.generate_incident_id(corr_id)
                new_incident = Incident(
                    incident_id=incident_id,
                    title=f"Security Incident: {corr_record.title}",
                    description=self.generate_description(corr_record),
                    severity=max(0, min(15, corr_record.severity)),
                    status=IncidentStatus.OPEN,
                    created_at=now,
                    updated_at=now,
                    correlation_ids=[corr_id],
                    alert_ids=alert_ids,
                    event_ids=event_ids,
                    first_seen=corr_record.first_seen,
                    last_seen=corr_record.last_seen,
                    mitre_techniques=mitre,
                    evidence={
                        "correlation_type": corr_record.correlation_type,
                        "entity_key": corr_record.entity_key,
                        "alert_count": len(alert_ids),
                    },
                    tags=[corr_record.correlation_type, corr_record.entity_key],
                )
                write_result = self._incident_repo.create_incident(new_incident)
                outcome = "created" if write_result.created else "duplicate"

                self._event_repo.create_audit_event(
                    AuditEvent(
                        audit_id=f"audit-{uuid4()}",
                        timestamp=now,
                        actor="system",
                        action=f"incident.{outcome}",
                        target=incident_id,
                        result="accepted",
                        metadata_json=json.dumps(
                            {
                                "incident_id": incident_id,
                                "correlation_id": corr_id,
                                "outcome": outcome,
                            },
                            sort_keys=True,
                        ),
                    )
                )

                if write_result.created:
                    created_ids.append(incident_id)
                    logger.info(
                        "Incident created",
                        extra={"incident_id": incident_id, "correlation_id": corr_id},
                    )

        return IncidentProcessResult(
            incidents_created=sorted(list(set(created_ids))),
            incidents_updated=sorted(list(set(updated_ids))),
        )

    def update_incident_status(
        self, incident_id: str, new_status: IncidentStatus, actor: str = "analyst"
    ) -> Incident | None:
        """Update incident status and record audit trail."""
        record = self._incident_repo.update_incident_status(
            incident_id=incident_id, new_status=new_status.value
        )
        if record is None:
            return None

        now = datetime.now(timezone.utc)
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor=actor,
                action="incident.status_updated",
                target=incident_id,
                result="accepted",
                metadata_json=json.dumps(
                    {"incident_id": incident_id, "new_status": new_status.value},
                    sort_keys=True,
                ),
            )
        )

        return Incident(
            incident_id=record.incident_id,
            title=record.title,
            description=record.description,
            severity=record.severity,
            status=IncidentStatus(record.status),
            created_at=record.created_at,
            updated_at=record.updated_at,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            correlation_ids=json.loads(record.correlation_ids_json)
            if record.correlation_ids_json
            else [],
            alert_ids=json.loads(record.alert_ids_json) if record.alert_ids_json else [],
            event_ids=json.loads(record.event_ids_json) if record.event_ids_json else [],
            mitre_techniques=json.loads(record.mitre_techniques_json)
            if record.mitre_techniques_json
            else [],
            evidence=json.loads(record.evidence_json) if record.evidence_json else {},
            tags=json.loads(record.tags_json) if record.tags_json else [],
        )
