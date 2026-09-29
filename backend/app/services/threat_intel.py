"""Threat Intelligence enrichment service.

Orchestrates IOC extraction, provider lookup, persistence, and audit logging
for incident-associated threat intelligence enrichment.

Security guarantees:
- Never modifies Incident severity.
- Never modifies ML risk score.
- Never modifies detection rule severity.
- Uses deterministic enrichment IDs for idempotency.
- Records bounded audit events without credentials.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
from uuid import uuid4

from ..models.threat_intel import IOC, ThreatIntelResult
from ..persistence.models import AuditEvent
from ..persistence.repositories import (
    EventRepository,
    IncidentRepository,
    ThreatIntelRepository,
)
from .ioc_extractor import IOCExtractor
from .threat_intel_provider import LocalDevThreatIntelProvider, ThreatIntelProvider

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ThreatIntelEnrichmentResult:
    """Result of enriching an incident with threat intelligence."""

    enrichments_created: list[str] = field(default_factory=list)
    enrichments_updated: list[str] = field(default_factory=list)
    iocs_extracted: int = 0


class ThreatIntelligenceService:
    """Manages threat-intelligence enrichment lifecycle for incidents.

    Responsibilities:
    1. Receive an Incident ID.
    2. Load incident and associated event data from persistence.
    3. Extract IOCs via IOCExtractor.
    4. Deduplicate IOCs.
    5. Query the configured provider for each IOC.
    6. Persist enrichment results.
    7. Generate deterministic enrichment IDs.
    8. Record audit events.
    9. Return structured result.

    Idempotent: repeated processing of the same Incident/IOC
    produces upserts on deterministic IDs, never uncontrolled duplicates.
    """

    def __init__(
        self,
        threat_intel_repository: ThreatIntelRepository,
        incident_repository: IncidentRepository,
        event_repository: EventRepository,
        provider: ThreatIntelProvider | None = None,
    ):
        self._ti_repo = threat_intel_repository
        self._incident_repo = incident_repository
        self._event_repo = event_repository
        self._provider = provider or LocalDevThreatIntelProvider()
        self._extractor = IOCExtractor()

    @staticmethod
    def generate_enrichment_id(incident_id: str, ioc_normalized: str) -> str:
        """Generate deterministic enrichment identifier."""
        digest = hashlib.sha256(
            f"ti:{incident_id}:{ioc_normalized}".encode()
        ).hexdigest()[:16]
        return f"ti-{digest}"

    def enrich_incident(self, incident_id: str) -> ThreatIntelEnrichmentResult:
        """Enrich a single incident with threat intelligence.

        CRITICAL: This method NEVER modifies incident severity or ML risk scores.
        """
        incident_record = self._incident_repo.get_incident(incident_id)
        if not incident_record:
            logger.warning("Incident not found for TI enrichment", extra={"incident_id": incident_id})
            return ThreatIntelEnrichmentResult()

        # Gather event data for IOC extraction
        event_data_list: list[dict] = []
        event_ids = json.loads(incident_record.event_ids_json) if incident_record.event_ids_json else []
        for eid in event_ids:
            ev_record = self._event_repo.get_event(eid)
            if ev_record:
                event_data_list.append({
                    "source_ip": ev_record.source_ip,
                    "destination_ip": ev_record.destination_ip,
                    "metadata": json.loads(ev_record.metadata_json) if ev_record.metadata_json else {},
                })

        # Gather incident evidence
        incident_evidence = (
            json.loads(incident_record.evidence_json)
            if incident_record.evidence_json
            else {}
        )

        # Extract IOCs
        iocs = self._extractor.extract_from_incident(
            incident_evidence=incident_evidence,
            event_data=event_data_list,
            source_context=f"incident:{incident_id}",
            timestamp=datetime.now(timezone.utc),
        )

        if not iocs:
            return ThreatIntelEnrichmentResult(iocs_extracted=0)

        # Enrich each IOC through the provider
        created: list[str] = []
        updated: list[str] = []

        for ioc in iocs:
            enrichment_id = self.generate_enrichment_id(incident_id, ioc.normalized_value)
            result = self._provider.lookup(
                ioc,
                incident_id=incident_id,
                enrichment_id=enrichment_id,
            )

            # Persist enrichment (upsert on deterministic ID)
            write_result = self._ti_repo.save_enrichment(result)
            now = datetime.now(timezone.utc)

            if write_result.created:
                created.append(enrichment_id)
                action = "threat_intelligence.enrichment_created"
            else:
                updated.append(enrichment_id)
                action = "threat_intelligence.enrichment_updated"

            # Audit event — bounded safe data only
            self._event_repo.create_audit_event(
                AuditEvent(
                    audit_id=f"audit-{uuid4()}",
                    timestamp=now,
                    actor="system",
                    action=action,
                    target=enrichment_id,
                    result="accepted",
                    metadata_json=json.dumps(
                        {
                            "enrichment_id": enrichment_id,
                            "incident_id": incident_id,
                            "ioc_type": ioc.ioc_type.value,
                            "classification": result.classification.value,
                            "provider": result.provider,
                        },
                        sort_keys=True,
                    ),
                )
            )

        return ThreatIntelEnrichmentResult(
            enrichments_created=sorted(list(set(created))),
            enrichments_updated=sorted(list(set(updated))),
            iocs_extracted=len(iocs),
        )

    def enrich_incidents(
        self, incident_ids: Sequence[str]
    ) -> ThreatIntelEnrichmentResult:
        """Enrich multiple incidents and aggregate results."""
        all_created: list[str] = []
        all_updated: list[str] = []
        total_iocs = 0

        for inc_id in incident_ids:
            result = self.enrich_incident(inc_id)
            all_created.extend(result.enrichments_created)
            all_updated.extend(result.enrichments_updated)
            total_iocs += result.iocs_extracted

        return ThreatIntelEnrichmentResult(
            enrichments_created=sorted(list(set(all_created))),
            enrichments_updated=sorted(list(set(all_updated))),
            iocs_extracted=total_iocs,
        )
