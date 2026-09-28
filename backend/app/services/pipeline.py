"""Event processing pipeline orchestrator."""

import logging

from ..models.events import NormalizedEvent
from ..models.processing import PipelineResult
from .alerts import AlertService
from .correlation import CorrelationEngine
from .detection import DetectionEngine
from .incidents import IncidentService
from .processing import EventProcessingService
from .risk import RiskScoringService
from .threat_intel import ThreatIntelligenceService

logger = logging.getLogger(__name__)


class EventPipeline:
    """Composes event processing, detection, alerting, correlation, incident creation, ML risk scoring, and threat intelligence."""

    def __init__(
        self,
        processing_service: EventProcessingService,
        detection_engine: DetectionEngine,
        alert_service: AlertService,
        correlation_engine: CorrelationEngine | None = None,
        incident_service: IncidentService | None = None,
        risk_service: RiskScoringService | None = None,
        threat_intel_service: ThreatIntelligenceService | None = None,
    ):
        self._processing = processing_service
        self._detection = detection_engine
        self._alerts = alert_service
        self._correlation = correlation_engine
        self._incident = incident_service
        self._risk = risk_service
        self._threat_intel = threat_intel_service

    def ingest(self, event: NormalizedEvent) -> PipelineResult:
        # Step 1: Persist event + audit (Phase 5 behavior)
        processing_result = self._processing.process(event)

        alert_ids: list[str] = []
        match_count = 0
        correlations_created: list[str] = []
        correlations_updated: list[str] = []
        incidents_created: list[str] = []
        incidents_updated: list[str] = []
        risk_assessments_created: list[str] = []
        risk_assessments_updated: list[str] = []
        risk_score: int | None = None
        risk_level: str | None = None
        threat_intel_created: list[str] = []
        threat_intel_updated: list[str] = []
        iocs_extracted: int = 0

        # Step 2: Detection & alerting (only for newly persisted events)
        if processing_result.newly_persisted:
            matches = self._detection.evaluate(event)
            match_count = len(matches)
            if matches:
                alert_ids = self._alerts.create_alerts_from_matches(event, matches)
                # Step 3: Correlation (only after alert generation)
                if alert_ids and self._correlation is not None:
                    corr_result = self._correlation.correlate_event_alerts(event, alert_ids)
                    correlations_created = corr_result.correlations_created
                    correlations_updated = corr_result.correlations_updated

                    # Step 4: Incident Creation (only when correlations exist)
                    all_affected_corrs = sorted(
                        list(set(correlations_created + correlations_updated))
                    )
                    if all_affected_corrs and self._incident is not None:
                        inc_result = self._incident.process_correlations(all_affected_corrs)
                        incidents_created = inc_result.incidents_created
                        incidents_updated = inc_result.incidents_updated

                        # Step 5: ML Risk Scoring (only when incidents are created or updated)
                        all_affected_incidents = sorted(
                            list(set(incidents_created + incidents_updated))
                        )
                        if all_affected_incidents and self._risk is not None:
                            risk_result = self._risk.score_incidents(all_affected_incidents)
                            risk_assessments_created = risk_result.assessments_created
                            risk_assessments_updated = risk_result.assessments_updated
                            risk_score = risk_result.latest_score
                            risk_level = risk_result.latest_level

                        # Step 6: Threat Intelligence Enrichment (only when incidents exist)
                        if all_affected_incidents and self._threat_intel is not None:
                            ti_result = self._threat_intel.enrich_incidents(all_affected_incidents)
                            threat_intel_created = ti_result.enrichments_created
                            threat_intel_updated = ti_result.enrichments_updated
                            iocs_extracted = ti_result.iocs_extracted

        return PipelineResult(
            event_id=processing_result.event_id,
            newly_persisted=processing_result.newly_persisted,
            duplicate=processing_result.duplicate,
            processing_status=processing_result.processing_status,
            persistence_status=processing_result.persistence_status,
            detection_matches=match_count,
            alerts_created=alert_ids,
            correlations_created=correlations_created,
            correlations_updated=correlations_updated,
            incidents_created=incidents_created,
            incidents_updated=incidents_updated,
            risk_assessments_created=risk_assessments_created,
            risk_assessments_updated=risk_assessments_updated,
            risk_score=risk_score,
            risk_level=risk_level,
            threat_intel_created=threat_intel_created,
            threat_intel_updated=threat_intel_updated,
            iocs_extracted=iocs_extracted,
        )
