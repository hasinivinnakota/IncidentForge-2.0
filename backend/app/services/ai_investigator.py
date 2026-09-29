"""AI Investigator service orchestrating incident analysis, LLM provider invocation,

persistence, and audit logging.

Security & Integrity Guarantees:
- Strictly advisory findings: never executes response actions or modifies endpoints.
- Strictly preserves Incident severity and ML risk score: never overwrites or recalculates them.
- Sanitizes and bounds all incident telemetry (truncating strings, stripping credentials/secrets).
- Deterministic investigation ID: `inv-SHA256("inv:" + incident_id)[:16]`.
- Records audit events for requested, completed, and failed investigations.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import hashlib
import json
import logging
from uuid import uuid4

from ..models.investigation import InvestigationResult
from ..persistence.models import AuditEvent
from ..persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    InvestigationRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from .llm_provider import LLMContext, LLMProvider, LocalDevLLMProvider
from .investigation_memory import InvestigationMemoryService

logger = logging.getLogger(__name__)

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "credential",
    "private_key",
)


class AIInvestigatorService:
    """Manages AI investigations for security incidents."""

    def __init__(
        self,
        investigation_repository: InvestigationRepository,
        incident_repository: IncidentRepository,
        event_repository: EventRepository,
        alert_repository: AlertRepository | None = None,
        correlation_repository: CorrelationRepository | None = None,
        risk_repository: RiskAssessmentRepository | None = None,
        threat_intel_repository: ThreatIntelRepository | None = None,
        provider: LLMProvider | None = None,
        memory_service: InvestigationMemoryService | None = None,
    ):
        self._investigation_repo = investigation_repository
        self._incident_repo = incident_repository
        self._event_repo = event_repository
        self._alert_repo = alert_repository
        self._corr_repo = correlation_repository
        self._risk_repo = risk_repository
        self._ti_repo = threat_intel_repository
        self._provider = provider or LocalDevLLMProvider()
        self._memory = memory_service or InvestigationMemoryService()

    @staticmethod
    def generate_investigation_id(incident_id: str) -> str:
        """Generate deterministic investigation identifier for an incident."""
        digest = hashlib.sha256(f"inv:{incident_id}".encode()).hexdigest()[:16]
        return f"inv-{digest}"

    def investigate_incident(
        self, incident_id: str, force: bool = False
    ) -> InvestigationResult | None:
        """Perform or retrieve an AI investigation for an incident.

        If `force=False` and an investigation already exists, returns the existing record.
        If `force=True` or no investigation exists, executes the investigation workflow,
        persists the result, logs audit events, and returns the result.
        """
        now = datetime.now(timezone.utc)
        inv_id = self.generate_investigation_id(incident_id)

        # Check existing if not forcing re-run
        if not force:
            existing = self._investigation_repo.get_investigation(inv_id)
            if existing is not None:
                return self._record_to_domain(existing)

        # Fetch Incident
        incident_record = self._incident_repo.get_incident(incident_id)
        if incident_record is None:
            logger.warning(f"Cannot investigate non-existent incident '{incident_id}'")
            return None

        # Log audit: investigation.requested
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor="system",
                action="investigation.requested",
                target=inv_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "investigation_id": inv_id,
                        "incident_id": incident_id,
                        "force": force,
                        "provider": self._provider.provider_name,
                    },
                    sort_keys=True,
                ),
            )
        )

        try:
            # Build bounded LLMContext
            context = self._build_context(incident_record)

            # Call provider
            result = self._provider.investigate(context, investigation_id=inv_id)

            # Persist result
            self._investigation_repo.save_investigation(result)

            # Log audit: investigation.completed
            self._event_repo.create_audit_event(
                AuditEvent(
                    audit_id=f"audit-{uuid4()}",
                    timestamp=datetime.now(timezone.utc),
                    actor="system",
                    action="investigation.completed",
                    target=inv_id,
                    result="accepted",
                    metadata_json=json.dumps(
                        {
                            "investigation_id": inv_id,
                            "incident_id": incident_id,
                            "confidence": result.confidence,
                            "findings_count": len(result.findings),
                            "provider": result.provider,
                            "model_name": result.model_name,
                        },
                        sort_keys=True,
                    ),
                )
            )

            return result

        except Exception as exc:
            logger.error(f"Investigation failed for incident '{incident_id}': {exc}", exc_info=True)
            self._event_repo.create_audit_event(
                AuditEvent(
                    audit_id=f"audit-{uuid4()}",
                    timestamp=datetime.now(timezone.utc),
                    actor="system",
                    action="investigation.failed",
                    target=inv_id,
                    result="failed",
                    metadata_json=json.dumps(
                        {
                            "investigation_id": inv_id,
                            "incident_id": incident_id,
                            "error": str(exc)[:256],
                        },
                        sort_keys=True,
                    ),
                )
            )
            raise

    def get_investigation(self, investigation_id: str) -> InvestigationResult | None:
        record = self._investigation_repo.get_investigation(investigation_id)
        if record is None:
            return None
        return self._record_to_domain(record)

    def get_latest_for_incident(self, incident_id: str) -> InvestigationResult | None:
        record = self._investigation_repo.get_latest_for_incident(incident_id)
        if record is None:
            return None
        return self._record_to_domain(record)

    def _build_context(self, incident_record) -> LLMContext:
        """Construct bounded, redacted LLM context from incident and associated telemetry."""
        alert_ids = json.loads(incident_record.alert_ids_json) if incident_record.alert_ids_json else []
        event_ids = json.loads(incident_record.event_ids_json) if incident_record.event_ids_json else []
        mitre_techniques = json.loads(incident_record.mitre_techniques_json) if incident_record.mitre_techniques_json else []
        evidence = json.loads(incident_record.evidence_json) if incident_record.evidence_json else {}

        # Extract primary entity
        entity_id = None
        if isinstance(evidence, dict):
            entity_id = evidence.get("entity_key") or evidence.get("entity_id") or evidence.get("host")
            
        # Recall historical memories for entity and techniques
        historical_memories = []
        if entity_id:
            query = f"Incident regarding {entity_id}"
            if mitre_techniques:
                query += f" with techniques {', '.join(mitre_techniques)}"
            historical_memories = self._memory.recall(query, entity_id=entity_id, limit=5)

        # Load alerts summary
        alerts_summary = []
        if self._alert_repo and alert_ids:
            for aid in alert_ids[:10]:  # bound to top 10
                alert = self._alert_repo.get_alert(aid)
                if alert:
                    alerts_summary.append({
                        "alert_id": alert.alert_id,
                        "rule_id": alert.rule_id,
                        "rule_name": self._sanitize_text(alert.rule_name, 128),
                        "severity": alert.severity,
                    })

        # Load ML Risk assessment
        risk_score = None
        risk_level = None
        if self._risk_repo:
            latest_risk = self._risk_repo.get_latest_for_incident(incident_record.incident_id)
            if latest_risk:
                risk_score = latest_risk.risk_score
                risk_level = latest_risk.risk_level

        # Load Threat Intel summary
        ti_summary: dict[str, int] = {
            "total_indicators": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "benign_count": 0,
            "unknown_count": 0,
        }
        if self._ti_repo:
            ti_records = self._ti_repo.list_by_incident(incident_record.incident_id)
            ti_summary["total_indicators"] = len(ti_records)
            for r in ti_records:
                cls_name = r.classification.lower()
                if cls_name == "malicious":
                    ti_summary["malicious_count"] += 1
                elif cls_name == "suspicious":
                    ti_summary["suspicious_count"] += 1
                elif cls_name == "benign":
                    ti_summary["benign_count"] += 1
                else:
                    ti_summary["unknown_count"] += 1

        # Build timeline events from raw events if available
        timeline_events = []
        if self._event_repo and event_ids:
            for eid in event_ids[:15]:  # bound to top 15
                ev = self._event_repo.get_event(eid)
                if ev:
                    timeline_events.append({
                        "timestamp": ev.timestamp.isoformat() if ev.timestamp else datetime.now(timezone.utc).isoformat(),
                        "event_type": self._sanitize_text(ev.event_type, 64),
                        "description": self._sanitize_text(ev.message or f"Event {ev.event_id}", 256),
                        "source_entity": ev.source,
                    })

        # Build dataset security context (v2.0) from evidence when incident involves dataset activity
        dataset_context: dict = {}
        if isinstance(evidence, dict):
            dataset_id = evidence.get("dataset_id")
            if dataset_id or any(
                "dataset" in t.lower() for t in (incident_record.tags_json and [incident_record.tags_json] or [])
            ):
                dataset_context = {
                    "dataset_id": dataset_id,
                    "dataset_name": evidence.get("dataset_name", dataset_id or "unknown"),
                    "actor": evidence.get("actor"),
                    "sensitivity": evidence.get("dataset_sensitivity", evidence.get("sensitivity")),
                    "records_accessed": evidence.get("records_accessed", 0),
                    "sensitive_columns": evidence.get("sensitive_columns", []),
                    "export_destination": evidence.get("export_destination"),
                    "export_size_bytes": evidence.get("export_size_bytes", 0),
                    "operations": evidence.get("operations", []),
                }

        return LLMContext(
            incident_id=incident_record.incident_id,
            incident_title=self._sanitize_text(incident_record.title, 256),
            incident_severity=incident_record.severity,
            incident_status=incident_record.status,
            entity_id=self._sanitize_text(entity_id, 128) if entity_id else None,
            created_at=incident_record.created_at or datetime.now(timezone.utc),
            alert_count=len(alert_ids),
            alerts_summary=alerts_summary,
            mitre_techniques=mitre_techniques[:10],
            threat_intel_summary=ti_summary,
            risk_score=risk_score,
            risk_level=risk_level,
            timeline_events=timeline_events,
            dataset_context=dataset_context,
            historical_memories=historical_memories,
        )

    @staticmethod
    def _sanitize_text(text: str | None, max_length: int = 500) -> str:
        """Sanitize text by removing credentials, stripping whitespace, and bounding length."""
        if not text:
            return ""
        sanitized = str(text).strip()
        import re
        for pattern in SENSITIVE_KEY_SUBSTRINGS:
            sanitized = re.sub(re.escape(pattern), "[REDACTED]", sanitized, flags=re.IGNORECASE)
        return sanitized[:max_length]

    @staticmethod
    def _record_to_domain(record) -> InvestigationResult:
        """Convert persistence Investigation record to domain InvestigationResult."""
        from ..models.investigation import FindingItem, RecommendedAction, TimelineItem

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
