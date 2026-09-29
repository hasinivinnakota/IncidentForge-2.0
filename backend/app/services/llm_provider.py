"""LLM Provider abstraction and deterministic local provider for AI Investigation.

Strictly advisory, evidence-grounded, zero external calls, safe telemetry bounding.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..models.investigation import (
    FindingItem,
    FindingType,
    InvestigationResult,
    RecommendedAction,
    TimelineItem,
)


class LLMContext(BaseModel):
    """Bounded, redacted, structured context passed to an LLM provider."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    incident_title: str
    incident_severity: int
    incident_status: str
    entity_id: str | None = None
    created_at: datetime
    alert_count: int
    alerts_summary: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    threat_intel_summary: dict[str, Any] = Field(default_factory=dict)
    risk_score: float | None = None
    risk_level: str | None = None
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)
    # v2.0: Dataset security context (optional — present when incident involves dataset activity)
    dataset_context: dict[str, Any] = Field(default_factory=dict)
    historical_memories: list[dict[str, Any]] = Field(default_factory=list)


class LLMProvider(ABC):
    """Abstract interface for investigation LLM providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider implementation."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the model backing this provider."""
        pass

    @abstractmethod
    def investigate(self, context: LLMContext, investigation_id: str) -> InvestigationResult:
        """Analyze the structured context and return an advisory InvestigationResult."""
        pass


class LocalDevLLMProvider(LLMProvider):
    """Deterministic, local development provider that derives structured investigation findings

    from grounded Incident evidence without calling external APIs.
    """

    @property
    def provider_name(self) -> str:
        return "local_dev"

    @property
    def model_name(self) -> str:
        return "heuristic_deterministic_v1"

    def investigate(self, context: LLMContext, investigation_id: str) -> InvestigationResult:
        # 1. Findings (OBSERVED, INFERRED, RECOMMENDED)
        findings: list[FindingItem] = []

        # Observed alerts
        observed_alert_types = [a.get("rule_name", "Unknown Alert") for a in context.alerts_summary]
        findings.append(
            FindingItem(
                finding_type=FindingType.OBSERVED,
                description=f"Observed {context.alert_count} alert(s) across incident: {', '.join(observed_alert_types) if observed_alert_types else 'None'}.",
                evidence=[f"alert_count={context.alert_count}"]
                + [f"rule:{a.get('rule_id', 'unknown')}" for a in context.alerts_summary[:5]],
            )
        )

        # Observed entity
        if context.entity_id:
            findings.append(
                FindingItem(
                    finding_type=FindingType.OBSERVED,
                    description=f"Primary affected entity identified as '{context.entity_id}'.",
                    evidence=[f"entity_id={context.entity_id}"],
                )
            )

        # Observed threat intel
        ti_malicious = context.threat_intel_summary.get("malicious_count", 0)
        ti_suspicious = context.threat_intel_summary.get("suspicious_count", 0)
        if ti_malicious > 0 or ti_suspicious > 0:
            findings.append(
                FindingItem(
                    finding_type=FindingType.OBSERVED,
                    description=f"Threat intelligence confirmed {ti_malicious} malicious and {ti_suspicious} suspicious indicator(s) associated with incident telemetry.",
                    evidence=[f"malicious={ti_malicious}", f"suspicious={ti_suspicious}"],
                )
            )

        # Inferred attack hypothesis
        if context.mitre_techniques:
            mitre_str = ", ".join(context.mitre_techniques)
            findings.append(
                FindingItem(
                    finding_type=FindingType.INFERRED,
                    description=f"Observed telemetry patterns align with mapped MITRE ATT&CK technique(s): {mitre_str}.",
                    evidence=[f"techniques={mitre_str}"],
                )
            )
        elif context.alert_count > 1:
            findings.append(
                FindingItem(
                    finding_type=FindingType.INFERRED,
                    description="Multiple alerts correlated against the same entity within a short time window indicate a coordinated sequence of suspicious activities.",
                    evidence=[f"alert_count={context.alert_count}"],
                )
            )
        else:
            findings.append(
                FindingItem(
                    finding_type=FindingType.INFERRED,
                    description="Single-event alert requires baseline entity profiling to verify whether this is an anomaly or typical user behavior.",
                    evidence=["alert_count=1"],
                )
            )

        # Dataset-specific findings (v2.0) — only when dataset context is present
        ds_ctx = context.dataset_context
        is_dataset_incident = bool(ds_ctx)
        if is_dataset_incident:
            dataset_name = ds_ctx.get("dataset_name", "unknown dataset")
            sensitivity = ds_ctx.get("sensitivity", "UNKNOWN")
            actor = ds_ctx.get("actor", context.entity_id or "unknown")
            records = ds_ctx.get("records_accessed", 0)
            sensitive_cols = ds_ctx.get("sensitive_columns", [])
            export_dest = ds_ctx.get("export_destination")
            operations = ds_ctx.get("operations", [])

            # OBSERVED: Dataset access
            findings.append(
                FindingItem(
                    finding_type=FindingType.OBSERVED,
                    description=(
                        f"Actor '{actor}' performed operations {operations} on dataset '{dataset_name}' "
                        f"(sensitivity: {sensitivity}), accessing {records:,} records"
                        + (f" including sensitive columns: {sensitive_cols}" if sensitive_cols else "") + "."
                    ),
                    evidence=[
                        f"dataset={dataset_name}",
                        f"sensitivity={sensitivity}",
                        f"records_accessed={records}",
                        f"sensitive_columns={sensitive_cols}",
                        f"actor={actor}",
                    ],
                )
            )

            if export_dest:
                findings.append(
                    FindingItem(
                        finding_type=FindingType.OBSERVED,
                        description=f"Dataset '{dataset_name}' was exported to destination: '{export_dest}'. This may represent data staging for exfiltration.",
                        evidence=[f"export_destination={export_dest}", f"dataset={dataset_name}"],
                    )
                )

            # INFERRED: Exfiltration pattern
            if export_dest or (records > 10000 and sensitive_cols):
                findings.append(
                    FindingItem(
                        finding_type=FindingType.INFERRED,
                        description=(
                            f"The sequence of bulk sensitive data access followed by export from '{dataset_name}' is "
                            f"consistent with a data exfiltration pattern (MITRE T1530, T1567). "
                            f"Actor '{actor}' accessed {records:,} records including PII/financial fields before export."
                        ),
                        evidence=[
                            "pattern=access+export_sequence",
                            f"mitre=T1530,T1567",
                            f"records={records}",
                        ],
                    )
                )

        # Recommended immediate analyst attention
        if is_dataset_incident:
            ds_ctx = context.dataset_context
            dataset_name = ds_ctx.get("dataset_name", "dataset")
            actor = ds_ctx.get("actor", context.entity_id or "unknown")
            findings.append(
                FindingItem(
                    finding_type=FindingType.RECOMMENDED,
                    description=(
                        f"Analyst should restrict access to '{dataset_name}' and review actor '{actor}' session logs. "
                        f"Consider proposing restrict_dataset_access simulation response and revoking actor credentials if unauthorized access is confirmed. "
                        f"ANALYST APPROVAL REQUIRED for any real action. This is advisory only."
                    ),
                    evidence=["advisory_guidance", "simulation_only"],
                )
            )
        else:
            findings.append(
                FindingItem(
                    finding_type=FindingType.RECOMMENDED,
                    description="Analyst should inspect raw endpoint logs, review process trees, and verify user authorization for identified activities.",
                    evidence=["advisory_guidance"],
                )
            )

        # 2. Timeline construction
        timeline: list[TimelineItem] = []
        for event in context.timeline_events:
            ts = event.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    ts = datetime.now(timezone.utc)
            elif not isinstance(ts, datetime):
                ts = datetime.now(timezone.utc)

            timeline.append(
                TimelineItem(
                    timestamp=ts,
                    event_type=event.get("event_type", "security_event"),
                    description=event.get("description", "Security event recorded in incident evidence"),
                    source_entity=event.get("source_entity") or context.entity_id,
                )
            )

        if not timeline:
            timeline.append(
                TimelineItem(
                    timestamp=context.created_at,
                    event_type="incident_created",
                    description=f"Incident {context.incident_id} created with initial title: {context.incident_title}",
                    source_entity=context.entity_id,
                )
            )

        # 3. Investigation gaps
        gaps: list[str] = []
        if not context.threat_intel_summary.get("total_indicators"):
            gaps.append("No IOCs were extracted or enriched from incident telemetry.")
        if len(context.alerts_summary) == 0:
            gaps.append("Alert details could not be retrieved from evidence store.")
        if not context.entity_id:
            gaps.append("No specific host or entity identifier linked to incident.")
        if not gaps:
            gaps.append("Network flow metadata and full memory dumps are currently uncollected.")

        # 4. Recommended next steps
        next_steps = [
            f"Review alerts and evidence for entity '{context.entity_id or 'unknown'}'.",
            "Validate user session authenticity and check for concurrent anomalous logins.",
            "Verify whether any process execution originated from untrusted directories or scripts.",
        ]
        if ti_malicious > 0:
            next_steps.append("Prioritize host containment review due to confirmed malicious indicators.")

        # 5. Inert proposed response actions (requiring human analyst approval)
        response_actions: list[RecommendedAction] = []
        target = context.entity_id or "unassigned_host"

        if context.dataset_context:
            ds_name = context.dataset_context.get("dataset_name", "unknown dataset")
            ds_actor = context.dataset_context.get("actor", target)
            response_actions.append(
                RecommendedAction(
                    action_type="restrict_dataset_access",
                    description=(
                        f"SIMULATION ONLY: Propose restricting access to '{ds_name}' to read-only / quarantine mode. "
                        f"No real permissions, ACLs, or files would be modified without analyst approval. "
                        f"ANALYST APPROVAL REQUIRED."
                    ),
                    target_entity=ds_name,
                    analyst_approval_required=True,
                    inert_proposed_only=True,
                )
            )
            if ds_actor:
                response_actions.append(
                    RecommendedAction(
                        action_type="revoke_credentials",
                        description=f"Propose credential revocation for actor '{ds_actor}' if unauthorized dataset access is confirmed. ANALYST APPROVAL REQUIRED.",
                        target_entity=ds_actor,
                        analyst_approval_required=True,
                        inert_proposed_only=True,
                    )
                )
        else:
            response_actions.append(
                RecommendedAction(
                    action_type="isolate_endpoint",
                    description=f"Propose network isolation for endpoint '{target}' to contain lateral spread pending investigation.",
                    target_entity=target,
                    analyst_approval_required=True,
                    inert_proposed_only=True,
                )
            )

            response_actions.append(
                RecommendedAction(
                    action_type="quarantine_file",
                    description="Propose suspicious binary quarantine if artifacts or malicious hashes are confirmed on host.",
                    target_entity=target,
                    analyst_approval_required=True,
                    inert_proposed_only=True,
                )
            )

            response_actions.append(
                RecommendedAction(
                    action_type="revoke_credentials",
                    description="Propose credential revocation and forced password reset for impacted user accounts.",
                    target_entity=target,
                    analyst_approval_required=True,
                    inert_proposed_only=True,
                )
            )

        # 6. Confidence calculation based on evidence completeness
        confidence_factors = 0.5  # Base confidence
        if context.alert_count > 0:
            confidence_factors += 0.15
        if context.mitre_techniques:
            confidence_factors += 0.15
        if context.threat_intel_summary.get("total_indicators", 0) > 0:
            confidence_factors += 0.10
        if context.entity_id:
            confidence_factors += 0.05
        confidence = round(min(1.0, confidence_factors), 2)

        # 7. Summary
        mitre_mention = f" mapped to MITRE techniques ({', '.join(context.mitre_techniques)})" if context.mitre_techniques else ""
        risk_mention = f" with ML risk assessment {context.risk_level} (score: {context.risk_score})" if context.risk_score is not None else ""
        summary = (
            f"Automated AI investigation for incident {context.incident_id} ('{context.incident_title}'). "
            f"Entity '{context.entity_id or 'unknown'}' was involved in {context.alert_count} alert(s){mitre_mention}{risk_mention}. "
            f"Threat intel reported {ti_malicious} malicious indicator(s). "
            f"Analysis recommends immediate analyst verification and proposes {len(response_actions)} inert containment actions."
        )

        return InvestigationResult(
            investigation_id=investigation_id,
            incident_id=context.incident_id,
            summary=summary,
            confidence=confidence,
            findings=findings,
            timeline=timeline,
            mitre_techniques=context.mitre_techniques,
            threat_intel_summary=context.threat_intel_summary,
            investigation_gaps=gaps,
            recommended_next_steps=next_steps,
            possible_response_actions=response_actions,
            provider=self.provider_name,
            model_name=self.model_name,
            generated_at=datetime.now(timezone.utc),
        )
