"""Correlation engine service evaluating alerts against correlation rules and managing correlation lifecycle."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from uuid import uuid4

from ..models.correlation import (
    CorrelatableAlert,
    Correlation,
    CorrelationMatch,
    CorrelationStatus,
)
from ..models.events import NormalizedEvent
from ..persistence.models import AuditEvent
from ..persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
)
from ..rules.correlation_base import CorrelationRule

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CorrelationResult:
    correlations_created: list[str]
    correlations_updated: list[str]


class CorrelationEngine:
    """Evaluates alerts against correlation rules and manages persistent correlation state."""

    def __init__(
        self,
        rules: Sequence[CorrelationRule],
        correlation_repository: CorrelationRepository,
        alert_repository: AlertRepository,
        event_repository: EventRepository,
    ):
        self._rules = list(rules)
        self._correlation_repo = correlation_repository
        self._alert_repo = alert_repository
        self._event_repo = event_repository

    @property
    def rules(self) -> list[CorrelationRule]:
        return list(self._rules)

    @staticmethod
    def generate_correlation_id(
        correlation_type: str, entity_key: str, founding_alert_id: str
    ) -> str:
        """Generate a deterministic correlation identifier."""
        digest = hashlib.sha256(
            f"{correlation_type}:{entity_key}:{founding_alert_id}".encode()
        ).hexdigest()[:16]
        return f"corr-{digest}"

    def evaluate_alert_matches(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> list[CorrelationMatch]:
        """Evaluate an incoming alert against all rules given the historical pool."""
        matches: list[CorrelationMatch] = []
        for rule in self._rules:
            match = rule.evaluate(incoming, history)
            if match is not None:
                matches.append(match)
        return matches

    def correlate_event_alerts(
        self, event: NormalizedEvent, alert_ids: Sequence[str]
    ) -> CorrelationResult:
        """Correlate newly generated alerts for an event against historical alert context."""
        created_ids: list[str] = []
        updated_ids: list[str] = []

        if not alert_ids:
            return CorrelationResult(correlations_created=[], correlations_updated=[])

        # Determine maximum lookback window across all registered rules
        max_window_seconds = max((r.window_seconds for r in self._rules), default=1800)
        since = event.timestamp - timedelta(seconds=max_window_seconds)

        # Retrieve recent alerts within window
        recent_records = self._alert_repo.list_recent_alerts(since=since, limit=200)

        # Build correlatable historical pool
        history_pool: list[CorrelatableAlert] = []
        for r in recent_records:
            h_event = self._event_repo.get_event(r.event_id)
            mitre = json.loads(r.mitre_techniques_json) if r.mitre_techniques_json else []
            evidence = json.loads(r.evidence_json) if r.evidence_json else {}
            history_pool.append(
                CorrelatableAlert(
                    alert_id=r.alert_id,
                    event_id=r.event_id,
                    timestamp=r.timestamp,
                    rule_id=r.rule_id,
                    rule_name=r.rule_name,
                    severity=r.severity,
                    source=r.source,
                    host=h_event.host if h_event else None,
                    user=h_event.user if h_event else None,
                    source_ip=h_event.source_ip if h_event else None,
                    destination_ip=h_event.destination_ip if h_event else None,
                    mitre_techniques=mitre,
                    evidence=evidence,
                )
            )

        # Process each newly generated alert for the event
        for alert_id in alert_ids:
            alert_record = self._alert_repo.get_alert(alert_id)
            if not alert_record:
                continue

            incoming = CorrelatableAlert(
                alert_id=alert_record.alert_id,
                event_id=alert_record.event_id,
                timestamp=alert_record.timestamp,
                rule_id=alert_record.rule_id,
                rule_name=alert_record.rule_name,
                severity=alert_record.severity,
                source=alert_record.source,
                host=event.host,
                user=event.user,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                mitre_techniques=json.loads(alert_record.mitre_techniques_json)
                if alert_record.mitre_techniques_json
                else [],
                evidence=json.loads(alert_record.evidence_json)
                if alert_record.evidence_json
                else {},
            )

            # Evaluate against all rules
            matches = self.evaluate_alert_matches(incoming, history_pool)

            for match in matches:
                # Find rule-specific window
                rule_window = next(
                    (r.window_seconds for r in self._rules if r.rule_id == match.rule_id),
                    1800,
                )
                window_cutoff = incoming.timestamp - timedelta(seconds=rule_window)

                # Check for existing open correlation of the same type and entity
                existing = self._correlation_repo.find_open_correlation(
                    correlation_type=match.correlation_type,
                    entity_key=match.entity_key,
                    since=window_cutoff,
                )

                if existing is not None:
                    # Update existing correlation
                    current_alerts = json.loads(existing.alert_ids_json)
                    current_events = json.loads(existing.event_ids_json)
                    current_mitre = json.loads(existing.mitre_techniques_json)

                    new_alerts = sorted(list(set(current_alerts) | set(match.matched_alert_ids)))
                    new_events = sorted(list(set(current_events) | set(match.matched_event_ids)))
                    new_mitre = sorted(list(set(current_mitre) | set(match.mitre_techniques)))
                    new_severity = max(existing.severity, match.severity)

                    if len(new_alerts) > len(current_alerts):
                        domain_corr = Correlation(
                            correlation_id=existing.correlation_id,
                            correlation_type=existing.correlation_type,
                            entity_key=existing.entity_key,
                            title=existing.title,
                            description=match.description,
                            severity=new_severity,
                            status=CorrelationStatus.OPEN,
                            first_seen=existing.first_seen,
                            last_seen=max(existing.last_seen, incoming.timestamp),
                            alert_ids=new_alerts,
                            event_ids=new_events,
                            alert_count=len(new_alerts),
                            mitre_techniques=new_mitre,
                            evidence=match.evidence,
                        )
                        self._correlation_repo.update_correlation(domain_corr)
                        self._event_repo.create_audit_event(
                            AuditEvent(
                                audit_id=f"audit-{uuid4()}",
                                timestamp=datetime.now(timezone.utc),
                                actor="system",
                                action="correlation.updated",
                                target=existing.correlation_id,
                                result="accepted",
                                metadata_json=json.dumps(
                                    {
                                        "correlation_id": existing.correlation_id,
                                        "alert_id": incoming.alert_id,
                                        "alert_count": len(new_alerts),
                                    },
                                    sort_keys=True,
                                ),
                            )
                        )
                        updated_ids.append(existing.correlation_id)
                else:
                    # Create new correlation
                    founding_alert_id = match.matched_alert_ids[0]
                    correlation_id = self.generate_correlation_id(
                        match.correlation_type, match.entity_key, founding_alert_id
                    )

                    # Determine first_seen and last_seen
                    all_matched_alerts = [
                        a
                        for a in history_pool + [incoming]
                        if a.alert_id in match.matched_alert_ids
                    ]
                    first_seen = (
                        min(a.timestamp for a in all_matched_alerts)
                        if all_matched_alerts
                        else incoming.timestamp
                    )
                    last_seen = (
                        max(a.timestamp for a in all_matched_alerts)
                        if all_matched_alerts
                        else incoming.timestamp
                    )

                    domain_corr = Correlation(
                        correlation_id=correlation_id,
                        correlation_type=match.correlation_type,
                        entity_key=match.entity_key,
                        title=match.title,
                        description=match.description,
                        severity=match.severity,
                        status=CorrelationStatus.OPEN,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        alert_ids=match.matched_alert_ids,
                        event_ids=match.matched_event_ids,
                        alert_count=len(match.matched_alert_ids),
                        mitre_techniques=match.mitre_techniques,
                        evidence=match.evidence,
                    )

                    write_result = self._correlation_repo.create_correlation(domain_corr)
                    outcome = "created" if write_result.created else "duplicate"

                    self._event_repo.create_audit_event(
                        AuditEvent(
                            audit_id=f"audit-{uuid4()}",
                            timestamp=datetime.now(timezone.utc),
                            actor="system",
                            action=f"correlation.{outcome}",
                            target=correlation_id,
                            result="accepted",
                            metadata_json=json.dumps(
                                {
                                    "correlation_id": correlation_id,
                                    "correlation_type": match.correlation_type,
                                    "entity_key": match.entity_key,
                                    "outcome": outcome,
                                },
                                sort_keys=True,
                            ),
                        )
                    )

                    if write_result.created:
                        created_ids.append(correlation_id)
                        logger.info(
                            "Correlation created",
                            extra={
                                "correlation_id": correlation_id,
                                "type": match.correlation_type,
                                "entity_key": match.entity_key,
                            },
                        )

            # Add incoming alert to history pool for any subsequent alert in the same event
            history_pool.append(incoming)

        # Return unique IDs
        unique_created = sorted(list(set(created_ids)))
        unique_updated = sorted(list(set(updated_ids)))
        return CorrelationResult(
            correlations_created=unique_created,
            correlations_updated=unique_updated,
        )
