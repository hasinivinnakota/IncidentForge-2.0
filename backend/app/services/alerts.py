"""Alert generation service creating domain alerts from detection matches."""

from datetime import datetime, timezone
import hashlib
import json
import logging
from uuid import uuid4

from ..models.alerts import Alert, AlertStatus
from ..models.events import NormalizedEvent
from ..models.rules import DetectionMatch
from ..persistence.models import AuditEvent
from ..persistence.repositories import AlertRepository, EventRepository

logger = logging.getLogger(__name__)


class AlertService:
    """Creates and persists Alert objects from DetectionMatch results."""

    def __init__(self, alert_repository: AlertRepository, event_repository: EventRepository):
        self._alert_repo = alert_repository
        self._event_repo = event_repository

    @staticmethod
    def generate_alert_id(event_id: str, rule_id: str) -> str:
        """Generate a deterministic alert identifier based on event_id and rule_id."""
        digest = hashlib.sha256(f"{event_id}:{rule_id}".encode()).hexdigest()[:16]
        return f"alert-{digest}"

    def create_alerts_from_matches(
        self, event: NormalizedEvent, matches: list[DetectionMatch]
    ) -> list[str]:
        """Create and persist domain alerts for each detection match."""
        alert_ids: list[str] = []
        for match in matches:
            alert_id = self.generate_alert_id(match.event_id, match.rule_id)
            domain_alert = Alert(
                alert_id=alert_id,
                event_id=match.event_id,
                timestamp=event.timestamp,
                rule_id=match.rule_id,
                rule_name=match.rule_name,
                severity=match.severity,
                description=match.description,
                source=event.source,
                evidence=match.evidence,
                mitre_techniques=match.mitre_techniques,
                status=AlertStatus.NEW,
            )
            write_result = self._alert_repo.create_alert(domain_alert)
            outcome = "created" if write_result.created else "duplicate"

            self._event_repo.create_audit_event(
                AuditEvent(
                    audit_id=f"audit-{uuid4()}",
                    timestamp=datetime.now(timezone.utc),
                    actor="system",
                    action=f"alert.{outcome}",
                    target=alert_id,
                    result="accepted",
                    metadata_json=json.dumps(
                        {
                            "alert_id": alert_id,
                            "event_id": match.event_id,
                            "rule_id": match.rule_id,
                            "outcome": outcome,
                        },
                        sort_keys=True,
                    ),
                )
            )
            logger.info(
                "Alert processing completed",
                extra={"alert_id": alert_id, "event_id": match.event_id, "outcome": outcome},
            )
            alert_ids.append(alert_id)
        return alert_ids
