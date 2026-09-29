"""Event-processing boundary for persistence and auditability."""

import logging
import json
from datetime import datetime, timezone
from uuid import uuid4

from ..models.events import NormalizedEvent
from ..models.processing import EventProcessingResult, PersistenceStatus
from ..persistence.models import AuditEvent
from ..persistence.repositories import EventRepository

logger = logging.getLogger(__name__)


class EventProcessingService:
    """Persist normalized events without implementing future detection logic."""

    def __init__(self, repository: EventRepository):
        self.repository = repository

    def process(self, event: NormalizedEvent) -> EventProcessingResult:
        write_result = self.repository.create_event(event)
        outcome = "created" if write_result.created else "duplicate"
        self.repository.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=datetime.now(timezone.utc),
                actor="system",
                action=f"event.{outcome}",
                target=event.event_id,
                result="accepted",
                metadata_json=json.dumps({"event_id": event.event_id, "outcome": outcome}, sort_keys=True),
            )
        )
        logger.info("Event processing completed", extra={"event_id": event.event_id, "outcome": outcome})
        return EventProcessingResult(
            event_id=event.event_id,
            newly_persisted=write_result.created,
            duplicate=not write_result.created,
            persistence_status=PersistenceStatus.PERSISTED if write_result.created else PersistenceStatus.DUPLICATE,
        )