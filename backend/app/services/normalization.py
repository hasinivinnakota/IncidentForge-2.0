"""Deterministic source-event normalization."""

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from ..models.events import NormalizedEvent


class NormalizationService:
    """Convert source mappings into the canonical event contract."""

    def normalize(self, source_event: Mapping[str, Any]) -> NormalizedEvent:
        payload = dict(source_event)
        timestamp = payload.get("timestamp")
        if isinstance(timestamp, str):
            payload["timestamp"] = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
            payload["timestamp"] = timestamp.replace(tzinfo=timezone.utc)

        severity = payload.get("severity", 0)
        if isinstance(severity, str):
            payload["severity"] = self._severity_value(severity)

        known_fields = set(NormalizedEvent.model_fields)
        metadata = dict(payload.get("metadata") or {})
        metadata.update({key: value for key, value in payload.items() if key not in known_fields})
        payload["metadata"] = metadata
        return NormalizedEvent.model_validate({key: value for key, value in payload.items() if key in known_fields})

    @staticmethod
    def _severity_value(value: str) -> int:
        levels = {"low": 3, "medium": 6, "high": 10, "critical": 15}
        normalized = value.strip().lower()
        if normalized not in levels:
            raise ValueError(f"Unsupported severity: {value}")
        return levels[normalized]