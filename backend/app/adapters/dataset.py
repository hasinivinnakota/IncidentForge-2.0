"""Dataset Activity Telemetry Adapter.

Translates DatasetActivity events into canonical NormalizedEvent objects.
Implements the TelemetryAdapter interface.

Guarantees:
- Pure data transformation (no shell execution, no subprocess, no PowerShell, no network calls).
- Preserves deterministic idempotency using activity ID (`dset-act-<id>`).
- Redacts/sanitizes sensitive parameters and credentials.
- Canonical source: "dataset_activity".
- Maps operations to canonical event types:
  * dataset_opened -> "dataset_opened"
  * dataset_read -> "dataset_read"
  * sensitive_column_access -> "sensitive_column_access"
  * bulk_access -> "dataset_bulk_access"
  * dataset_modified -> "dataset_modified"
  * dataset_copied -> "dataset_copied"
  * dataset_exported -> "dataset_exported"
  * dataset_deleted -> "dataset_deleted"
  * schema_changed -> "dataset_schema_changed"
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any

from .base import TelemetryAdapter
from ..models.dataset import DatasetActivity, DatasetOperation, SensitivityLevel
from ..models.events import NormalizedEvent
from ..services.normalization import NormalizationService

logger = logging.getLogger(__name__)

_SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "credential",
    "private_key",
    "session",
    "cookie",
)

_SENSITIVE_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|authorization|"
    r"bearer|credential|private[_-]?key|session|cookie)\b\s*[:=]\s*[^\s,;]+"
)


def sanitize_value(val: Any) -> Any:
    """Sanitize strings, dictionaries, and lists to redact sensitive credentials."""
    if isinstance(val, str):
        cleaned = _SENSITIVE_PATTERN.sub("[REDACTED]", val)
        for key in _SENSITIVE_KEY_SUBSTRINGS:
            cleaned = re.sub(re.escape(key), "[REDACTED]", cleaned, flags=re.IGNORECASE)
        return cleaned[:5000]
    if isinstance(val, dict):
        return {
            k: ("[REDACTED]" if any(s in k.lower() for s in _SENSITIVE_KEY_SUBSTRINGS) else sanitize_value(v))
            for k, v in val.items()
        }
    if isinstance(val, list):
        return [sanitize_value(item) for item in val]
    return val


class DatasetActivityAdapter(TelemetryAdapter):
    """Adapter translating raw DatasetActivity objects into canonical NormalizedEvent instances."""

    def __init__(
        self,
        activities: Sequence[DatasetActivity | Mapping[str, Any]] | None = None,
        normalizer: NormalizationService | None = None,
    ):
        self._activities: list[dict[str, Any]] = []
        self._normalizer = normalizer or NormalizationService()

        if activities:
            for item in activities:
                self.add_activity(item)

    def add_activity(self, activity_input: DatasetActivity | Mapping[str, Any]) -> None:
        if isinstance(activity_input, DatasetActivity):
            self._activities.append(activity_input.model_dump(mode="json"))
        else:
            self._activities.append(dict(activity_input))

    def clear(self) -> None:
        self._activities.clear()

    @staticmethod
    def map_operation_to_severity(
        operation: str,
        records_accessed: int = 0,
        records_modified: int = 0,
        has_sensitive_columns: bool = False,
        sensitivity: str = "LOW",
    ) -> int:
        """Compute bounded canonical severity (0-15) based on operation and impact volume."""
        op = operation.lower()
        sens = sensitivity.upper()

        if op in ("dataset_exported", "export"):
            if sens in ("CRITICAL", "HIGH") or records_accessed >= 5000:
                return 10  # High
            return 7

        if op in ("dataset_deleted", "delete"):
            return 11 if sens in ("CRITICAL", "HIGH") else 8

        if op in ("dataset_modified", "modify"):
            if records_modified >= 10000:
                return 11
            if records_modified >= 1000:
                return 7
            return 4

        if op in ("schema_changed", "schema_change"):
            return 8 if sens in ("CRITICAL", "HIGH") else 6

        if op in ("bulk_access", "bulk_read"):
            if sens == "CRITICAL" or has_sensitive_columns:
                return 10  # High
            if records_accessed >= 50000:
                return 8
            return 6

        if op in ("sensitive_column_access",):
            if sens == "CRITICAL":
                return 9
            return 7

        if op in ("dataset_opened", "dataset_read"):
            return 3  # Informational / low

        return 3

    def transform_activity(self, activity: Mapping[str, Any]) -> dict[str, Any]:
        """Convert a single raw dataset activity record into an IncidentForge source event mapping."""
        raw_id = activity.get("activity_id") or activity.get("id") or str(hash(json.dumps(dict(activity), sort_keys=True, default=str)) & 0xFFFFFFFF)
        event_id = f"dset-act-{raw_id}"

        # Timestamp
        ts = activity.get("timestamp")
        if isinstance(ts, datetime):
            timestamp_str = ts.astimezone(timezone.utc).isoformat()
        elif isinstance(ts, str):
            timestamp_str = ts
        else:
            timestamp_str = datetime.now(timezone.utc).isoformat()

        operation_val = str(activity.get("operation", "dataset_read"))
        if "." in operation_val:
            operation_val = operation_val.split(".")[-1]

        # Normalize canonical event_type
        if operation_val in ("bulk_access", "bulk_read"):
            event_type = "dataset_bulk_access"
        elif operation_val in ("sensitive_column_access",):
            event_type = "sensitive_column_access"
        elif operation_val in ("schema_changed", "schema_change"):
            event_type = "dataset_schema_changed"
        elif not operation_val.startswith("dataset_"):
            event_type = f"dataset_{operation_val}"
        else:
            event_type = operation_val

        dataset_id = str(activity.get("dataset_id", "unknown_dataset"))
        dataset_name = str(activity.get("dataset_name", dataset_id))
        actor = str(activity.get("actor") or activity.get("user") or "unknown_actor")
        actor_host = str(activity.get("actor_host") or activity.get("host") or "workstation-01")
        source_ip = activity.get("source_ip") or activity.get("actor_ip")
        destination_ip = activity.get("destination_ip")

        records_accessed = int(activity.get("records_accessed", 0))
        records_modified = int(activity.get("records_modified", 0))
        sensitive_cols = list(activity.get("sensitive_columns", []))
        export_size = int(activity.get("export_size_bytes", 0))
        export_dest = activity.get("export_destination")
        context = dict(activity.get("context", {}))
        sensitivity_val = str(context.get("sensitivity", "LOW"))

        severity = self.map_operation_to_severity(
            operation=operation_val,
            records_accessed=records_accessed,
            records_modified=records_modified,
            has_sensitive_columns=bool(sensitive_cols),
            sensitivity=sensitivity_val,
        )

        message = (
            f"[{dataset_name}] {event_type.upper()} by actor '{actor}' "
            f"(records: {records_accessed or records_modified}, sensitive_cols: {len(sensitive_cols)})"
        )
        if export_dest:
            message += f" exported to {export_dest}"

        metadata = {
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "dataset_operation": operation_val,
            "records_accessed": records_accessed,
            "records_modified": records_modified,
            "sensitive_columns": sanitize_value(sensitive_cols),
            "export_size_bytes": export_size,
            "export_destination": sanitize_value(export_dest),
            "sensitivity": sensitivity_val,
            "context": sanitize_value(context),
        }

        return {
            "event_id": event_id,
            "timestamp": timestamp_str,
            "source": "dataset_activity",
            "event_type": event_type,
            "severity": severity,
            "message": sanitize_value(message),
            "host": sanitize_value(actor_host),
            "user": sanitize_value(actor),
            "source_ip": sanitize_value(source_ip),
            "destination_ip": sanitize_value(destination_ip),
            "metadata": metadata,
        }

    def get_events(self) -> Sequence[Mapping[str, Any]]:
        return [self.transform_activity(act) for act in self._activities]

    def get_normalized_events(self) -> list[NormalizedEvent]:
        return [self._normalizer.normalize(ev) for ev in self.get_events()]
