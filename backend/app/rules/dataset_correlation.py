"""Dataset Security correlation rules.

Correlates dataset security alerts into meaningful attack/access sequences.

Rules:
- corr-dset-001: Data Access/Exfiltration Sequence
  * sensitive_column_access or bulk_access + dataset_exported
- corr-dset-002: Privilege/Access Anomaly Sequence
  * unusual_actor + sensitive_access + bulk_access
- corr-dset-003: Mass Modification Sequence
  * dataset_modified (large volume) + schema_changed
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

from ..models.correlation import CorrelatableAlert, CorrelationMatch
from .correlation_base import CorrelationRule

_DATASET_RULE_IDS = frozenset({
    "dataset-001",
    "dataset-002",
    "dataset-003",
    "dataset-004",
    "dataset-005",
    "dataset-006",
})

_ACCESS_RULE_IDS = frozenset({"dataset-001", "dataset-002"})      # bulk + sensitive col
_EXPORT_RULE_IDS = frozenset({"dataset-003"})                      # export
_UNUSUAL_RULE_IDS = frozenset({"dataset-004"})                     # unusual actor
_MODIFY_RULE_IDS = frozenset({"dataset-005"})                      # mass modify
_SCHEMA_RULE_IDS = frozenset({"dataset-006"})                      # schema change


def _dataset_entity_key(alert: CorrelatableAlert) -> str | None:
    """Derive a correlation entity key for dataset alerts."""
    # Prefer user-based entity for access/exfil sequences
    dataset_id = alert.evidence.get("dataset_id")
    if alert.user and dataset_id:
        return f"user:{alert.user}:dataset:{dataset_id}"
    if alert.user:
        return f"user:{alert.user}"
    if dataset_id:
        return f"dataset:{dataset_id}"
    if alert.host:
        return f"host:{alert.host}"
    return None


class DataExfiltrationSequenceRule(CorrelationRule):
    """Correlate bulk/sensitive-column access + export events into an exfiltration sequence.

    Pattern:
      (dataset-001 OR dataset-002) followed by dataset-003
      from the same user/dataset within the window.
    """

    def __init__(self, window_seconds: int = 1800):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-dset-001"

    @property
    def rule_name(self) -> str:
        return "Data Access and Exfiltration Sequence"

    @property
    def correlation_type(self) -> str:
        return "data_exfiltration_sequence"

    @property
    def description(self) -> str:
        return (
            "Detects a sequence of bulk/sensitive data access followed by a dataset export, "
            "suggesting data staging and exfiltration."
        )

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        # Only trigger when incoming is an export alert
        if incoming.rule_id not in _EXPORT_RULE_IDS:
            return None

        entity = _dataset_entity_key(incoming)
        if not entity:
            return None

        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)

        # Find prior access or sensitive-column alerts from same entity
        preceding_access = [
            h for h in history
            if h.alert_id != incoming.alert_id
            and h.rule_id in _ACCESS_RULE_IDS
            and cutoff <= h.timestamp <= incoming.timestamp
            and _dataset_entity_key(h) == entity
        ]

        if not preceding_access:
            return None

        all_alerts = list(preceding_access) + [incoming]
        all_alert_ids = sorted({a.alert_id for a in all_alerts})
        all_event_ids = sorted({a.event_id for a in all_alerts})
        alert_count = len(all_alert_ids)

        severity = min(15, 12 + (alert_count - 2))

        dataset_name = incoming.evidence.get("dataset_name", incoming.evidence.get("dataset_id", "unknown"))

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Data Exfiltration Sequence: {entity}",
            description=(
                f"Dataset access sequence detected for {entity}: {len(preceding_access)} access alert(s) "
                f"followed by export of '{dataset_name}' within {self.window_seconds // 60} minutes."
            ),
            severity=severity,
            mitre_techniques=["T1530", "T1567"],
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "alert_count": alert_count,
                "dataset_name": dataset_name,
                "access_alert_count": len(preceding_access),
                "rule_type": self.correlation_type,
                "time_window_seconds": self.window_seconds,
            },
        )


class AccessAnomalySequenceRule(CorrelationRule):
    """Correlate unusual actor + sensitive-column access + bulk access.

    Pattern:
      dataset-004 (unusual actor) + (dataset-001 OR dataset-002)
      from the same user within the window.
    """

    def __init__(self, window_seconds: int = 900):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-dset-002"

    @property
    def rule_name(self) -> str:
        return "Privilege and Access Anomaly Sequence"

    @property
    def correlation_type(self) -> str:
        return "access_anomaly_sequence"

    @property
    def description(self) -> str:
        return (
            "Detects an unusual actor accessing sensitive or bulk dataset contents, "
            "suggesting privilege abuse or unauthorized access."
        )

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        # Trigger when incoming is a bulk/sensitive-col alert
        if incoming.rule_id not in _ACCESS_RULE_IDS:
            return None

        entity = _dataset_entity_key(incoming)
        if not entity:
            return None

        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)

        # Find unusual-actor alerts for same entity
        unusual_actor_alerts = [
            h for h in history
            if h.alert_id != incoming.alert_id
            and h.rule_id in _UNUSUAL_RULE_IDS
            and cutoff <= h.timestamp <= incoming.timestamp
            and _dataset_entity_key(h) == entity
        ]

        if not unusual_actor_alerts:
            return None

        all_alerts = unusual_actor_alerts + [incoming]
        all_alert_ids = sorted({a.alert_id for a in all_alerts})
        all_event_ids = sorted({a.event_id for a in all_alerts})

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Access Anomaly Sequence: {entity}",
            description=(
                f"Unusual actor {entity} performed sensitive or bulk dataset access "
                f"within {self.window_seconds // 60} minutes of anomalous actor detection."
            ),
            severity=11,
            mitre_techniques=["T1530"],
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "alert_count": len(all_alerts),
                "unusual_actor_alerts": len(unusual_actor_alerts),
                "rule_type": self.correlation_type,
                "time_window_seconds": self.window_seconds,
            },
        )


class MassModificationSequenceRule(CorrelationRule):
    """Correlate mass dataset modification with schema changes.

    Pattern:
      dataset-005 (mass modify) + dataset-006 (schema change)
      for the same dataset within the window.
    """

    def __init__(self, window_seconds: int = 3600):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-dset-003"

    @property
    def rule_name(self) -> str:
        return "Mass Modification and Schema Change Sequence"

    @property
    def correlation_type(self) -> str:
        return "mass_modification_sequence"

    @property
    def description(self) -> str:
        return (
            "Detects large-volume dataset modification combined with schema changes, "
            "suggesting data tampering or destructive action."
        )

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        # Trigger when incoming is schema change
        if incoming.rule_id not in _SCHEMA_RULE_IDS:
            return None

        dataset_id = incoming.evidence.get("dataset_id")
        if not dataset_id:
            return None

        entity = f"dataset:{dataset_id}"
        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)

        mass_modify_alerts = [
            h for h in history
            if h.alert_id != incoming.alert_id
            and h.rule_id in _MODIFY_RULE_IDS
            and cutoff <= h.timestamp <= incoming.timestamp
            and h.evidence.get("dataset_id") == dataset_id
        ]

        if not mass_modify_alerts:
            return None

        all_alerts = mass_modify_alerts + [incoming]
        all_alert_ids = sorted({a.alert_id for a in all_alerts})
        all_event_ids = sorted({a.event_id for a in all_alerts})

        dataset_name = incoming.evidence.get("dataset_name", dataset_id)

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Mass Modification Sequence: {dataset_name}",
            description=(
                f"Dataset '{dataset_name}' experienced mass record modification followed by "
                f"schema change within {self.window_seconds // 60} minutes."
            ),
            severity=12,
            mitre_techniques=["T1485"],
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "dataset_id": dataset_id,
                "dataset_name": dataset_name,
                "alert_count": len(all_alerts),
                "rule_type": self.correlation_type,
                "time_window_seconds": self.window_seconds,
            },
        )


def get_default_dataset_correlation_rules() -> list:
    """Return the default dataset security correlation rule set."""
    return [
        DataExfiltrationSequenceRule(),
        AccessAnomalySequenceRule(),
        MassModificationSequenceRule(),
    ]
