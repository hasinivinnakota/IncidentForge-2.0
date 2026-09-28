"""Built-in deterministic Dataset Security detection rules.

Each rule evaluates a single NormalizedEvent with source="dataset_activity"
and returns a DetectionMatch on hit or None on miss.

Rule IDs: dataset-001 through dataset-006

MITRE ATT&CK mappings are applied only where genuinely appropriate:
- T1530: Data from Cloud Storage / File Repositories (bulk access, export)
- T1567: Exfiltration Over Web Service (export with destination)
- T1485: Data Destruction (deletion of records)
- T1098: Account Manipulation (schema change affecting access control)
"""

from ..models.events import NormalizedEvent
from ..models.rules import DetectionMatch, DetectionRule

_DATASET_SOURCE = "dataset_activity"

# Operations that indicate bulk or export risk
_BULK_EVENT_TYPES = frozenset((
    "dataset_bulk_access",
    "bulk_access",
))

_EXPORT_EVENT_TYPES = frozenset((
    "dataset_exported",
    "dataset_export",
))

_MODIFY_EVENT_TYPES = frozenset((
    "dataset_modified",
    "dataset_modify",
))

_DELETE_EVENT_TYPES = frozenset((
    "dataset_deleted",
    "dataset_delete",
))

_SCHEMA_EVENT_TYPES = frozenset((
    "dataset_schema_changed",
    "schema_changed",
))

# Thresholds
BULK_RECORD_THRESHOLD = 10_000
MASS_MODIFY_THRESHOLD = 5_000


class BulkSensitiveDatasetAccessRule(DetectionRule):
    """Fires on bulk dataset access events exceeding record threshold or with sensitive columns.

    Rule: dataset-001
    """

    @property
    def rule_id(self) -> str:
        return "dataset-001"

    @property
    def rule_name(self) -> str:
        return "Bulk Sensitive Dataset Access"

    @property
    def description(self) -> str:
        return (
            "Detects bulk dataset reads accessing a large record volume "
            f"(>= {BULK_RECORD_THRESHOLD}) or flagged as bulk_access operation."
        )

    @property
    def severity(self) -> int:
        return 8

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1530"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.source != _DATASET_SOURCE:
            return None
        is_bulk_op = event.event_type in _BULK_EVENT_TYPES
        records = int(event.metadata.get("records_accessed", 0))
        above_threshold = records >= BULK_RECORD_THRESHOLD

        if not (is_bulk_op or above_threshold):
            return None

        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "dataset_id": event.metadata.get("dataset_id"),
                "dataset_name": event.metadata.get("dataset_name"),
                "records_accessed": records,
                "bulk_threshold": BULK_RECORD_THRESHOLD,
                "is_bulk_op": is_bulk_op,
                "actor": event.user,
                "host": event.host,
            },
        )


class SensitiveColumnAccessRule(DetectionRule):
    """Fires when an event accesses one or more sensitive columns.

    Rule: dataset-002
    """

    @property
    def rule_id(self) -> str:
        return "dataset-002"

    @property
    def rule_name(self) -> str:
        return "Sensitive Column Access"

    @property
    def description(self) -> str:
        return "Detects dataset access events that touch sensitive or PII-tagged columns."

    @property
    def severity(self) -> int:
        return 9

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1530"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.source != _DATASET_SOURCE:
            return None
        sensitive_cols = event.metadata.get("sensitive_columns", [])
        if not sensitive_cols or not isinstance(sensitive_cols, list) or len(sensitive_cols) == 0:
            # Also check event type explicitly
            if event.event_type != "sensitive_column_access":
                return None

        sensitivity = str(event.metadata.get("sensitivity", "LOW")).upper()

        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "dataset_id": event.metadata.get("dataset_id"),
                "dataset_name": event.metadata.get("dataset_name"),
                "sensitive_columns": sensitive_cols,
                "sensitive_column_count": len(sensitive_cols),
                "dataset_sensitivity": sensitivity,
                "actor": event.user,
                "host": event.host,
            },
        )


class SuspiciousDatasetExportRule(DetectionRule):
    """Fires on dataset export events, especially those with an external destination.

    Rule: dataset-003
    """

    @property
    def rule_id(self) -> str:
        return "dataset-003"

    @property
    def rule_name(self) -> str:
        return "Suspicious Dataset Export"

    @property
    def description(self) -> str:
        return "Detects dataset export operations that may represent data staging or exfiltration."

    @property
    def severity(self) -> int:
        return 10

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1567"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.source != _DATASET_SOURCE:
            return None
        is_export = event.event_type in _EXPORT_EVENT_TYPES
        has_destination = bool(event.metadata.get("export_destination"))
        has_dest_ip = bool(event.destination_ip)

        if not (is_export or has_destination or has_dest_ip):
            return None

        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "dataset_id": event.metadata.get("dataset_id"),
                "dataset_name": event.metadata.get("dataset_name"),
                "export_destination": event.metadata.get("export_destination"),
                "export_size_bytes": event.metadata.get("export_size_bytes", 0),
                "records_accessed": event.metadata.get("records_accessed", 0),
                "destination_ip": event.destination_ip,
                "actor": event.user,
            },
        )


class UnusualDatasetActorRule(DetectionRule):
    """Fires when the actor accessing the dataset is flagged as unusual/new.

    Rule: dataset-004

    Note: The initial implementation detects actors from atypical source IPs
    or with 'unknown' / test-like identifiers. Future versions can integrate
    actor baseline models.
    """

    _SUSPICIOUS_ACTOR_PATTERNS = ("anonymous", "unknown", "test_", "debug_", "tmp_")

    @property
    def rule_id(self) -> str:
        return "dataset-004"

    @property
    def rule_name(self) -> str:
        return "Unusual or New Dataset Actor"

    @property
    def description(self) -> str:
        return (
            "Detects dataset access from actors with unusual identifiers or "
            "source IPs that look atypical (e.g., external, loopback, test accounts)."
        )

    @property
    def severity(self) -> int:
        return 7

    @property
    def mitre_techniques(self) -> list[str]:
        # No strongly appropriate ATT&CK mapping - omitted rather than forced
        return []

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.source != _DATASET_SOURCE:
            return None

        actor = (event.user or "").lower()
        is_unusual_actor = any(p in actor for p in self._SUSPICIOUS_ACTOR_PATTERNS)

        # Flag external source IPs (non-RFC1918 private ranges) as unusual
        is_external_ip = False
        src_ip = event.source_ip or ""
        if src_ip and not (
            src_ip.startswith("10.")
            or src_ip.startswith("192.168.")
            or src_ip.startswith("172.")
            or src_ip.startswith("127.")
            or src_ip == ""
        ):
            is_external_ip = True

        if not (is_unusual_actor or is_external_ip):
            return None

        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "dataset_id": event.metadata.get("dataset_id"),
                "actor": event.user,
                "source_ip": src_ip,
                "is_unusual_actor": is_unusual_actor,
                "is_external_ip": is_external_ip,
            },
        )


class MassDatasetModificationRule(DetectionRule):
    """Fires on large-volume dataset modification or deletion events.

    Rule: dataset-005
    """

    @property
    def rule_id(self) -> str:
        return "dataset-005"

    @property
    def rule_name(self) -> str:
        return "Mass Dataset Modification"

    @property
    def description(self) -> str:
        return (
            f"Detects bulk modification or deletion of dataset records "
            f"(>= {MASS_MODIFY_THRESHOLD} records affected)."
        )

    @property
    def severity(self) -> int:
        return 11

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1485"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.source != _DATASET_SOURCE:
            return None

        is_modify = event.event_type in _MODIFY_EVENT_TYPES or event.event_type in _DELETE_EVENT_TYPES
        if not is_modify:
            return None

        records_modified = int(event.metadata.get("records_modified", 0))
        records_accessed = int(event.metadata.get("records_accessed", 0))
        volume = max(records_modified, records_accessed)

        if volume < MASS_MODIFY_THRESHOLD:
            return None

        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "dataset_id": event.metadata.get("dataset_id"),
                "dataset_name": event.metadata.get("dataset_name"),
                "records_modified": records_modified,
                "records_accessed": records_accessed,
                "operation": event.event_type,
                "actor": event.user,
                "threshold": MASS_MODIFY_THRESHOLD,
            },
        )


class UnexpectedSchemaChangeRule(DetectionRule):
    """Fires on schema change events for any tracked dataset.

    Rule: dataset-006
    """

    @property
    def rule_id(self) -> str:
        return "dataset-006"

    @property
    def rule_name(self) -> str:
        return "Unexpected Dataset Schema Change"

    @property
    def description(self) -> str:
        return "Detects schema changes to tracked datasets, which may indicate tampering or unauthorized modification."

    @property
    def severity(self) -> int:
        return 8

    @property
    def mitre_techniques(self) -> list[str]:
        # Schema changes can relate to access control manipulation
        return ["T1098"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.source != _DATASET_SOURCE:
            return None
        if event.event_type not in _SCHEMA_EVENT_TYPES:
            return None

        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "dataset_id": event.metadata.get("dataset_id"),
                "dataset_name": event.metadata.get("dataset_name"),
                "actor": event.user,
                "host": event.host,
                "event_type": event.event_type,
            },
        )
