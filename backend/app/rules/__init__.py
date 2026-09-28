"""Built-in detection rule registry (endpoint + dataset security)."""

from ..models.rules import DetectionRule
from .builtin import (
    AuthenticationFailureRule,
    HighSeverityRule,
    NetworkConnectionAnomalyRule,
    PrivilegeEscalationRule,
    SuspiciousProcessRule,
)
from .correlation_base import CorrelationRule
from .correlation_builtin import (
    AuthenticationAttackSequenceRule,
    PrivilegeEscalationSequenceRule,
    ProcessNetworkSequenceRule,
    SameEntityCorrelationRule,
    get_default_correlation_rules,
)
from .dataset_builtin import (
    BulkSensitiveDatasetAccessRule,
    MassDatasetModificationRule,
    SensitiveColumnAccessRule,
    SuspiciousDatasetExportRule,
    UnexpectedSchemaChangeRule,
    UnusualDatasetActorRule,
)
from .dataset_correlation import (
    AccessAnomalySequenceRule,
    DataExfiltrationSequenceRule,
    MassModificationSequenceRule,
    get_default_dataset_correlation_rules,
)


def get_default_rules() -> list[DetectionRule]:
    """Return the full built-in rule set: endpoint + dataset security."""
    return [
        # Endpoint / host rules (v1 - unchanged)
        HighSeverityRule(),
        SuspiciousProcessRule(),
        AuthenticationFailureRule(),
        NetworkConnectionAnomalyRule(),
        PrivilegeEscalationRule(),
        # Dataset security rules (v2)
        BulkSensitiveDatasetAccessRule(),
        SensitiveColumnAccessRule(),
        SuspiciousDatasetExportRule(),
        UnusualDatasetActorRule(),
        MassDatasetModificationRule(),
        UnexpectedSchemaChangeRule(),
    ]


def get_all_correlation_rules() -> list[CorrelationRule]:
    """Return all correlation rules: endpoint + dataset security."""
    return get_default_correlation_rules() + get_default_dataset_correlation_rules()


__all__ = [
    "AccessAnomalySequenceRule",
    "AuthenticationAttackSequenceRule",
    "AuthenticationFailureRule",
    "BulkSensitiveDatasetAccessRule",
    "CorrelationRule",
    "DataExfiltrationSequenceRule",
    "HighSeverityRule",
    "MassDatasetModificationRule",
    "MassModificationSequenceRule",
    "NetworkConnectionAnomalyRule",
    "PrivilegeEscalationRule",
    "PrivilegeEscalationSequenceRule",
    "ProcessNetworkSequenceRule",
    "SameEntityCorrelationRule",
    "SensitiveColumnAccessRule",
    "SuspiciousDatasetExportRule",
    "SuspiciousProcessRule",
    "UnexpectedSchemaChangeRule",
    "UnusualDatasetActorRule",
    "get_all_correlation_rules",
    "get_default_correlation_rules",
    "get_default_dataset_correlation_rules",
    "get_default_rules",
]
