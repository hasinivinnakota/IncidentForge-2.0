"""Built-in deterministic correlation rules."""

from collections.abc import Sequence
from datetime import timedelta

from ..models.correlation import CorrelatableAlert, CorrelationMatch
from .correlation_base import CorrelationRule


class AuthenticationAttackSequenceRule(CorrelationRule):
    """Correlate multiple authentication failures from the same source/entity within a bounded time window."""

    def __init__(self, window_seconds: int = 900):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-rule-001"

    @property
    def rule_name(self) -> str:
        return "Authentication Attack Sequence"

    @property
    def correlation_type(self) -> str:
        return "auth_attack_sequence"

    @property
    def description(self) -> str:
        return "Detects multiple authentication failure alerts targeting or originating from the same entity within a bounded window."

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def _entity_key(self, alert: CorrelatableAlert) -> str | None:
        if alert.user:
            return f"user:{alert.user}"
        if alert.source_ip:
            return f"source_ip:{alert.source_ip}"
        if alert.host:
            return f"host:{alert.host}"
        return None

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        if incoming.rule_id != "builtin-003":
            return None

        entity = self._entity_key(incoming)
        if not entity:
            return None

        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)
        matching_history = [
            h
            for h in history
            if h.alert_id != incoming.alert_id
            and h.rule_id == "builtin-003"
            and self._entity_key(h) == entity
            and cutoff <= h.timestamp <= incoming.timestamp + timedelta(seconds=self._window_seconds)
        ]

        if not matching_history:
            return None

        all_alerts = list(matching_history) + [incoming]
        all_alert_ids = sorted(list({a.alert_id for a in all_alerts}))
        all_event_ids = sorted(list({a.event_id for a in all_alerts}))
        alert_count = len(all_alert_ids)

        severity = min(15, 8 + (alert_count - 2) * 2)

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Authentication Attack Sequence against {entity}",
            description=(
                f"Multiple authentication failure alerts ({alert_count}) observed for "
                f"{entity} within {self.window_seconds // 60} minutes."
            ),
            severity=severity,
            mitre_techniques=["T1110"],
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "alert_count": alert_count,
                "rule_type": self.correlation_type,
                "time_window_seconds": self.window_seconds,
            },
        )


class ProcessNetworkSequenceRule(CorrelationRule):
    """Correlate a suspicious process execution followed by a network connection on the same host."""

    def __init__(self, window_seconds: int = 1800):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-rule-002"

    @property
    def rule_name(self) -> str:
        return "Suspicious Process Followed by Network Connection"

    @property
    def correlation_type(self) -> str:
        return "process_network_sequence"

    @property
    def description(self) -> str:
        return "Detects a suspicious process execution followed by a related network connection on the same host."

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        if incoming.rule_id not in ("builtin-002", "builtin-004"):
            return None
        if not incoming.host:
            return None

        entity = f"host:{incoming.host}"
        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)

        target_rule = "builtin-002" if incoming.rule_id == "builtin-004" else "builtin-004"
        matching_history = [
            h
            for h in history
            if h.alert_id != incoming.alert_id
            and h.rule_id == target_rule
            and h.host == incoming.host
            and cutoff <= h.timestamp <= incoming.timestamp + timedelta(seconds=self._window_seconds)
        ]

        if not matching_history:
            return None

        all_alerts = list(matching_history) + [incoming]
        all_alert_ids = sorted(list({a.alert_id for a in all_alerts}))
        all_event_ids = sorted(list({a.event_id for a in all_alerts}))

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Suspicious Process and Network Connection on {entity}",
            description=(
                f"Suspicious process execution followed by network connection observed on "
                f"{entity} within {self.window_seconds // 60} minutes."
            ),
            severity=12,
            mitre_techniques=["T1059", "T1071"],
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "host": incoming.host,
                "rules_correlated": ["builtin-002", "builtin-004"],
                "time_window_seconds": self.window_seconds,
            },
        )


class PrivilegeEscalationSequenceRule(CorrelationRule):
    """Correlate authentication/process activity with a privilege escalation indicator on the same entity."""

    def __init__(self, window_seconds: int = 1800):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-rule-003"

    @property
    def rule_name(self) -> str:
        return "Privilege Escalation Sequence"

    @property
    def correlation_type(self) -> str:
        return "privilege_escalation_sequence"

    @property
    def description(self) -> str:
        return "Detects privilege escalation activity correlated with preceding suspicious process or authentication alerts."

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def _entity_key(self, alert: CorrelatableAlert) -> str | None:
        if alert.user:
            return f"user:{alert.user}"
        if alert.host:
            return f"host:{alert.host}"
        return None

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        if incoming.rule_id not in ("builtin-005", "builtin-002", "builtin-003"):
            return None

        entity = self._entity_key(incoming)
        if not entity:
            return None

        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)

        if incoming.rule_id == "builtin-005":
            target_rules = ("builtin-002", "builtin-003")
        else:
            target_rules = ("builtin-005",)

        matching_history = [
            h
            for h in history
            if h.alert_id != incoming.alert_id
            and h.rule_id in target_rules
            and self._entity_key(h) == entity
            and cutoff <= h.timestamp <= incoming.timestamp + timedelta(seconds=self._window_seconds)
        ]

        if not matching_history:
            return None

        all_alerts = list(matching_history) + [incoming]
        all_alert_ids = sorted(list({a.alert_id for a in all_alerts}))
        all_event_ids = sorted(list({a.event_id for a in all_alerts}))
        mitre = sorted(list({m for a in all_alerts for m in a.mitre_techniques} | {"T1548"}))

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Privilege Escalation Sequence on {entity}",
            description=(
                f"Privilege escalation activity correlated with suspicious process or authentication event "
                f"on {entity} within {self.window_seconds // 60} minutes."
            ),
            severity=14,
            mitre_techniques=mitre,
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "rules_correlated": sorted(list({a.rule_id for a in all_alerts})),
                "time_window_seconds": self.window_seconds,
            },
        )


class SameEntityCorrelationRule(CorrelationRule):
    """Correlate multiple alerts sharing the same entity that are not part of a specialized sequence."""

    def __init__(self, window_seconds: int = 1800):
        self._window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "corr-rule-004"

    @property
    def rule_name(self) -> str:
        return "Multiple Security Alerts on Same Entity"

    @property
    def correlation_type(self) -> str:
        return "same_entity"

    @property
    def description(self) -> str:
        return "Correlates multiple distinct security alerts occurring on the same host or user within a bounded window."

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def _entity_key(self, alert: CorrelatableAlert) -> str | None:
        if alert.host:
            return f"host:{alert.host}"
        if alert.user:
            return f"user:{alert.user}"
        return None

    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        entity = self._entity_key(incoming)
        if not entity:
            return None

        cutoff = incoming.timestamp - timedelta(seconds=self._window_seconds)

        # Look for historical alerts on the same entity with a different rule_id
        # Skip pairs already handled by specialized sequences (builtin-002 + builtin-004, builtin-005 + builtin-002/003)
        excluded_pairs = {
            frozenset({"builtin-002", "builtin-004"}),
            frozenset({"builtin-005", "builtin-002"}),
            frozenset({"builtin-005", "builtin-003"}),
        }

        matching_history = [
            h
            for h in history
            if h.alert_id != incoming.alert_id
            and self._entity_key(h) == entity
            and h.rule_id != incoming.rule_id
            and frozenset({incoming.rule_id, h.rule_id}) not in excluded_pairs
            and cutoff <= h.timestamp <= incoming.timestamp + timedelta(seconds=self._window_seconds)
        ]

        if not matching_history:
            return None

        all_alerts = list(matching_history) + [incoming]
        all_alert_ids = sorted(list({a.alert_id for a in all_alerts}))
        all_event_ids = sorted(list({a.event_id for a in all_alerts}))
        mitre = sorted(list({m for a in all_alerts for m in a.mitre_techniques}))
        max_severity = max(a.severity for a in all_alerts)

        return CorrelationMatch(
            rule_id=self.rule_id,
            correlation_type=self.correlation_type,
            entity_key=entity,
            title=f"Multiple Security Alerts on {entity}",
            description=(
                f"Multiple distinct security alerts ({len(all_alert_ids)}) observed on "
                f"{entity} within {self.window_seconds // 60} minutes."
            ),
            severity=max_severity,
            mitre_techniques=mitre,
            matched_alert_ids=all_alert_ids,
            matched_event_ids=all_event_ids,
            evidence={
                "entity_key": entity,
                "distinct_rules": sorted(list({a.rule_id for a in all_alerts})),
                "alert_count": len(all_alert_ids),
                "time_window_seconds": self.window_seconds,
            },
        )


def get_default_correlation_rules() -> list[CorrelationRule]:
    """Return the standard built-in correlation rule set."""
    return [
        AuthenticationAttackSequenceRule(),
        ProcessNetworkSequenceRule(),
        PrivilegeEscalationSequenceRule(),
        SameEntityCorrelationRule(),
    ]
