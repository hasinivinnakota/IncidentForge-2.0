"""Built-in deterministic detection rules.

Each rule implements the DetectionRule ABC and evaluates a single
NormalizedEvent, returning a DetectionMatch on hit or None on miss.
"""

from ..models.events import NormalizedEvent
from ..models.rules import DetectionMatch, DetectionRule

_SUSPICIOUS_PATH_INDICATORS = (
    "/tmp/",
    "\\temp\\",
    "powershell -enc",
    "cmd.exe /c",
    "cmd /c",
    "/dev/shm/",
)

_PRIVILEGE_EVENT_TYPES = frozenset((
    "privilege_escalation",
    "runas",
    "sudo",
))

_AUTH_FAILURE_EVENT_TYPES = frozenset((
    "authentication_failure",
    "login_failure",
))


class HighSeverityRule(DetectionRule):
    """Fires when an event has severity >= 10."""

    @property
    def rule_id(self) -> str:
        return "builtin-001"

    @property
    def rule_name(self) -> str:
        return "High Severity Event"

    @property
    def description(self) -> str:
        return "Detects events with severity at or above the high-severity threshold (10)."

    @property
    def severity(self) -> int:
        return 10

    @property
    def mitre_techniques(self) -> list[str]:
        return []

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.severity < 10:
            return None
        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=event.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "matched_field": "severity",
                "matched_value": event.severity,
                "threshold": 10,
            },
        )


class SuspiciousProcessRule(DetectionRule):
    """Fires on process_start events whose message contains suspicious path indicators."""

    @property
    def rule_id(self) -> str:
        return "builtin-002"

    @property
    def rule_name(self) -> str:
        return "Suspicious Process Execution"

    @property
    def description(self) -> str:
        return "Detects process-start events referencing suspicious paths or encoded commands."

    @property
    def severity(self) -> int:
        return 10

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1059"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.event_type != "process_start":
            return None
        message_lower = event.message.lower()
        matched_indicators = [
            indicator for indicator in _SUSPICIOUS_PATH_INDICATORS
            if indicator.lower() in message_lower
        ]
        if not matched_indicators:
            return None
        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "matched_field": "message",
                "event_type": event.event_type,
                "indicators_matched": matched_indicators,
                "host": event.host,
            },
        )


class AuthenticationFailureRule(DetectionRule):
    """Fires on authentication or login failure events."""

    @property
    def rule_id(self) -> str:
        return "builtin-003"

    @property
    def rule_name(self) -> str:
        return "Authentication Failure"

    @property
    def description(self) -> str:
        return "Detects authentication or login failure events."

    @property
    def severity(self) -> int:
        return 6

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1110"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.event_type not in _AUTH_FAILURE_EVENT_TYPES:
            return None
        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "matched_field": "event_type",
                "event_type": event.event_type,
                "user": event.user,
                "source_ip": event.source_ip,
                "host": event.host,
            },
        )


class NetworkConnectionAnomalyRule(DetectionRule):
    """Fires on network_connection events that include a destination IP."""

    @property
    def rule_id(self) -> str:
        return "builtin-004"

    @property
    def rule_name(self) -> str:
        return "Network Connection Anomaly"

    @property
    def description(self) -> str:
        return "Detects network connection events with a recorded destination address."

    @property
    def severity(self) -> int:
        return 6

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1071"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        if event.event_type != "network_connection":
            return None
        if not event.destination_ip:
            return None
        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "matched_field": "event_type",
                "event_type": event.event_type,
                "destination_ip": event.destination_ip,
                "source_ip": event.source_ip,
                "host": event.host,
            },
        )


class PrivilegeEscalationRule(DetectionRule):
    """Fires on privilege-escalation-related events or messages mentioning privilege."""

    @property
    def rule_id(self) -> str:
        return "builtin-005"

    @property
    def rule_name(self) -> str:
        return "Privilege Escalation Indicator"

    @property
    def description(self) -> str:
        return "Detects events indicating potential privilege escalation activity."

    @property
    def severity(self) -> int:
        return 12

    @property
    def mitre_techniques(self) -> list[str]:
        return ["T1548"]

    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        type_match = event.event_type in _PRIVILEGE_EVENT_TYPES
        message_match = "privilege" in event.message.lower()
        if not (type_match or message_match):
            return None
        return DetectionMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            event_id=event.event_id,
            severity=self.severity,
            description=self.description,
            mitre_techniques=self.mitre_techniques,
            evidence={
                "matched_field": "event_type" if type_match else "message",
                "event_type": event.event_type,
                "type_match": type_match,
                "message_match": message_match,
                "user": event.user,
                "host": event.host,
            },
        )
