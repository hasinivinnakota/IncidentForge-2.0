"""Wazuh alert telemetry adapter.

Translates Wazuh alert JSON structures (such as records from alerts.json or
Wazuh Manager APIs) into IncidentForge source mappings and canonical
NormalizedEvent objects, bypassing the Filebeat `_type` -> OpenSearch limitation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any

from .base import TelemetryAdapter
from ..models.events import NormalizedEvent
from ..services.normalization import NormalizationService

logger = logging.getLogger(__name__)

# Patterns for redacting sensitive authentication parameters or credentials
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
    """Sanitize strings or nested dicts/lists to redact credentials and bounded length."""
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


class WazuhAlertAdapter(TelemetryAdapter):
    """Adapter that reads Wazuh alert JSON payloads and maps them to IncidentForge events.

    Guarantees:
    - Pure data transformation: never executes shell, commands, or response actions.
    - Preserves deterministic idempotency using Wazuh alert id (`wazuh-alert-<id>`).
    - Redacts credentials/tokens in payload metadata and messages.
    - Bridges rule IDs, rule levels, agent host, MITRE techniques, source/dest IPs, users.
    - Integrates cleanly with NormalizationService.
    """

    def __init__(
        self,
        raw_alerts: Sequence[Mapping[str, Any] | str] | None = None,
        normalizer: NormalizationService | None = None,
    ):
        self._raw_alerts: list[dict[str, Any]] = []
        self._normalizer = normalizer or NormalizationService()

        if raw_alerts:
            for item in raw_alerts:
                self.add_raw_alert(item)

    def add_raw_alert(self, alert_input: Mapping[str, Any] | str) -> None:
        """Add a raw Wazuh alert dict or JSON line to the adapter buffer."""
        if isinstance(alert_input, str):
            line = alert_input.strip()
            if not line:
                return
            parsed = json.loads(line)
        else:
            parsed = dict(alert_input)
        self._raw_alerts.append(parsed)

    def clear(self) -> None:
        """Clear current buffer."""
        self._raw_alerts.clear()

    @staticmethod
    def map_wazuh_level_to_severity(level: int | float | None) -> int:
        """Map Wazuh rule level (typically 0-16) to IncidentForge canonical severity (0-15).

        Wazuh rules range from 0 to 16:
        - Levels 0-3: informational / low
        - Levels 4-7: low/medium (e.g. auth failure level 5-6)
        - Levels 8-11: high
        - Levels 12-16: critical
        """
        if level is None:
            return 3
        try:
            lvl = int(level)
        except (ValueError, TypeError):
            return 3

        if lvl >= 12:
            return 12  # critical (IncidentForge considers >= 12 critical)
        if lvl >= 8:
            return 10  # high
        if lvl >= 4:
            return 6   # medium
        return 3       # low

    @staticmethod
    def extract_event_type(rule: dict[str, Any], data: dict[str, Any]) -> str:
        """Determine canonical event_type from Wazuh rule groups or Sysmon data."""
        groups = [str(g).lower() for g in rule.get("groups", [])]

        if "authentication_failed" in groups or "authentication_failure" in groups or "invalid_login" in groups:
            return "authentication_failure"
        if "authentication_success" in groups:
            return "authentication_success"
        if "privilege_escalation" in groups or "sudo" in groups:
            return "privilege_escalation"
        if "network" in groups or "firewall" in groups:
            return "network_connection"
        if "process" in groups or "sysmon_process" in groups:
            return "process_start"
        if "file" in groups:
            return "file_read"

        # Check Sysmon event id inside data.win.system.eventID or data.audit
        win_sys = data.get("win", {}).get("system", {})
        win_event_id = str(win_sys.get("eventID", ""))
        if win_event_id == "1":
            return "process_start"
        if win_event_id == "3":
            return "network_connection"
        if win_event_id in ("4625", "4776"):
            return "authentication_failure"

        # Fallback to general alert
        return "wazuh_alert"

    def transform_wazuh_alert(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        """Convert a single raw Wazuh alert record into an IncidentForge source event mapping."""
        # 1. Deterministic event ID
        raw_id = alert.get("id") or alert.get("_id")
        if raw_id:
            event_id = f"wazuh-alert-{raw_id}"
        else:
            # Hash timestamp + rule_id as fallback
            ts = alert.get("timestamp", "")
            rid = alert.get("rule", {}).get("id", "0")
            event_id = f"wazuh-synth-{hash(f'{ts}:{rid}') & 0xffffffff:08x}"

        # 2. Timestamp
        timestamp_str = alert.get("timestamp")
        if not timestamp_str:
            timestamp_str = datetime.now(timezone.utc).isoformat()

        # 3. Rule details
        rule = alert.get("rule") or {}
        rule_id = str(rule.get("id", ""))
        rule_desc = rule.get("description", "Wazuh security alert")
        rule_level = rule.get("level")
        severity = self.map_wazuh_level_to_severity(rule_level)

        # 4. Agent information
        agent = alert.get("agent") or {}
        host = agent.get("name") or agent.get("hostname") or alert.get("host")

        # 5. Extract Entities (Data payload)
        data = alert.get("data") or {}
        src_ip = (
            alert.get("srcip")
            or data.get("srcip")
            or data.get("source_ip")
            or data.get("win", {}).get("eventdata", {}).get("ipAddress")
        )
        dst_ip = (
            alert.get("dstip")
            or data.get("dstip")
            or data.get("destination_ip")
            or data.get("win", {}).get("eventdata", {}).get("destinationIp")
        )
        user = (
            alert.get("dstuser")
            or alert.get("srcuser")
            or data.get("dstuser")
            or data.get("srcuser")
            or data.get("win", {}).get("eventdata", {}).get("targetUserName")
        )

        event_type = self.extract_event_type(rule, data)

        # 6. MITRE Techniques
        mitre = rule.get("mitre") or {}
        mitre_ids = mitre.get("id", [])
        if isinstance(mitre_ids, str):
            mitre_techniques = [mitre_ids]
        elif isinstance(mitre_ids, list):
            mitre_techniques = [str(m) for m in mitre_ids]
        else:
            mitre_techniques = []

        # 7. Metadata (sanitized)
        metadata: dict[str, Any] = {
            "wazuh_rule_id": rule_id,
            "wazuh_rule_level": rule_level,
            "wazuh_rule_groups": rule.get("groups", []),
            "wazuh_agent_id": agent.get("id"),
            "wazuh_manager_name": alert.get("manager", {}).get("name"),
            "mitre_techniques": mitre_techniques,
        }
        if data:
            metadata["wazuh_data"] = sanitize_value(data)

        # Build clean message
        message = f"[{rule_id}] {rule_desc}"
        if host:
            message += f" (host: {host})"
        if user:
            message += f" (user: {user})"

        return {
            "event_id": event_id,
            "timestamp": timestamp_str,
            "source": "wazuh",
            "event_type": event_type,
            "severity": severity,
            "message": sanitize_value(message),
            "host": sanitize_value(host),
            "user": sanitize_value(user),
            "source_ip": sanitize_value(src_ip),
            "destination_ip": sanitize_value(dst_ip),
            "metadata": metadata,
        }

    def get_events(self) -> Sequence[Mapping[str, Any]]:
        """Return source events without imposing a source-specific schema (TelemetryAdapter contract)."""
        return [self.transform_wazuh_alert(alert) for alert in self._raw_alerts]

    def get_normalized_events(self) -> list[NormalizedEvent]:
        """Convert all buffered Wazuh alerts into canonical IncidentForge NormalizedEvent instances."""
        raw_events = self.get_events()
        return [self._normalizer.normalize(ev) for ev in raw_events]
