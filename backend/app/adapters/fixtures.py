"""Deterministic development/test telemetry adapter."""

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from .base import TelemetryAdapter


class FixtureAdapter(TelemetryAdapter):
    def get_events(self) -> Sequence[Mapping[str, Any]]:
        return [
            {
                "event_id": "fixture-event-001",
                "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "source": "fixture",
                "event_type": "process_start",
                "severity": 3,
                "message": "Example process-start event",
                "host": "fixture-host",
                "metadata": {"fixture": True},
            },
            {
                "event_id": "fixture-event-002",
                "timestamp": datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
                "source": "fixture",
                "event_type": "process_start",
                "severity": 12,
                "message": "Suspicious execution /tmp/malicious.sh",
                "host": "workstation-01",
                "metadata": {"fixture": True},
            },
            {
                "event_id": "fixture-event-003",
                "timestamp": datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc),
                "source": "fixture",
                "event_type": "authentication_failure",
                "severity": 6,
                "message": "Failed login attempt for user admin",
                "user": "admin",
                "source_ip": "192.168.1.100",
                "host": "auth-server",
                "metadata": {"fixture": True},
            },
            {
                "event_id": "fixture-event-004",
                "timestamp": datetime(2026, 1, 1, 0, 3, tzinfo=timezone.utc),
                "source": "fixture",
                "event_type": "network_connection",
                "severity": 4,
                "message": "Outbound connection to external IP",
                "source_ip": "10.0.0.5",
                "destination_ip": "203.0.113.50",
                "host": "workstation-01",
                "metadata": {"fixture": True},
            },
            {
                "event_id": "fixture-event-005",
                "timestamp": datetime(2026, 1, 1, 0, 4, tzinfo=timezone.utc),
                "source": "fixture",
                "event_type": "privilege_escalation",
                "severity": 12,
                "message": "Privilege escalation attempted via sudo exploit",
                "user": "testuser",
                "host": "server-01",
                "metadata": {"fixture": True},
            },
            {
                "event_id": "fixture-event-006",
                "timestamp": datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
                "source": "fixture",
                "event_type": "file_read",
                "severity": 2,
                "message": "Read /etc/hosts",
                "host": "server-01",
                "metadata": {"fixture": True},
            },
        ]