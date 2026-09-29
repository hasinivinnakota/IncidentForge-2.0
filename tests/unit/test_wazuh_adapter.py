"""Unit tests for WazuhAlertAdapter and full pipeline integration."""

from datetime import datetime, timezone
import json

import pytest
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from backend.app.adapters import TelemetryAdapter, WazuhAlertAdapter
from backend.app.models.events import NormalizedEvent
from backend.app.persistence.repositories import (
    AlertRepository,
    CorrelationRepository,
    EventRepository,
    IncidentRepository,
    RiskAssessmentRepository,
    ThreatIntelRepository,
)
from backend.app.rules import get_default_correlation_rules, get_default_rules
from backend.app.services.alerts import AlertService
from backend.app.services.correlation import CorrelationEngine
from backend.app.services.detection import DetectionEngine
from backend.app.services.incidents import IncidentService
from backend.app.services.pipeline import EventPipeline
from backend.app.services.processing import EventProcessingService
from backend.app.services.risk import RiskScoringService
from backend.app.services.threat_intel import ThreatIntelligenceService


# Synthetic sample Wazuh alert records
SAMPLE_WAZUH_AUTH_FAIL_1 = {
    "id": "1725974000.12345",
    "timestamp": "2026-09-10T14:00:00.000+0000",
    "rule": {
        "id": "5710",
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["syslog", "sshd", "authentication_failed"],
        "mitre": {"id": ["T1110"]},
    },
    "agent": {"id": "001", "name": "linux-endpoint-01"},
    "manager": {"name": "wazuh-manager"},
    "srcip": "198.51.100.23",
    "dstuser": "sec_analyst_test",
    "data": {
        "srcip": "198.51.100.23",
        "dstuser": "sec_analyst_test",
    },
}

SAMPLE_WAZUH_AUTH_FAIL_2 = {
    "id": "1725974120.67890",
    "timestamp": "2026-09-10T14:02:00.000+0000",
    "rule": {
        "id": "5710",
        "level": 5,
        "description": "sshd: Multiple failed logins",
        "groups": ["syslog", "sshd", "authentication_failure"],
        "mitre": {"id": ["T1110"]},
    },
    "agent": {"id": "001", "name": "linux-endpoint-01"},
    "manager": {"name": "wazuh-manager"},
    "srcip": "198.51.100.23",
    "dstuser": "sec_analyst_test",
    "data": {
        "srcip": "198.51.100.23",
        "dstuser": "sec_analyst_test",
    },
}

SAMPLE_WAZUH_SUSPICIOUS_PROCESS = {
    "id": "1725974200.99999",
    "timestamp": "2026-09-10T14:05:00.000+0000",
    "rule": {
        "id": "92100",
        "level": 12,
        "description": "Suspicious execution in /tmp/ directory",
        "groups": ["sysmon", "sysmon_process"],
        "mitre": {"id": ["T1059"]},
    },
    "agent": {"id": "002", "name": "win-workstation-01"},
    "manager": {"name": "wazuh-manager"},
    "data": {
        "win": {
            "system": {"eventID": "1"},
            "eventdata": {
                "image": "C:\\temp\\malicious.exe",
                "commandLine": "powershell -enc AAAA /tmp/evil.sh",
                "targetUserName": "john_doe",
            },
        },
        "password": "SuperSecretPassword123!",  # Ensure sensitive data is redacted
    },
}


@pytest.fixture
def in_memory_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_wazuh_adapter_conforms_to_contract():
    adapter = WazuhAlertAdapter()
    assert isinstance(adapter, TelemetryAdapter)


def test_wazuh_adapter_mapping():
    adapter = WazuhAlertAdapter([SAMPLE_WAZUH_AUTH_FAIL_1])
    events = adapter.get_events()
    assert len(events) == 1
    event = events[0]

    assert event["event_id"] == "wazuh-alert-1725974000.12345"
    assert event["source"] == "wazuh"
    assert event["event_type"] == "authentication_failure"
    assert event["severity"] == 6  # Wazuh level 5 maps to medium severity (6)
    assert event["host"] == "linux-endpoint-01"
    assert event["user"] == "sec_analyst_test"
    assert event["source_ip"] == "198.51.100.23"
    assert "T1110" in event["metadata"]["mitre_techniques"]
    assert event["metadata"]["wazuh_rule_id"] == "5710"


def test_wazuh_adapter_credential_redaction():
    adapter = WazuhAlertAdapter([SAMPLE_WAZUH_SUSPICIOUS_PROCESS])
    events = adapter.get_events()
    assert len(events) == 1
    event = events[0]

    # Check that sensitive fields are sanitized
    assert event["event_type"] == "process_start"
    wazuh_data = event["metadata"].get("wazuh_data", {})
    assert wazuh_data.get("password") == "[REDACTED]"
    assert "SuperSecretPassword123!" not in str(event)


def test_wazuh_adapter_normalization():
    adapter = WazuhAlertAdapter([SAMPLE_WAZUH_AUTH_FAIL_1])
    normalized_list = adapter.get_normalized_events()
    assert len(normalized_list) == 1
    norm_event = normalized_list[0]

    assert isinstance(norm_event, NormalizedEvent)
    assert norm_event.event_id == "wazuh-alert-1725974000.12345"
    assert norm_event.source == "wazuh"
    assert norm_event.severity == 6
    assert norm_event.user == "sec_analyst_test"


def test_wazuh_adapter_full_pipeline_flow(in_memory_session):
    """Verify complete path: Wazuh JSON -> Adapter -> Pipeline -> Detection -> Alert -> Correlation -> Incident -> Risk -> Threat Intel."""
    event_repo = EventRepository(in_memory_session)
    alert_repo = AlertRepository(in_memory_session)
    corr_repo = CorrelationRepository(in_memory_session)
    inc_repo = IncidentRepository(in_memory_session)
    risk_repo = RiskAssessmentRepository(in_memory_session)
    ti_repo = ThreatIntelRepository(in_memory_session)

    pipeline = EventPipeline(
        processing_service=EventProcessingService(event_repo),
        detection_engine=DetectionEngine(get_default_rules()),
        alert_service=AlertService(alert_repo, event_repo),
        correlation_engine=CorrelationEngine(
            rules=get_default_correlation_rules(),
            correlation_repository=corr_repo,
            alert_repository=alert_repo,
            event_repository=event_repo,
        ),
        incident_service=IncidentService(
            incident_repository=inc_repo,
            correlation_repository=corr_repo,
            event_repository=event_repo,
        ),
        risk_service=RiskScoringService(
            risk_repository=risk_repo,
            incident_repository=inc_repo,
            correlation_repository=corr_repo,
            event_repository=event_repo,
        ),
        threat_intel_service=ThreatIntelligenceService(
            threat_intel_repository=ti_repo,
            incident_repository=inc_repo,
            event_repository=event_repo,
        ),
    )

    # Ingest 2 sequential authentication failures from same user/ip
    adapter = WazuhAlertAdapter([SAMPLE_WAZUH_AUTH_FAIL_1, SAMPLE_WAZUH_AUTH_FAIL_2])
    normalized_events = adapter.get_normalized_events()

    # Event 1: Auth failure
    res1 = pipeline.ingest(normalized_events[0])
    assert res1.newly_persisted is True
    assert res1.detection_matches >= 1
    assert len(res1.alerts_created) == 1
    assert len(res1.incidents_created) == 0  # 1 alert alone does not trigger sequence correlation

    # Event 2: Second auth failure -> triggers AuthenticationAttackSequence correlation
    res2 = pipeline.ingest(normalized_events[1])
    assert res2.newly_persisted is True
    assert res2.detection_matches >= 1
    assert len(res2.alerts_created) == 1
    assert len(res2.correlations_created) == 1
    assert len(res2.incidents_created) == 1
    assert len(res2.risk_assessments_created) == 1
    assert res2.risk_score is not None

    # Verify incident persisted in repository
    incidents = inc_repo.list_incidents()
    assert len(incidents) == 1
    incident = incidents[0]
    assert "sec_analyst_test" in incident.title
    assert "T1110" in incident.mitre_techniques_json
    assert len(json.loads(incident.alert_ids_json)) == 2


def test_wazuh_adapter_idempotency(in_memory_session):
    """Verify that re-ingesting the exact same Wazuh alert ID is idempotent."""
    event_repo = EventRepository(in_memory_session)
    alert_repo = AlertRepository(in_memory_session)

    pipeline = EventPipeline(
        processing_service=EventProcessingService(event_repo),
        detection_engine=DetectionEngine(get_default_rules()),
        alert_service=AlertService(alert_repo, event_repo),
    )

    adapter = WazuhAlertAdapter([SAMPLE_WAZUH_AUTH_FAIL_1])
    norm_event = adapter.get_normalized_events()[0]

    # First ingestion
    first_res = pipeline.ingest(norm_event)
    assert first_res.newly_persisted is True
    assert first_res.duplicate is False
    assert len(first_res.alerts_created) == 1

    # Second ingestion of duplicate alert
    second_res = pipeline.ingest(norm_event)
    assert second_res.newly_persisted is False
    assert second_res.duplicate is True
    assert len(second_res.alerts_created) == 0  # Does not re-trigger alerts
