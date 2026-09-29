"""Unit tests for LLM Provider abstraction and LocalDevLLMProvider."""

from datetime import datetime, timezone
import pytest

from backend.app.models.investigation import FindingType, InvestigationResult
from backend.app.services.llm_provider import LLMContext, LocalDevLLMProvider


@pytest.fixture
def sample_context():
    return LLMContext(
        incident_id="inc-test-12345",
        incident_title="Suspicious Process Execution on HOST-01",
        incident_severity=4,
        incident_status="open",
        entity_id="HOST-01",
        created_at=datetime.now(timezone.utc),
        alert_count=2,
        alerts_summary=[
            {
                "alert_id": "alt-01",
                "rule_id": "RULE-SUSP-PROC",
                "rule_name": "Suspicious Process Execution",
                "severity": 4,
            },
            {
                "alert_id": "alt-02",
                "rule_id": "RULE-PRIV-ESC",
                "rule_name": "Privilege Escalation Detected",
                "severity": 4,
            },
        ],
        mitre_techniques=["T1059", "T1068"],
        threat_intel_summary={
            "total_indicators": 2,
            "malicious_count": 1,
            "suspicious_count": 1,
            "benign_count": 0,
            "unknown_count": 0,
        },
        risk_score=78.5,
        risk_level="HIGH",
        timeline_events=[
            {
                "timestamp": "2026-09-04T09:00:00Z",
                "event_type": "process_creation",
                "description": "powershell.exe executed with suspicious flags",
                "source_entity": "HOST-01",
            }
        ],
    )


def test_local_dev_provider_metadata():
    provider = LocalDevLLMProvider()
    assert provider.provider_name == "local_dev"
    assert provider.model_name == "heuristic_deterministic_v1"


def test_local_dev_provider_investigate_findings(sample_context):
    provider = LocalDevLLMProvider()
    result = provider.investigate(sample_context, "inv-test-999")

    assert isinstance(result, InvestigationResult)
    assert result.investigation_id == "inv-test-999"
    assert result.incident_id == sample_context.incident_id
    assert result.provider == "local_dev"
    assert result.model_name == "heuristic_deterministic_v1"

    # Check findings categorization
    types = [f.finding_type for f in result.findings]
    assert FindingType.OBSERVED in types
    assert FindingType.INFERRED in types
    assert FindingType.RECOMMENDED in types

    # Check observed findings contain evidence
    observed = [f for f in result.findings if f.finding_type == FindingType.OBSERVED]
    assert len(observed) >= 2
    for item in observed:
        assert len(item.evidence) > 0


def test_local_dev_provider_response_actions_are_inert(sample_context):
    provider = LocalDevLLMProvider()
    result = provider.investigate(sample_context, "inv-test-999")

    assert len(result.possible_response_actions) > 0
    for action in result.possible_response_actions:
        assert action.analyst_approval_required is True
        assert action.inert_proposed_only is True
        assert action.target_entity == "HOST-01"


def test_local_dev_provider_timeline_and_gaps(sample_context):
    provider = LocalDevLLMProvider()
    result = provider.investigate(sample_context, "inv-test-999")

    assert len(result.timeline) == 1
    assert result.timeline[0].event_type == "process_creation"
    assert result.timeline[0].source_entity == "HOST-01"

    # Gaps identified
    assert len(result.investigation_gaps) > 0
    # Next steps proposed
    assert len(result.recommended_next_steps) > 0


def test_local_dev_provider_confidence_bounded(sample_context):
    provider = LocalDevLLMProvider()
    result = provider.investigate(sample_context, "inv-test-999")

    assert 0.0 <= result.confidence <= 1.0
    # With alerts, MITRE, TI, and entity, confidence should be high
    assert result.confidence >= 0.8
