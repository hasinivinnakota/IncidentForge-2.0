"""Tests for the local development threat intelligence provider."""

from backend.app.models.threat_intel import IOC, IOCType, ThreatClassification
from backend.app.services.threat_intel_provider import LocalDevThreatIntelProvider


def test_malicious_ipv4():
    provider = LocalDevThreatIntelProvider()
    ioc = IOC(
        ioc_id="test",
        ioc_type=IOCType.IPV4,
        value="203.0.113.50",
        normalized_value="203.0.113.50",
        source_context="test",
    )
    result = provider.lookup(ioc, incident_id="inc-1", enrichment_id="ti-1")

    assert result.classification == ThreatClassification.MALICIOUS
    assert result.confidence == 94
    assert result.threat_category == "command_and_control"
    assert "synthetic" in result.tags


def test_benign_domain():
    provider = LocalDevThreatIntelProvider()
    ioc = IOC(
        ioc_id="test",
        ioc_type=IOCType.DOMAIN,
        value="safe.synthetic.example",
        normalized_value="safe.synthetic.example",
        source_context="test",
    )
    result = provider.lookup(ioc, incident_id="inc-1", enrichment_id="ti-1")

    assert result.classification == ThreatClassification.BENIGN
    assert result.confidence == 90
    assert "clean" in result.tags


def test_unknown_indicator():
    provider = LocalDevThreatIntelProvider()
    ioc = IOC(
        ioc_id="test",
        ioc_type=IOCType.IPV4,
        value="8.8.8.8",
        normalized_value="8.8.8.8",
        source_context="test",
    )
    result = provider.lookup(ioc, incident_id="inc-1", enrichment_id="ti-1")

    assert result.classification == ThreatClassification.UNKNOWN
    assert result.confidence == 0
    assert result.reputation == "unknown"


def test_malicious_url():
    provider = LocalDevThreatIntelProvider()
    ioc = IOC(
        ioc_id="test",
        ioc_type=IOCType.URL,
        value="http://evil.synthetic.example/payload",
        normalized_value="http://evil.synthetic.example/payload",
        source_context="test",
    )
    result = provider.lookup(ioc, incident_id="inc-1", enrichment_id="ti-1")

    assert result.classification == ThreatClassification.MALICIOUS
    assert result.confidence == 94
