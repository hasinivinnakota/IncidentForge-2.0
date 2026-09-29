"""Tests for IOC extraction from structured evidence."""

from datetime import datetime, timezone

from backend.app.models.threat_intel import IOCType
from backend.app.services.ioc_extractor import IOCExtractor


def test_extract_ipv4():
    extractor = IOCExtractor()
    iocs = extractor.extract_from_event_data(
        source_ip="192.168.1.100",
        destination_ip="203.0.113.50",
    )
    assert len(iocs) == 2
    types = {ioc.ioc_type for ioc in iocs}
    assert types == {IOCType.IPV4}
    values = {ioc.normalized_value for ioc in iocs}
    assert values == {"192.168.1.100", "203.0.113.50"}


def test_extract_ipv6():
    extractor = IOCExtractor()
    iocs = extractor.extract_from_event_data(
        source_ip="2001:db8::1",
    )
    assert len(iocs) == 1
    assert iocs[0].ioc_type == IOCType.IPV6
    assert iocs[0].normalized_value == "2001:db8::1"


def test_extract_from_metadata():
    extractor = IOCExtractor()
    now = datetime.now(timezone.utc)
    iocs = extractor.extract_from_event_data(
        metadata={
            "domain": "evil.example.com",
            "url": "http://evil.example.com/payload.exe",
            "file_sha256": "a" * 64,
            "file_md5": "b" * 32,
            "irrelevant_field": "10.0.0.1",  # Should be ignored
        },
        timestamp=now,
    )
    assert len(iocs) == 4

    domain_ioc = next(i for i in iocs if i.ioc_type == IOCType.DOMAIN)
    assert domain_ioc.normalized_value == "evil.example.com"

    url_ioc = next(i for i in iocs if i.ioc_type == IOCType.URL)
    assert url_ioc.normalized_value == "http://evil.example.com/payload.exe"

    sha256_ioc = next(i for i in iocs if i.ioc_type == IOCType.SHA256)
    assert sha256_ioc.normalized_value == "A" * 64  # Uppercase

    md5_ioc = next(i for i in iocs if i.ioc_type == IOCType.MD5)
    assert md5_ioc.normalized_value == "B" * 32  # Uppercase


def test_deduplication():
    extractor = IOCExtractor()
    iocs = extractor.extract_from_incident(
        incident_evidence={"domain": "test.com"},
        alert_evidences=[
            {"url": "http://test.com/1"},
            {"domain": "test.com"}
        ],
        event_data=[
            {"source_ip": "10.0.0.1", "metadata": {"domain": "TEST.com"}}
        ]
    )
    # 1 IP, 1 URL, 1 Domain
    assert len(iocs) == 3
    domains = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
    assert len(domains) == 1
    assert domains[0].normalized_value == "test.com"


def test_credential_exclusion():
    extractor = IOCExtractor()
    iocs = extractor.extract_from_event_data(
        metadata={
            "domain": "safe.example",
            "password": "SuperSecretPassword123",
            "api_key": "abcd1234abcd1234abcd1234",
            "bearer": "ey...",
            "url": "http://safe.example/path", # Does not contain credentials
            "auth_token": "a" * 64, # Looks like sha256 but key is credential-like
        }
    )
    types = {ioc.ioc_type for ioc in iocs}
    assert IOCType.SHA256 not in types  # auth_token skipped
    assert len(iocs) == 2  # domain and url


def test_invalid_iocs():
    extractor = IOCExtractor()
    iocs = extractor.extract_from_event_data(
        source_ip="not_an_ip",
        metadata={
            "domain": "invalid domain name!",
            "file_sha256": "too_short",
            "url": "not_a_url",
        }
    )
    assert len(iocs) == 0
