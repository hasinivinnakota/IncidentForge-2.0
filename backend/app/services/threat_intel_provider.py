"""Threat Intelligence provider abstraction and local development provider.

The provider interface allows future implementations (VirusTotal, MISP, STIX/TAXII,
commercial feeds) without modifying the core pipeline or service layer.

The LocalDevThreatIntelProvider uses deterministic synthetic data for development
and testing. It makes NO external network calls.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from ..models.threat_intel import IOC, IOCType, ThreatClassification, ThreatIntelResult

logger = logging.getLogger(__name__)


class ThreatIntelProvider(ABC):
    """Abstract base class for threat-intelligence data sources.

    Future implementations:
    - VirusTotal provider
    - MISP provider
    - STIX/TAXII provider
    - Commercial threat-intelligence feeds

    All providers must return a ThreatIntelResult for any given IOC.
    Unknown indicators should return classification=UNKNOWN with appropriate explanation.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique provider identifier string."""

    @abstractmethod
    def lookup(
        self,
        ioc: IOC,
        *,
        incident_id: str,
        enrichment_id: str,
    ) -> ThreatIntelResult:
        """Look up an IOC and return structured threat intelligence.

        Args:
            ioc: The validated IOC to look up.
            incident_id: The incident this IOC is associated with.
            enrichment_id: Pre-computed deterministic enrichment ID.

        Returns:
            ThreatIntelResult with classification, confidence, and explanation.
        """


# ---------------------------------------------------------------------------
# Deterministic synthetic threat-intelligence dataset
# ---------------------------------------------------------------------------

# IMPORTANT: These are clearly synthetic/documented indicators for development only.
# They do NOT represent real-world malicious infrastructure.

_SYNTHETIC_MALICIOUS_IPV4 = frozenset({
    "203.0.113.50",   # TEST-NET-3 (RFC 5737) — synthetic C2 server
    "198.51.100.99",  # TEST-NET-2 (RFC 5737) — synthetic scanner
    "203.0.113.100",  # TEST-NET-3 — synthetic exfiltration endpoint
})

_SYNTHETIC_BENIGN_IPV4 = frozenset({
    "192.0.2.1",    # TEST-NET-1 (RFC 5737) — synthetic clean host
    "192.0.2.10",   # TEST-NET-1 — synthetic internal server
})

_SYNTHETIC_MALICIOUS_DOMAINS = frozenset({
    "evil.synthetic.example",       # Synthetic malware C2
    "malware.synthetic.example",    # Synthetic malware distribution
    "phishing.synthetic.example",   # Synthetic phishing
})

_SYNTHETIC_BENIGN_DOMAINS = frozenset({
    "safe.synthetic.example",       # Synthetic safe domain
    "trusted.synthetic.example",    # Synthetic trusted domain
})

_SYNTHETIC_MALICIOUS_HASHES = frozenset({
    # Synthetic SHA256 — deterministic test hash representing malware
    "A" * 64,
    # Synthetic SHA1
    "B" * 40,
    # Synthetic MD5
    "C" * 32,
})

_SYNTHETIC_BENIGN_HASHES = frozenset({
    "D" * 64,  # Synthetic clean file SHA256
    "E" * 40,  # Synthetic clean file SHA1
    "F" * 32,  # Synthetic clean file MD5 (all-F is still valid hex)
})

_THREAT_CATEGORIES = {
    "203.0.113.50": "command_and_control",
    "198.51.100.99": "scanning",
    "203.0.113.100": "data_exfiltration",
    "evil.synthetic.example": "command_and_control",
    "malware.synthetic.example": "malware_distribution",
    "phishing.synthetic.example": "phishing",
    "A" * 64: "trojan",
    "B" * 40: "trojan",
    "C" * 32: "trojan",
}


class LocalDevThreatIntelProvider(ThreatIntelProvider):
    """Deterministic local threat-intelligence provider for development and testing.

    Uses synthetic indicators from RFC 5737 test networks and .example TLD.
    Makes NO external network calls.
    All results are clearly labeled as synthetic development intelligence.
    """

    @property
    def provider_name(self) -> str:
        return "local_dev_provider"

    def lookup(
        self,
        ioc: IOC,
        *,
        incident_id: str,
        enrichment_id: str,
    ) -> ThreatIntelResult:
        """Look up an IOC against the synthetic local dataset."""
        now = datetime.now(timezone.utc)
        normalized = ioc.normalized_value

        # Check malicious indicators
        if self._is_malicious(ioc.ioc_type, normalized):
            category = _THREAT_CATEGORIES.get(normalized, "malicious_activity")
            return ThreatIntelResult(
                enrichment_id=enrichment_id,
                incident_id=incident_id,
                ioc_type=ioc.ioc_type,
                ioc_value=normalized,
                classification=ThreatClassification.MALICIOUS,
                confidence=94,
                reputation="malicious",
                threat_category=category,
                provider=self.provider_name,
                source_count=3,
                first_seen=now,
                last_seen=now,
                tags=["synthetic", category],
                explanation=(
                    f"Synthetic development intelligence classifies this {ioc.ioc_type.value} "
                    f"indicator as malicious with high confidence. "
                    f"Category: {category}. This is test data only."
                ),
                lookup_timestamp=now,
            )

        # Check benign indicators
        if self._is_benign(ioc.ioc_type, normalized):
            return ThreatIntelResult(
                enrichment_id=enrichment_id,
                incident_id=incident_id,
                ioc_type=ioc.ioc_type,
                ioc_value=normalized,
                classification=ThreatClassification.BENIGN,
                confidence=90,
                reputation="benign",
                threat_category="",
                provider=self.provider_name,
                source_count=2,
                first_seen=now,
                last_seen=now,
                tags=["synthetic", "clean"],
                explanation=(
                    f"Synthetic development intelligence classifies this {ioc.ioc_type.value} "
                    f"indicator as benign with high confidence. This is test data only."
                ),
                lookup_timestamp=now,
            )

        # Unknown — not in synthetic dataset
        return ThreatIntelResult(
            enrichment_id=enrichment_id,
            incident_id=incident_id,
            ioc_type=ioc.ioc_type,
            ioc_value=normalized,
            classification=ThreatClassification.UNKNOWN,
            confidence=0,
            reputation="unknown",
            threat_category="",
            provider=self.provider_name,
            source_count=0,
            tags=["synthetic"],
            explanation=(
                f"No matching intelligence was found for this {ioc.ioc_type.value} "
                f"indicator in the synthetic development dataset."
            ),
            lookup_timestamp=now,
        )

    def _is_malicious(self, ioc_type: IOCType, normalized: str) -> bool:
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return normalized in _SYNTHETIC_MALICIOUS_IPV4
        if ioc_type == IOCType.DOMAIN:
            return normalized in _SYNTHETIC_MALICIOUS_DOMAINS
        if ioc_type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
            return normalized in _SYNTHETIC_MALICIOUS_HASHES
        if ioc_type == IOCType.URL:
            # Check if URL contains a malicious domain
            for domain in _SYNTHETIC_MALICIOUS_DOMAINS:
                if domain in normalized:
                    return True
        return False

    def _is_benign(self, ioc_type: IOCType, normalized: str) -> bool:
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return normalized in _SYNTHETIC_BENIGN_IPV4
        if ioc_type == IOCType.DOMAIN:
            return normalized in _SYNTHETIC_BENIGN_DOMAINS
        if ioc_type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
            return normalized in _SYNTHETIC_BENIGN_HASHES
        if ioc_type == IOCType.URL:
            for domain in _SYNTHETIC_BENIGN_DOMAINS:
                if domain in normalized:
                    return True
        return False
