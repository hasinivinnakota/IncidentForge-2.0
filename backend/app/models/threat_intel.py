"""Domain models for Threat Intelligence Enrichment."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"


class ThreatClassification(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class IOC(BaseModel):
    """Strongly typed Indicator of Compromise."""

    model_config = ConfigDict(extra="forbid")

    ioc_id: str = Field(min_length=1, max_length=256)
    ioc_type: IOCType
    value: str = Field(min_length=1, max_length=2048)
    normalized_value: str = Field(min_length=1, max_length=2048)
    source_context: str = Field(min_length=1, max_length=512)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ThreatIntelResult(BaseModel):
    """Structured threat-intelligence enrichment result for a single IOC."""

    model_config = ConfigDict(extra="forbid")

    enrichment_id: str = Field(min_length=1, max_length=256)
    incident_id: str = Field(min_length=1, max_length=256)
    ioc_type: IOCType
    ioc_value: str = Field(min_length=1, max_length=2048)
    classification: ThreatClassification
    confidence: int = Field(ge=0, le=100)
    reputation: str = Field(min_length=1, max_length=64)
    threat_category: str = Field(max_length=128, default="")
    provider: str = Field(min_length=1, max_length=128)
    source_count: int = Field(ge=0, default=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    explanation: str = Field(min_length=1, max_length=2048)
    lookup_timestamp: datetime
