"""Correlated security activity domain models."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CorrelationStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


class CorrelatableAlert(BaseModel):
    """Immutable view of an alert and its source event attributes for correlation evaluation."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=256)
    event_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    rule_id: str = Field(min_length=1, max_length=128)
    rule_name: str = Field(min_length=1, max_length=256)
    severity: int = Field(ge=0, le=15)
    source: str = Field(min_length=1, max_length=128)
    host: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class CorrelationMatch(BaseModel):
    """Result returned by a correlation rule when candidate alerts correlate."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=128)
    correlation_type: str = Field(min_length=1, max_length=128)
    entity_key: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=10000)
    severity: int = Field(ge=0, le=15)
    mitre_techniques: list[str] = Field(default_factory=list)
    matched_alert_ids: list[str] = Field(min_length=1)
    matched_event_ids: list[str] = Field(min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)


class Correlation(BaseModel):
    """Canonical domain model for correlated security activity."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: str = Field(min_length=1, max_length=256)
    correlation_type: str = Field(min_length=1, max_length=128)
    entity_key: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=10000)
    severity: int = Field(ge=0, le=15)
    status: CorrelationStatus = CorrelationStatus.OPEN
    first_seen: datetime
    last_seen: datetime
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    alert_count: int = Field(ge=0)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
