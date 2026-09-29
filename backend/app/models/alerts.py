"""Detection result model."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=256)
    event_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    rule_id: str = Field(min_length=1, max_length=128)
    rule_name: str = Field(min_length=1, max_length=256)
    severity: int = Field(ge=0, le=15)
    description: str = Field(min_length=1, max_length=10000)
    source: str = Field(min_length=1, max_length=128)
    evidence: dict[str, object] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW