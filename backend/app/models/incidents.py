from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=10000)
    severity: int = Field(ge=0, le=15)
    status: IncidentStatus = IncidentStatus.OPEN
    created_at: datetime
    updated_at: datetime
    correlation_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)