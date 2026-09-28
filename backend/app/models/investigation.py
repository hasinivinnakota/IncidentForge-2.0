"""AI investigation result domain models. Provider-agnostic, structured investigation findings."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingType(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    RECOMMENDED = "RECOMMENDED"


class FindingItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_type: FindingType
    description: str = Field(min_length=1, max_length=2000)
    evidence: list[str] = Field(default_factory=list)


class TimelineItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=2000)
    source_entity: str | None = Field(default=None, max_length=256)


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=2000)
    target_entity: str = Field(min_length=1, max_length=256)
    analyst_approval_required: bool = True
    inert_proposed_only: bool = True


class InvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=256)
    incident_id: str = Field(min_length=1, max_length=256)
    summary: str = Field(min_length=1, max_length=10000)
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[FindingItem] = Field(default_factory=list)
    timeline: list[TimelineItem] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    threat_intel_summary: dict[str, Any] = Field(default_factory=dict)
    investigation_gaps: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    possible_response_actions: list[RecommendedAction] = Field(default_factory=list)
    provider: str = Field(default="local_dev", min_length=1, max_length=64)
    model_name: str = Field(default="heuristic_deterministic_v1", min_length=1, max_length=128)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))