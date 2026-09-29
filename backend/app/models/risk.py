"""Domain models for ML Risk Scoring."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(BaseModel):
    """Canonical representation of an ML risk assessment for a SOC incident."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(min_length=1, max_length=256)
    incident_id: str = Field(min_length=1, max_length=256)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    model_name: str = Field(min_length=1, max_length=128)
    model_version: str = Field(min_length=1, max_length=64)
    feature_version: str = Field(min_length=1, max_length=64)
    scored_at: datetime
    features: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    feature_contributions: dict[str, float] = Field(default_factory=dict)
