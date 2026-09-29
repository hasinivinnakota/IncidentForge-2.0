"""Dataset Security Assessment domain models for IncidentForge v2.

These models represent the OUTPUT of a deterministic security assessment run
against an uploaded dataset. They are entirely separate from the ML incident-
risk model and make no claim to be a trained classifier benchmark.

CLASSIFICATION DISCLAIMER:
  Sensitive-field detection is heuristic / rule-based. It indicates probable
  presence of sensitive data but is NOT a guarantee of complete PII discovery.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .dataset import DatasetAsset, SensitivityLevel


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DatasetFinding(BaseModel):
    """A single structured finding from a dataset security assessment."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    severity: FindingSeverity
    title: str = Field(min_length=1, max_length=256)
    description: str
    affected_columns: list[str] = Field(default_factory=list)
    recommendation: str = ""
    evidence_summary: str = ""


class SecurityCheckResult(BaseModel):
    """Result of a single security check step."""

    model_config = ConfigDict(extra="forbid")

    check_name: str
    passed: bool
    severity: FindingSeverity = FindingSeverity.INFO
    detail: str = ""


class DatasetSecurityScore(BaseModel):
    """Deterministic dataset security score (0-100, lower = riskier)."""

    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    risk_level: str  # LOW / MEDIUM / HIGH / CRITICAL
    contributing_factors: list[str] = Field(default_factory=list)


class DatasetSecurityAssessment(BaseModel):
    """Complete security assessment result for a dataset."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(min_length=1, max_length=128)
    dataset_id: str = Field(min_length=1, max_length=256)
    dataset_name: str = Field(min_length=1, max_length=256)

    # Core profile (sanitized — no raw rows)
    asset: DatasetAsset

    # Security assessment results
    findings: list[DatasetFinding] = Field(default_factory=list)
    security_score: DatasetSecurityScore
    checks_performed: list[SecurityCheckResult] = Field(default_factory=list)

    # Summary counts
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0

    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Disclaimer — always present
    disclaimer: str = (
        "Sensitive-field detection is heuristic and rule-based. "
        "This assessment indicates probable areas of concern but is not a guarantee "
        "of complete PII discovery or compliance certification."
    )


class DatasetUploadResult(BaseModel):
    """Response from the POST /api/v1/data-assets/upload endpoint."""

    model_config = ConfigDict(extra="forbid")

    success: bool
    dataset_id: str
    assessment: DatasetSecurityAssessment
    registered: bool = True
    temp_file_cleaned: bool = True
    message: str = ""


class DatasetSimulationResult(BaseModel):
    """Result of a per-dataset suspicious-activity simulation."""

    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    dataset_name: str
    events_generated: int
    alerts_created: int
    correlations_created: int
    incidents_created: int
    simulation_actor: str
    simulated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pipeline_results: list[dict[str, Any]] = Field(default_factory=list)
