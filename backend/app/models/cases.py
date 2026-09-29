"""SOC Case Management domain models.

Defines the Case, CaseNote, EvidenceReference, CaseResolution, and related enums.
Adheres strictly to evidence-referencing rather than raw telemetry duplication.
"""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceType(str, Enum):
    EVENT = "event"
    ALERT = "alert"
    CORRELATION = "correlation"
    INCIDENT = "incident"
    INVESTIGATION = "investigation"
    THREAT_INTEL = "threat_intel"
    ARTIFACT = "artifact"


class EvidenceReference(BaseModel):
    """Pointer to existing security evidence without duplicating raw telemetry."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    case_id: str = Field(min_length=1, max_length=256)
    evidence_type: EvidenceType
    reference_key: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=1000)
    added_by: str = Field(min_length=1, max_length=256)
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseNote(BaseModel):
    """Analyst note or comment attached to a case (append-only in Phase 9)."""

    model_config = ConfigDict(extra="forbid")

    note_id: str = Field(min_length=1, max_length=256)
    case_id: str = Field(min_length=1, max_length=256)
    author: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=5000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseResolution(BaseModel):
    """Structured resolution information recorded when resolving a case."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=3000)
    root_cause: str = Field(default="", max_length=2000)
    action_taken: str = Field(default="", max_length=2000)
    resolved_by: str = Field(min_length=1, max_length=256)
    resolved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseTimelineEntry(BaseModel):
    """Chronological event in the life of a case, derived from audit events and milestones."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    action: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=1000)
    metadata: dict[str, str] = Field(default_factory=dict)


class Case(BaseModel):
    """Top-level SOC Case domain model."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=5000)
    severity: int = Field(ge=0, le=15)
    priority: CasePriority = CasePriority.MEDIUM
    status: CaseStatus = CaseStatus.OPEN
    assignee: str | None = Field(default=None, max_length=256)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    incident_ids: list[str] = Field(default_factory=list)
    investigation_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    notes: list[CaseNote] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    resolution: CaseResolution | None = None
