"""Result returned by the event-processing boundary."""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ProcessingStatus(str, Enum):
    PROCESSED = "processed"


class PersistenceStatus(str, Enum):
    PERSISTED = "persisted"
    DUPLICATE = "duplicate"


class EventProcessingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=256)
    newly_persisted: bool
    duplicate: bool
    processing_status: ProcessingStatus = ProcessingStatus.PROCESSED
    persistence_status: PersistenceStatus


class PipelineResult(BaseModel):
    """Response from the full event pipeline (superset of EventProcessingResult)."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=256)
    newly_persisted: bool
    duplicate: bool
    processing_status: ProcessingStatus = ProcessingStatus.PROCESSED
    persistence_status: PersistenceStatus
    detection_matches: int = 0
    alerts_created: list[str] = Field(default_factory=list)
    correlations_created: list[str] = Field(default_factory=list)
    correlations_updated: list[str] = Field(default_factory=list)
    incidents_created: list[str] = Field(default_factory=list)
    incidents_updated: list[str] = Field(default_factory=list)
    risk_assessments_created: list[str] = Field(default_factory=list)
    risk_assessments_updated: list[str] = Field(default_factory=list)
    risk_score: int | None = None
    risk_level: str | None = None
    threat_intel_created: list[str] = Field(default_factory=list)
    threat_intel_updated: list[str] = Field(default_factory=list)
    iocs_extracted: int = 0
