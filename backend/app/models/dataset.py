"""Dataset Security domain models for IncidentForge v2.

Defines DatasetAsset, ColumnProfile, SensitivityLevel, and DatasetActivity models.
Strictly non-destructive, metadata-focused representation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DataFormat(str, Enum):
    CSV = "csv"
    JSON = "json"
    PARQUET = "parquet"


class SensitivityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DatasetOperation(str, Enum):
    DATASET_OPENED = "dataset_opened"
    DATASET_READ = "dataset_read"
    SENSITIVE_COLUMN_ACCESS = "sensitive_column_access"
    BULK_ACCESS = "bulk_access"
    DATASET_MODIFIED = "dataset_modified"
    DATASET_COPIED = "dataset_copied"
    DATASET_EXPORTED = "dataset_exported"
    DATASET_DELETED = "dataset_deleted"
    SCHEMA_CHANGED = "schema_changed"


class ColumnProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    data_type: str = Field(min_length=1, max_length=64)
    is_sensitive: bool = False
    pii_type: str | None = Field(default=None, max_length=64)
    sensitivity: SensitivityLevel = SensitivityLevel.LOW


class DatasetAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    format: DataFormat
    file_path: str = Field(min_length=1, max_length=1024)
    size_bytes: int = Field(default=0, ge=0)
    record_count: int = Field(default=0, ge=0)
    column_count: int = Field(default=0, ge=0)
    columns: list[ColumnProfile] = Field(default_factory=list)
    sensitive_columns: list[str] = Field(default_factory=list)
    sensitivity: SensitivityLevel = SensitivityLevel.LOW
    schema_hash: str = Field(default="", max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class DatasetActivity(BaseModel):
    """Raw dataset activity record representing an access, modification, or export event."""

    model_config = ConfigDict(extra="forbid")

    activity_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    dataset_id: str = Field(min_length=1, max_length=256)
    dataset_name: str = Field(min_length=1, max_length=256)
    operation: DatasetOperation
    actor: str = Field(min_length=1, max_length=256)
    actor_host: str = Field(default="workstation-01", max_length=256)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    records_accessed: int = Field(default=0, ge=0)
    records_modified: int = Field(default=0, ge=0)
    sensitive_columns: list[str] = Field(default_factory=list)
    export_size_bytes: int = Field(default=0, ge=0)
    export_destination: str | None = Field(default=None, max_length=512)
    context: dict[str, Any] = Field(default_factory=dict)
