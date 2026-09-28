"""Canonical normalized security event model."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    source: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    severity: int = Field(ge=0, le=15)
    message: str = Field(min_length=1, max_length=10000)
    host: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)