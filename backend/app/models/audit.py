"""Audit trail event model."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    actor: str = Field(min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=256)
    result: str = Field(min_length=1, max_length=10000)
    metadata: dict[str, Any] = Field(default_factory=dict)