"""Proposed response action model. It intentionally performs no action.

v2.0 adds restrict_dataset_access to support dataset security simulation responses.
All existing endpoint response actions (isolate_endpoint, quarantine_file, revoke_credentials)
remain fully backward compatible.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ResponseActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    REJECTED = "rejected"


class ResponseActionType(str, Enum):
    ISOLATE_ENDPOINT = "isolate_endpoint"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_CREDENTIALS = "revoke_credentials"
    # v2.0: Dataset security simulation action
    RESTRICT_DATASET_ACCESS = "restrict_dataset_access"


ALLOWED_ACTION_TYPES = frozenset(
    {
        ResponseActionType.ISOLATE_ENDPOINT.value,
        ResponseActionType.QUARANTINE_FILE.value,
        ResponseActionType.REVOKE_CREDENTIALS.value,
        ResponseActionType.RESTRICT_DATASET_ACCESS.value,
    }
)


class ResponseAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1, max_length=256)
    incident_id: str = Field(min_length=1, max_length=256)
    action_type: str = Field(min_length=1, max_length=128)
    status: ResponseActionStatus = ResponseActionStatus.PROPOSED
    requested_at: datetime
    approved_by: str | None = Field(default=None, max_length=256)
    executed_at: datetime | None = None
    result: str | None = Field(default=None, max_length=10000)