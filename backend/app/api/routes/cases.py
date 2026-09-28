"""Case management API endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import Session

from ...database import get_session
from ...models.cases import (
    Case,
    CaseNote,
    CasePriority,
    CaseStatus,
    CaseTimelineEntry,
    EvidenceReference,
    EvidenceType,
)
from ...persistence.repositories import (
    CaseRepository,
    EventRepository,
    IncidentRepository,
    InvestigationRepository,
)
from ...services.cases import CaseService

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=5000)
    severity: int = Field(ge=0, le=15)
    priority: CasePriority = CasePriority.MEDIUM
    incident_id: str | None = Field(default=None, max_length=256)
    tags: list[str] = Field(default_factory=list)
    actor: str = Field(default="analyst", max_length=256)


class CaseUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, min_length=1, max_length=5000)
    priority: CasePriority | None = None
    tags: list[str] | None = None
    actor: str = Field(default="analyst", max_length=256)


class CaseAssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee: str | None = Field(default=None, max_length=256)
    actor: str = Field(default="analyst", max_length=256)


class CaseStatusTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_status: CaseStatus
    reason: str | None = Field(default=None, max_length=500)
    actor: str = Field(default="analyst", max_length=256)


class CaseResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=3000)
    root_cause: str = Field(default="", max_length=2000)
    action_taken: str = Field(default="", max_length=2000)
    resolver: str = Field(default="analyst", min_length=1, max_length=256)


class CaseNoteCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=5000)
    author: str = Field(default="analyst", min_length=1, max_length=256)


class EvidenceLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: EvidenceType
    reference_key: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=1000)
    added_by: str = Field(default="analyst", min_length=1, max_length=256)


# ---------------------------------------------------------------------------
# Helper Dependency
# ---------------------------------------------------------------------------

def _get_case_service(session: Session = Depends(get_session)) -> CaseService:
    case_repo = CaseRepository(session)
    event_repo = EventRepository(session)
    incident_repo = IncidentRepository(session)
    investigation_repo = InvestigationRepository(session)
    return CaseService(
        case_repository=case_repo,
        event_repository=event_repo,
        incident_repository=incident_repo,
        investigation_repository=investigation_repo,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=Case, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreateRequest,
    service: CaseService = Depends(_get_case_service),
) -> Case:
    """Create a new case (standalone or seeded from an existing incident)."""
    return service.create_case(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        priority=payload.priority,
        incident_id=payload.incident_id,
        tags=payload.tags,
        actor=payload.actor,
    )


@router.get("", response_model=list[Case])
def list_cases(
    status: CaseStatus | None = None,
    priority: CasePriority | None = None,
    assignee: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    service: CaseService = Depends(_get_case_service),
) -> list[Case]:
    """List cases with optional filters for status, priority, and assignee."""
    status_filter = status.value if status else None
    priority_filter = priority.value if priority else None
    return service.list_cases(
        status=status_filter,
        priority=priority_filter,
        assignee=assignee,
        limit=limit,
    )


@router.get("/{case_id}", response_model=Case)
def get_case(
    case_id: str,
    service: CaseService = Depends(_get_case_service),
) -> Case:
    """Retrieve details of a specific case."""
    case = service.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return case


@router.patch("/{case_id}", response_model=Case)
def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    service: CaseService = Depends(_get_case_service),
) -> Case:
    """Update general properties (title, description, priority, tags) of a case."""
    case = service.update_case(
        case_id=case_id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        tags=payload.tags,
        actor=payload.actor,
    )
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return case


@router.post("/{case_id}/assign", response_model=Case)
def assign_case(
    case_id: str,
    payload: CaseAssignRequest,
    service: CaseService = Depends(_get_case_service),
) -> Case:
    """Assign or reassign a case to an analyst."""
    case = service.assign_case(
        case_id=case_id,
        assignee=payload.assignee,
        actor=payload.actor,
    )
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return case


@router.post("/{case_id}/status", response_model=Case)
def transition_case_status(
    case_id: str,
    payload: CaseStatusTransitionRequest,
    service: CaseService = Depends(_get_case_service),
) -> Case:
    """Validate and transition case status according to state machine rules."""
    try:
        return service.transition_status(
            case_id=case_id,
            new_status=payload.new_status,
            reason=payload.reason,
            actor=payload.actor,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.post("/{case_id}/resolve", response_model=Case)
def resolve_case(
    case_id: str,
    payload: CaseResolveRequest,
    service: CaseService = Depends(_get_case_service),
) -> Case:
    """Resolve a case with summary, root cause, and action taken."""
    try:
        return service.resolve_case(
            case_id=case_id,
            summary=payload.summary,
            root_cause=payload.root_cause,
            action_taken=payload.action_taken,
            resolver=payload.resolver,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.post("/{case_id}/notes", response_model=CaseNote, status_code=status.HTTP_201_CREATED)
def add_case_note(
    case_id: str,
    payload: CaseNoteCreateRequest,
    service: CaseService = Depends(_get_case_service),
) -> CaseNote:
    """Add an append-only analyst note to a case."""
    try:
        return service.add_note(
            case_id=case_id,
            content=payload.content,
            author=payload.author,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.get("/{case_id}/notes", response_model=list[CaseNote])
def list_case_notes(
    case_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: CaseService = Depends(_get_case_service),
) -> list[CaseNote]:
    """List notes attached to a case."""
    case = service.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return service.list_notes(case_id=case_id, limit=limit)


@router.post("/{case_id}/evidence", response_model=EvidenceReference, status_code=status.HTTP_201_CREATED)
def link_evidence(
    case_id: str,
    payload: EvidenceLinkRequest,
    service: CaseService = Depends(_get_case_service),
) -> EvidenceReference:
    """Link an evidence pointer (event, alert, correlation, incident, investigation, TI) to a case."""
    try:
        return service.link_evidence(
            case_id=case_id,
            evidence_type=payload.evidence_type,
            reference_key=payload.reference_key,
            description=payload.description,
            added_by=payload.added_by,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.get("/{case_id}/timeline", response_model=list[CaseTimelineEntry])
def get_case_timeline(
    case_id: str,
    service: CaseService = Depends(_get_case_service),
) -> list[CaseTimelineEntry]:
    """Retrieve chronological case history reconstructed from audit events."""
    try:
        return service.get_timeline(case_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
