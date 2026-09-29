"""Controlled response action endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import Session

from ...database import get_session
from ...models.response import ResponseAction
from ...persistence.repositories import (
    EventRepository,
    IncidentRepository,
    ResponseActionRepository,
)
from ...services.response import (
    ResponseNotFoundError,
    ResponseService,
    ResponseServiceError,
    ResponseTransitionError,
    ResponseValidationError,
)

router = APIRouter(
    prefix="/api/v1",
    tags=["response"],
)


class CreateResponseActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str = Field(min_length=1, max_length=128)
    actor: str = Field(default="analyst", min_length=1, max_length=256)


class ResponseActorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(min_length=1, max_length=256)


class RejectResponseActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(min_length=1, max_length=256)
    reason: str | None = Field(default=None, max_length=10_000)


def _service(session: Session) -> ResponseService:
    return ResponseService(
        event_repository=EventRepository(session),
        incident_repository=IncidentRepository(session),
        response_repository=ResponseActionRepository(session),
    )


@router.post(
    "/incidents/{incident_id}/response-actions",
    response_model=ResponseAction,
    status_code=status.HTTP_201_CREATED,
)
def create_response_action(
    incident_id: str,
    request: CreateResponseActionRequest,
    session: Session = Depends(get_session),
) -> ResponseAction:
    service = _service(session)

    # Check if incident exists; return 404 if not found
    if IncidentRepository(session).get_incident(incident_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    try:
        return service.create_action(
            incident_id=incident_id,
            action_type=request.action_type,
            actor=request.actor,
        )
    except ResponseValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "/incidents/{incident_id}/response-actions",
    response_model=list[ResponseAction],
)
def list_response_actions(
    incident_id: str,
    session: Session = Depends(get_session),
) -> list[ResponseAction]:
    service = _service(session)

    if IncidentRepository(session).get_incident(incident_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    return service.list_actions(incident_id)


@router.get(
    "/response-actions/{action_id}",
    response_model=ResponseAction,
)
def get_response_action(
    action_id: str,
    session: Session = Depends(get_session),
) -> ResponseAction:
    service = _service(session)

    try:
        return service.get_action(action_id)
    except ResponseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/response-actions/{action_id}/approve",
    response_model=ResponseAction,
)
def approve_response_action(
    action_id: str,
    request: ResponseActorRequest,
    session: Session = Depends(get_session),
) -> ResponseAction:
    service = _service(session)

    try:
        return service.approve(
            action_id=action_id,
            actor=request.actor,
        )
    except ResponseTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ResponseValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ResponseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/response-actions/{action_id}/reject",
    response_model=ResponseAction,
)
def reject_response_action(
    action_id: str,
    request: RejectResponseActionRequest,
    session: Session = Depends(get_session),
) -> ResponseAction:
    service = _service(session)

    try:
        return service.reject(
            action_id=action_id,
            actor=request.actor,
            reason=request.reason,
        )
    except ResponseTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ResponseValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ResponseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/response-actions/{action_id}/execute",
    response_model=ResponseAction,
)
def execute_response_action(
    action_id: str,
    request: ResponseActorRequest,
    session: Session = Depends(get_session),
) -> ResponseAction:
    service = _service(session)

    try:
        return service.execute(
            action_id=action_id,
            actor=request.actor,
        )
    except ResponseTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ResponseValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ResponseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
