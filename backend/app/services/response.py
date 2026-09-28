"""Controlled, analyst-approved response orchestration.

This module intentionally performs simulation-only response actions.
It never changes the host, network, accounts, files, or other external resources.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
import re

from ..models.response import (
    ALLOWED_ACTION_TYPES,
    ResponseAction,
    ResponseActionStatus,
    ResponseActionType,
)
from ..persistence.models import AuditEvent, ResponseAction as PersistenceResponseAction
from ..persistence.repositories import (
    EventRepository,
    IncidentRepository,
    ResponseActionRepository,
)

logger = logging.getLogger(__name__)

# Strict state transitions:
# PROPOSED -> APPROVED, REJECTED
# APPROVED -> EXECUTED, FAILED
# EXECUTED, FAILED, REJECTED are terminal
ALLOWED_TRANSITIONS: dict[ResponseActionStatus, frozenset[ResponseActionStatus]] = {
    ResponseActionStatus.PROPOSED: frozenset(
        {
            ResponseActionStatus.APPROVED,
            ResponseActionStatus.REJECTED,
        }
    ),
    ResponseActionStatus.APPROVED: frozenset(
        {
            ResponseActionStatus.EXECUTED,
            ResponseActionStatus.FAILED,
        }
    ),
    ResponseActionStatus.EXECUTED: frozenset(),
    ResponseActionStatus.FAILED: frozenset(),
    ResponseActionStatus.REJECTED: frozenset(),
}

_MAX_RESULT_LENGTH = 10_000
_MAX_ACTOR_LENGTH = 256

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "credential",
    "private_key",
    "session",
    "cookie",
)

_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|authorization|"
    r"bearer|credential|private[_-]?key|session|cookie)\b\s*[:=]\s*[^\s,;]+"
)


class ResponseServiceError(Exception):
    """Base exception for controlled response errors."""


class ResponseNotFoundError(ResponseServiceError):
    """Requested response action does not exist."""


class ResponseValidationError(ResponseServiceError):
    """Response action request is invalid."""


class ResponseTransitionError(ResponseServiceError):
    """Requested response state transition is invalid."""


class ResponseService:
    """Create, approve, reject, and safely simulate response actions."""

    def __init__(
        self,
        event_repository: EventRepository,
        incident_repository: IncidentRepository,
        response_repository: ResponseActionRepository | None = None,
    ):
        self.event_repository = event_repository
        self.incident_repository = incident_repository
        self.response_repository = response_repository or ResponseActionRepository(
            event_repository.session
        )
        self.session = event_repository.session

    @staticmethod
    def generate_action_id(
        incident_id: str,
        action_type: str,
    ) -> str:
        digest = hashlib.sha256(
            f"response:{incident_id}:{action_type}".encode("utf-8")
        ).hexdigest()[:16]
        return f"resp-{digest}"

    @classmethod
    def sanitize_text(cls, text: str | None, max_length: int = 5000) -> str:
        """Sanitize text by stripping whitespace, bounding length, and redacting credentials."""
        if not text:
            return ""
        sanitized = str(text).strip()
        # Redact key-value pairings (e.g. password=xyz)
        sanitized = _SENSITIVE_ASSIGNMENT_PATTERN.sub("[REDACTED]", sanitized)
        # Redact any standalone sensitive keywords / secrets
        for pattern in SENSITIVE_KEY_SUBSTRINGS:
            sanitized = re.sub(
                re.escape(pattern), "[REDACTED]", sanitized, flags=re.IGNORECASE
            )
        return sanitized[:max_length]

    @classmethod
    def sanitize_actor(cls, actor: str) -> str:
        actor = actor.strip()
        if not actor:
            raise ResponseValidationError("Actor is required.")
        if len(actor) > _MAX_ACTOR_LENGTH:
            raise ResponseValidationError("Actor is too long.")
        return cls.sanitize_text(actor, _MAX_ACTOR_LENGTH)

    @classmethod
    def sanitize_result(cls, result: str) -> str:
        return cls.sanitize_text(result, _MAX_RESULT_LENGTH)

    def create_action(
        self,
        incident_id: str,
        action_type: str,
        actor: str = "analyst",
    ) -> ResponseAction:
        """Create a proposed action without executing anything. Idempotent."""
        if not incident_id or not incident_id.strip():
            raise ResponseValidationError("Incident ID is required.")

        incident = self.incident_repository.get_incident(incident_id.strip())
        if incident is None:
            raise ResponseValidationError(
                f"Incident '{incident_id}' was not found."
            )

        if action_type not in ALLOWED_ACTION_TYPES:
            raise ResponseValidationError(
                f"Unsupported response action type: {action_type}. "
                f"Allowed: {sorted(ALLOWED_ACTION_TYPES)}"
            )

        clean_actor = self.sanitize_actor(actor)
        clean_incident_id = incident_id.strip()
        action_id = self.generate_action_id(clean_incident_id, action_type)

        existing = self.response_repository.get_response_action(action_id)
        if existing is not None:
            return self._record_to_domain(existing)

        now = datetime.now(timezone.utc)
        
        target_entity = None
        if action_type == "restrict_dataset_access":
            for tag in incident.tags:
                if "dataset:ds-" in tag:
                    target_entity = "dataset:" + tag.split("dataset:")[1]
                    break

        domain_action = ResponseAction(
            action_id=action_id,
            incident_id=clean_incident_id,
            action_type=action_type,
            status=ResponseActionStatus.PROPOSED,
            requested_at=now,
            result=f"Target: {target_entity}" if target_entity else None,
        )

        write_res = self.response_repository.create_response_action(domain_action)
        record = write_res.response_action

        if write_res.created:
            self._audit(
                action="response_action.proposed",
                target=action_id,
                actor=clean_actor,
                result="proposed",
                metadata={
                    "incident_id": clean_incident_id,
                    "action_type": action_type,
                },
            )

        return self._record_to_domain(record)

    def get_action(self, action_id: str) -> ResponseAction:
        record = self.response_repository.get_response_action(action_id)
        if record is None:
            raise ResponseNotFoundError(
                f"Response action '{action_id}' was not found."
            )
        return self._record_to_domain(record)

    def list_actions(self, incident_id: str) -> list[ResponseAction]:
        records = self.response_repository.list_response_actions(incident_id=incident_id)
        return [self._record_to_domain(record) for record in records]

    def approve(
        self,
        action_id: str,
        actor: str,
    ) -> ResponseAction:
        clean_actor = self.sanitize_actor(actor)
        return self._transition(
            action_id=action_id,
            target_status=ResponseActionStatus.APPROVED,
            actor=clean_actor,
            audit_action="response_action.approved",
        )

    def reject(
        self,
        action_id: str,
        actor: str,
        reason: str | None = None,
    ) -> ResponseAction:
        action = self.get_action(action_id)
        self._validate_transition(action.status, ResponseActionStatus.REJECTED)

        clean_actor = self.sanitize_actor(actor)
        clean_reason = self.sanitize_result(
            reason or "Response action rejected by analyst."
        )

        domain_action = ResponseAction(
            action_id=action.action_id,
            incident_id=action.incident_id,
            action_type=action.action_type,
            status=ResponseActionStatus.REJECTED,
            requested_at=action.requested_at,
            approved_by=action.approved_by,
            executed_at=action.executed_at,
            result=clean_reason,
        )

        updated_record = self.response_repository.update_response_action(domain_action)
        assert updated_record is not None

        self._audit(
            action="response_action.rejected",
            target=action_id,
            actor=clean_actor,
            result="rejected",
            metadata={
                "incident_id": updated_record.incident_id,
                "action_type": updated_record.action_type,
                "reason": clean_reason,
            },
        )

        return self._record_to_domain(updated_record)

    def execute(
        self,
        action_id: str,
        actor: str,
    ) -> ResponseAction:
        """Execute only a deterministic local simulation. Requires APPROVED status."""
        action = self.get_action(action_id)
        self._validate_transition(action.status, ResponseActionStatus.EXECUTED)

        clean_actor = self.sanitize_actor(actor)

        # Audit execution start
        self._audit(
            action="response_action.execution_started",
            target=action_id,
            actor=clean_actor,
            result="simulation_started",
            metadata={
                "incident_id": action.incident_id,
                "action_type": action.action_type,
                "simulation_only": True,
            },
        )

        # Execute safe local simulation
        simulation_result = self._simulate(action.action_type, action.incident_id)
        clean_result = self.sanitize_result(simulation_result)
        now = datetime.now(timezone.utc)

        domain_action = ResponseAction(
            action_id=action.action_id,
            incident_id=action.incident_id,
            action_type=action.action_type,
            status=ResponseActionStatus.EXECUTED,
            requested_at=action.requested_at,
            approved_by=action.approved_by,
            executed_at=now,
            result=clean_result,
        )

        updated_record = self.response_repository.update_response_action(domain_action)
        assert updated_record is not None

        # Audit execution completion
        self._audit(
            action="response_action.executed",
            target=action_id,
            actor=clean_actor,
            result="simulated_success",
            metadata={
                "incident_id": updated_record.incident_id,
                "action_type": updated_record.action_type,
                "simulation_only": True,
            },
        )

        return self._record_to_domain(updated_record)

    def _transition(
        self,
        action_id: str,
        target_status: ResponseActionStatus,
        actor: str,
        audit_action: str,
    ) -> ResponseAction:
        action = self.get_action(action_id)
        self._validate_transition(action.status, target_status)

        approved_by = actor if target_status == ResponseActionStatus.APPROVED else action.approved_by

        domain_action = ResponseAction(
            action_id=action.action_id,
            incident_id=action.incident_id,
            action_type=action.action_type,
            status=target_status,
            requested_at=action.requested_at,
            approved_by=approved_by,
            executed_at=action.executed_at,
            result=action.result,
        )

        updated_record = self.response_repository.update_response_action(domain_action)
        assert updated_record is not None

        self._audit(
            action=audit_action,
            target=action_id,
            actor=actor,
            result=target_status.value,
            metadata={
                "incident_id": updated_record.incident_id,
                "action_type": updated_record.action_type,
            },
        )

        return self._record_to_domain(updated_record)

    @staticmethod
    def _validate_transition(
        current: ResponseActionStatus,
        target: ResponseActionStatus,
    ) -> None:
        if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
            raise ResponseTransitionError(
                f"Invalid response transition: {current.value} -> {target.value}"
            )

    @staticmethod
    def _simulate(action_type: str, incident_id: str) -> str:
        """Deterministic simulation handlers for allowlisted actions.

        NEVER calls external systems, never executes subcommands, never modifies resources.
        """
        if action_type == ResponseActionType.ISOLATE_ENDPOINT.value:
            return (
                f"SIMULATION ONLY: endpoint associated with incident '{incident_id}' would be isolated. "
                "No network configuration or endpoint state was changed."
            )
        if action_type == ResponseActionType.QUARANTINE_FILE.value:
            return (
                f"SIMULATION ONLY: suspicious file associated with incident '{incident_id}' would be quarantined. "
                "No files were moved, deleted, or modified."
            )
        if action_type == ResponseActionType.REVOKE_CREDENTIALS.value:
            return (
                f"SIMULATION ONLY: credentials associated with incident '{incident_id}' would be revoked. "
                "No accounts, passwords, sessions, or credentials were changed."
            )
        if action_type == ResponseActionType.RESTRICT_DATASET_ACCESS.value:
            return (
                f"SIMULATION ONLY: access policy for the dataset associated with incident '{incident_id}' "
                "would be restricted to read-only / quarantine mode. "
                "No files, storage ACLs, permissions, cloud buckets, or dataset contents were modified. "
                "ANALYST APPROVAL REQUIRED before any real action could be taken."
            )

        raise ResponseValidationError(
            f"No simulation handler exists for action type: {action_type}"
        )

    @staticmethod
    def _record_to_domain(record: PersistenceResponseAction) -> ResponseAction:
        return ResponseAction(
            action_id=record.action_id,
            incident_id=record.incident_id,
            action_type=record.action_type,
            status=ResponseActionStatus(record.status),
            requested_at=record.requested_at,
            approved_by=record.approved_by,
            executed_at=record.executed_at,
            result=record.result,
        )

    def _audit(
        self,
        action: str,
        target: str,
        actor: str,
        result: str,
        metadata: dict,
    ) -> None:
        now = datetime.now(timezone.utc)
        audit_seed = f"{action}:{target}:{actor}:{now.isoformat()}"
        audit_id = hashlib.sha256(audit_seed.encode("utf-8")).hexdigest()[:32]

        # Ensure metadata is json-serialized cleanly and free of raw passwords/tokens
        metadata_clean = {
            k: self.sanitize_text(str(v), 500) if isinstance(v, str) else v
            for k, v in metadata.items()
        }

        self.event_repository.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{audit_id}",
                timestamp=now,
                actor=actor,
                action=action,
                target=target,
                result=result,
                metadata_json=json.dumps(metadata_clean, sort_keys=True),
            )
        )
