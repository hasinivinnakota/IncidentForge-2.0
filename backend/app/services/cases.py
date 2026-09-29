"""SOC Case Management service.

Orchestrates Case creation, incident association, evidence referencing,
append-only analyst notes, state machine lifecycle transitions, resolution,
audit event logging, and timeline reconstruction.

Security & Architectural Guarantees:
- Downstream operational layer: Never mutates Incident severity, Alert, Event,
  or ML RiskAssessment score.
- AI advisory isolation: AI cannot modify cases or transition their statuses.
- Sanitizes all analyst free-text input (stripping credentials/tokens with [REDACTED]).
- Strict lifecycle state machine:
  OPEN -> IN_PROGRESS
  IN_PROGRESS -> PENDING, RESOLVED, OPEN
  PENDING -> IN_PROGRESS, RESOLVED
  RESOLVED -> CLOSED, IN_PROGRESS
  CLOSED -> IN_PROGRESS
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
from uuid import uuid4

from ..models.cases import (
    Case,
    CaseNote,
    CasePriority,
    CaseResolution,
    CaseStatus,
    CaseTimelineEntry,
    EvidenceReference,
    EvidenceType,
)
from ..persistence.models import AuditEvent
from ..persistence.repositories import (
    CaseRepository,
    EventRepository,
    IncidentRepository,
    InvestigationRepository,
)

logger = logging.getLogger(__name__)

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "credential",
    "private_key",
)

# Strict state transition matrix
ALLOWED_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.OPEN: {CaseStatus.IN_PROGRESS},
    CaseStatus.IN_PROGRESS: {CaseStatus.PENDING, CaseStatus.RESOLVED, CaseStatus.OPEN},
    CaseStatus.PENDING: {CaseStatus.IN_PROGRESS, CaseStatus.RESOLVED},
    CaseStatus.RESOLVED: {CaseStatus.CLOSED, CaseStatus.IN_PROGRESS},
    CaseStatus.CLOSED: {CaseStatus.IN_PROGRESS},
}


class CaseService:
    """Manages Case domain lifecycle, persistence, notes, evidence, and audit events."""

    def __init__(
        self,
        case_repository: CaseRepository,
        event_repository: EventRepository,
        incident_repository: IncidentRepository | None = None,
        investigation_repository: InvestigationRepository | None = None,
    ):
        self._case_repo = case_repository
        self._event_repo = event_repository
        self._incident_repo = incident_repository
        self._investigation_repo = investigation_repository

    @staticmethod
    def generate_incident_seeded_case_id(incident_id: str) -> str:
        """Deterministic ID for incident-seeded case creation."""
        digest = hashlib.sha256(f"case:{incident_id}".encode()).hexdigest()[:16]
        return f"case-{digest}"

    @staticmethod
    def generate_standalone_case_id() -> str:
        """Collision-safe identifier for standalone manually-created cases."""
        return f"case-{uuid4().hex[:16]}"

    @staticmethod
    def sanitize_text(text: str | None, max_length: int = 5000) -> str:
        """Sanitize text by stripping whitespace, bounding length, and redacting credentials."""
        if not text:
            return ""
        sanitized = str(text).strip()
        for pattern in SENSITIVE_KEY_SUBSTRINGS:
            sanitized = re.sub(re.escape(pattern), "[REDACTED]", sanitized, flags=re.IGNORECASE)
        return sanitized[:max_length]

    def create_case(
        self,
        title: str,
        description: str,
        severity: int,
        priority: CasePriority = CasePriority.MEDIUM,
        incident_id: str | None = None,
        tags: list[str] | None = None,
        actor: str = "analyst",
    ) -> Case:
        """Create a new Case. If incident_id is given, uses deterministic ID and links incident/investigation."""
        now = datetime.now(timezone.utc)
        sanitized_title = self.sanitize_text(title, 256)
        sanitized_desc = self.sanitize_text(description, 5000)
        bounded_severity = max(0, min(15, severity))
        cleaned_tags = [self.sanitize_text(t, 64) for t in (tags or [])][:20]

        incident_ids: list[str] = []
        investigation_ids: list[str] = []
        first_seen = now
        last_seen = now

        if incident_id:
            case_id = self.generate_incident_seeded_case_id(incident_id)
            existing = self.get_case(case_id)
            if existing:
                return existing

            incident_ids.append(incident_id)
            # Inspect incident if repo is available
            if self._incident_repo:
                inc = self._incident_repo.get_incident(incident_id)
                if inc:
                    first_seen = inc.first_seen or now
                    last_seen = inc.last_seen or now
                    # Link incident tags
                    if inc.tags_json:
                        inc_tags = json.loads(inc.tags_json)
                        for it in inc_tags:
                            if it not in cleaned_tags:
                                cleaned_tags.append(self.sanitize_text(it, 64))

            # Inspect latest investigation for incident if available
            if self._investigation_repo:
                inv = self._investigation_repo.get_latest_for_incident(incident_id)
                if inv and inv.investigation_id not in investigation_ids:
                    investigation_ids.append(inv.investigation_id)
        else:
            case_id = self.generate_standalone_case_id()

        domain_case = Case(
            case_id=case_id,
            title=sanitized_title,
            description=sanitized_desc,
            severity=bounded_severity,
            priority=priority,
            status=CaseStatus.OPEN,
            assignee=None,
            created_at=now,
            updated_at=now,
            first_seen=first_seen,
            last_seen=last_seen,
            incident_ids=incident_ids,
            investigation_ids=investigation_ids,
            tags=cleaned_tags,
            notes=[],
            evidence_references=[],
            resolution=None,
        )

        write_res = self._case_repo.create_case(domain_case)

        # Log audit: case.created
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor=actor,
                action="case.created",
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "title": sanitized_title,
                        "severity": bounded_severity,
                        "priority": priority.value,
                        "incident_id": incident_id,
                    },
                    sort_keys=True,
                ),
            )
        )

        # If incident was linked, also link as evidence reference
        if incident_id:
            self.link_evidence(
                case_id=case_id,
                evidence_type=EvidenceType.INCIDENT,
                reference_key=incident_id,
                description="Primary incident seeding case creation",
                added_by=actor,
            )

        return self.get_case(case_id) or domain_case

    def get_case(self, case_id: str) -> Case | None:
        """Retrieve full domain Case assembling normalized notes and evidence references."""
        record = self._case_repo.get_case(case_id)
        if not record:
            return None
        return self._record_to_domain(record)

    def list_cases(
        self,
        status: str | None = None,
        priority: str | None = None,
        assignee: str | None = None,
        limit: int = 100,
    ) -> list[Case]:
        """List cases with optional filters."""
        records = self._case_repo.list_cases(
            status=status, priority=priority, assignee=assignee, limit=limit
        )
        return [self._record_to_domain(r) for r in records]

    def update_case(
        self,
        case_id: str,
        title: str | None = None,
        description: str | None = None,
        priority: CasePriority | None = None,
        tags: list[str] | None = None,
        actor: str = "analyst",
    ) -> Case | None:
        """Update general case properties."""
        current = self.get_case(case_id)
        if not current:
            return None

        updated_title = self.sanitize_text(title, 256) if title is not None else current.title
        updated_desc = self.sanitize_text(description, 5000) if description is not None else current.description
        updated_priority = priority if priority is not None else current.priority
        updated_tags = (
            [self.sanitize_text(t, 64) for t in tags][:20] if tags is not None else current.tags
        )

        current.title = updated_title
        current.description = updated_desc
        current.priority = updated_priority
        current.tags = updated_tags
        current.updated_at = datetime.now(timezone.utc)

        self._case_repo.update_case(current)

        # Log audit: case.updated
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=current.updated_at,
                actor=actor,
                action="case.updated",
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "title": updated_title,
                        "priority": updated_priority.value,
                    },
                    sort_keys=True,
                ),
            )
        )

        return self.get_case(case_id)

    def assign_case(self, case_id: str, assignee: str | None, actor: str = "analyst") -> Case | None:
        """Assign or reassign a case to an analyst."""
        current = self.get_case(case_id)
        if not current:
            return None

        sanitized_assignee = self.sanitize_text(assignee, 256) if assignee else None
        current.assignee = sanitized_assignee
        current.updated_at = datetime.now(timezone.utc)

        self._case_repo.update_case(current)

        # Log audit: case.assigned
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=current.updated_at,
                actor=actor,
                action="case.assigned",
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "assignee": sanitized_assignee,
                    },
                    sort_keys=True,
                ),
            )
        )

        return self.get_case(case_id)

    def transition_status(
        self,
        case_id: str,
        new_status: CaseStatus,
        reason: str | None = None,
        actor: str = "analyst",
    ) -> Case:
        """Transition case status according to state machine.

        Raises ValueError on invalid transitions.
        """
        current = self.get_case(case_id)
        if not current:
            raise ValueError(f"Case '{case_id}' not found")

        old_status = current.status
        if new_status == old_status:
            return current

        allowed_targets = ALLOWED_TRANSITIONS.get(old_status, set())
        if new_status not in allowed_targets:
            raise ValueError(
                f"Invalid status transition from '{old_status.value}' to '{new_status.value}'. "
                f"Allowed transitions: {[s.value for s in allowed_targets]}."
            )

        # Additional constraints: closing requires prior resolution
        if new_status == CaseStatus.CLOSED and current.resolution is None:
            raise ValueError("Cannot close case that has not been resolved. Resolve the case first.")

        now = datetime.now(timezone.utc)
        current.status = new_status
        current.updated_at = now

        self._case_repo.update_case(current)

        action_name = "case.closed" if new_status == CaseStatus.CLOSED else "case.status_changed"
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor=actor,
                action=action_name,
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "old_status": old_status.value,
                        "new_status": new_status.value,
                        "reason": self.sanitize_text(reason, 500) if reason else "",
                    },
                    sort_keys=True,
                ),
            )
        )

        return self.get_case(case_id) or current

    def resolve_case(
        self,
        case_id: str,
        summary: str,
        root_cause: str = "",
        action_taken: str = "",
        resolver: str = "analyst",
    ) -> Case:
        """Resolve a case with required resolution summary and actor attribution."""
        current = self.get_case(case_id)
        if not current:
            raise ValueError(f"Case '{case_id}' not found")

        # Allowed transitions to RESOLVED: IN_PROGRESS or PENDING
        if current.status not in (CaseStatus.IN_PROGRESS, CaseStatus.PENDING):
            raise ValueError(
                f"Cannot resolve case in '{current.status.value}' state. "
                "Case must be in 'in_progress' or 'pending' state."
            )

        sanitized_summary = self.sanitize_text(summary, 3000)
        if not sanitized_summary:
            raise ValueError("Resolution summary is required.")

        now = datetime.now(timezone.utc)
        resolution = CaseResolution(
            summary=sanitized_summary,
            root_cause=self.sanitize_text(root_cause, 2000),
            action_taken=self.sanitize_text(action_taken, 2000),
            resolved_by=self.sanitize_text(resolver, 256),
            resolved_at=now,
        )

        current.resolution = resolution
        current.status = CaseStatus.RESOLVED
        current.updated_at = now

        self._case_repo.update_case(current)

        # Log audit: case.resolved
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor=resolver,
                action="case.resolved",
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "summary": sanitized_summary[:256],
                        "resolver": resolver,
                    },
                    sort_keys=True,
                ),
            )
        )

        return self.get_case(case_id) or current

    def add_note(self, case_id: str, content: str, author: str) -> CaseNote:
        """Add append-only analyst note."""
        current = self.get_case(case_id)
        if not current:
            raise ValueError(f"Case '{case_id}' not found")

        sanitized_content = self.sanitize_text(content, 5000)
        if not sanitized_content:
            raise ValueError("Note content cannot be empty.")

        now = datetime.now(timezone.utc)
        note_id = f"note-{uuid4().hex[:16]}"
        note = CaseNote(
            note_id=note_id,
            case_id=case_id,
            author=self.sanitize_text(author, 256),
            content=sanitized_content,
            created_at=now,
            updated_at=now,
        )

        self._case_repo.add_note(note)

        # Update case updated_at
        current.updated_at = now
        self._case_repo.update_case(current)

        # Log audit: case.note_added
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor=author,
                action="case.note_added",
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "note_id": note_id,
                        "author": author,
                    },
                    sort_keys=True,
                ),
            )
        )

        return note

    def list_notes(self, case_id: str, limit: int = 100) -> list[CaseNote]:
        """List notes for a case."""
        records = self._case_repo.list_notes_by_case(case_id, limit=limit)
        return [
            CaseNote(
                note_id=r.note_id,
                case_id=r.case_id,
                author=r.author,
                content=r.content,
                created_at=r.created_at.replace(tzinfo=timezone.utc)
                if r.created_at and r.created_at.tzinfo is None
                else r.created_at,
                updated_at=r.updated_at.replace(tzinfo=timezone.utc)
                if r.updated_at and r.updated_at.tzinfo is None
                else r.updated_at,
            )
            for r in records
        ]

    def link_evidence(
        self,
        case_id: str,
        evidence_type: EvidenceType,
        reference_key: str,
        description: str = "",
        added_by: str = "analyst",
    ) -> EvidenceReference:
        """Link evidence reference idempotently without duplicating raw telemetry."""
        current = self.get_case(case_id)
        if not current:
            raise ValueError(f"Case '{case_id}' not found")

        now = datetime.now(timezone.utc)
        evidence_id = (
            f"evref-{hashlib.sha256(f'{case_id}:{evidence_type.value}:{reference_key}'.encode()).hexdigest()[:16]}"
        )

        ref = EvidenceReference(
            evidence_id=evidence_id,
            case_id=case_id,
            evidence_type=evidence_type,
            reference_key=reference_key,
            description=self.sanitize_text(description, 1000),
            added_by=self.sanitize_text(added_by, 256),
            added_at=now,
        )

        saved = self._case_repo.add_evidence_reference(ref)

        # Also update case incident_ids or investigation_ids if relevant
        if evidence_type == EvidenceType.INCIDENT and reference_key not in current.incident_ids:
            current.incident_ids.append(reference_key)
            self._case_repo.update_case(current)
            self._event_repo.create_audit_event(
                AuditEvent(
                    audit_id=f"audit-{uuid4()}",
                    timestamp=now,
                    actor=added_by,
                    action="case.incident_linked",
                    target=case_id,
                    result="accepted",
                    metadata_json=json.dumps(
                        {"case_id": case_id, "incident_id": reference_key}, sort_keys=True
                    ),
                )
            )
        elif evidence_type == EvidenceType.INVESTIGATION and reference_key not in current.investigation_ids:
            current.investigation_ids.append(reference_key)
            self._case_repo.update_case(current)
            self._event_repo.create_audit_event(
                AuditEvent(
                    audit_id=f"audit-{uuid4()}",
                    timestamp=now,
                    actor=added_by,
                    action="case.investigation_linked",
                    target=case_id,
                    result="accepted",
                    metadata_json=json.dumps(
                        {"case_id": case_id, "investigation_id": reference_key}, sort_keys=True
                    ),
                )
            )

        # Log audit: case.evidence_linked
        self._event_repo.create_audit_event(
            AuditEvent(
                audit_id=f"audit-{uuid4()}",
                timestamp=now,
                actor=added_by,
                action="case.evidence_linked",
                target=case_id,
                result="accepted",
                metadata_json=json.dumps(
                    {
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "evidence_type": evidence_type.value,
                        "reference_key": reference_key,
                    },
                    sort_keys=True,
                ),
            )
        )

        return EvidenceReference(
            evidence_id=saved.evidence_id,
            case_id=saved.case_id,
            evidence_type=EvidenceType(saved.evidence_type),
            reference_key=saved.reference_key,
            description=saved.description,
            added_by=saved.added_by,
            added_at=saved.added_at.replace(tzinfo=timezone.utc)
            if saved.added_at and saved.added_at.tzinfo is None
            else saved.added_at,
        )

    def get_timeline(self, case_id: str) -> list[CaseTimelineEntry]:
        """Derive chronological case timeline from audit events without maintaining a secondary store."""
        current = self.get_case(case_id)
        if not current:
            raise ValueError(f"Case '{case_id}' not found")

        audit_records = self._event_repo.list_audit_events(target=case_id)
        timeline: list[CaseTimelineEntry] = []

        for aud in audit_records:
            meta = json.loads(aud.metadata_json) if aud.metadata_json else {}
            action_desc = f"Action '{aud.action}' performed by {aud.actor}"
            if aud.action == "case.created":
                action_desc = f"Case created with priority {meta.get('priority', 'medium')}"
            elif aud.action == "case.status_changed":
                action_desc = f"Status changed from {meta.get('old_status')} to {meta.get('new_status')}"
            elif aud.action == "case.assigned":
                action_desc = f"Case assigned to {meta.get('assignee')}"
            elif aud.action == "case.resolved":
                action_desc = f"Case resolved: {meta.get('summary', '')}"
            elif aud.action == "case.closed":
                action_desc = "Case closed"
            elif aud.action == "case.note_added":
                action_desc = f"Analyst note added by {aud.actor}"
            elif aud.action == "case.evidence_linked":
                action_desc = f"Evidence linked: {meta.get('evidence_type')} ({meta.get('reference_key')})"
            elif aud.action == "case.incident_linked":
                action_desc = f"Incident {meta.get('incident_id')} linked"
            elif aud.action == "case.investigation_linked":
                action_desc = f"AI Investigation {meta.get('investigation_id')} linked"

            clean_meta = {str(k): str(v) for k, v in meta.items()}

            timeline.append(
                CaseTimelineEntry(
                    timestamp=aud.timestamp.replace(tzinfo=timezone.utc)
                    if aud.timestamp and aud.timestamp.tzinfo is None
                    else aud.timestamp,
                    action=aud.action,
                    actor=aud.actor,
                    description=action_desc[:1000],
                    metadata=clean_meta,
                )
            )

        return timeline

    def _record_to_domain(self, record) -> Case:
        """Convert persistence Case row into domain Case, fetching normalized notes and evidence."""
        notes = self.list_notes(record.case_id)
        evidence_records = self._case_repo.list_evidence_by_case(record.case_id)
        evidence_references = [
            EvidenceReference(
                evidence_id=e.evidence_id,
                case_id=e.case_id,
                evidence_type=EvidenceType(e.evidence_type),
                reference_key=e.reference_key,
                description=e.description,
                added_by=e.added_by,
                added_at=e.added_at.replace(tzinfo=timezone.utc)
                if e.added_at and e.added_at.tzinfo is None
                else e.added_at,
            )
            for e in evidence_records
        ]

        resolution = None
        if record.resolution_json:
            res_dict = json.loads(record.resolution_json)
            if "resolved_at" in res_dict and isinstance(res_dict["resolved_at"], str):
                res_dict["resolved_at"] = datetime.fromisoformat(res_dict["resolved_at"])
            resolution = CaseResolution(**res_dict)

        return Case(
            case_id=record.case_id,
            title=record.title,
            description=record.description,
            severity=record.severity,
            priority=CasePriority(record.priority),
            status=CaseStatus(record.status),
            assignee=record.assignee,
            created_at=record.created_at.replace(tzinfo=timezone.utc)
            if record.created_at and record.created_at.tzinfo is None
            else record.created_at,
            updated_at=record.updated_at.replace(tzinfo=timezone.utc)
            if record.updated_at and record.updated_at.tzinfo is None
            else record.updated_at,
            first_seen=record.first_seen.replace(tzinfo=timezone.utc)
            if record.first_seen and record.first_seen.tzinfo is None
            else record.first_seen,
            last_seen=record.last_seen.replace(tzinfo=timezone.utc)
            if record.last_seen and record.last_seen.tzinfo is None
            else record.last_seen,
            incident_ids=json.loads(record.incident_ids_json) if record.incident_ids_json else [],
            investigation_ids=json.loads(record.investigation_ids_json)
            if record.investigation_ids_json
            else [],
            tags=json.loads(record.tags_json) if record.tags_json else [],
            notes=notes,
            evidence_references=evidence_references,
            resolution=resolution,
        )
