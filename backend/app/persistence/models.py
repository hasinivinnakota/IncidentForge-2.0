"""SQLModel persistence tables, separate from API/domain schemas."""

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class Event(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True, max_length=256)
    timestamp: datetime
    source: str = Field(max_length=128)
    event_type: str = Field(max_length=128)
    severity: int
    message: str
    host: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    metadata_json: str = "{}"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Alert(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    alert_id: str = Field(index=True, unique=True, max_length=256)
    event_id: str = Field(index=True, max_length=256)
    timestamp: datetime
    rule_id: str = Field(max_length=128)
    rule_name: str = Field(max_length=256)
    severity: int
    description: str
    source: str = Field(max_length=128)
    evidence_json: str = "{}"
    mitre_techniques_json: str = "[]"
    status: str = Field(default="new", max_length=32)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Correlation(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    correlation_id: str = Field(index=True, unique=True, max_length=256)
    correlation_type: str = Field(index=True, max_length=128)
    entity_key: str = Field(index=True, max_length=256)
    title: str = Field(max_length=256)
    description: str
    severity: int
    status: str = Field(default="open", max_length=32)
    first_seen: datetime
    last_seen: datetime
    alert_ids_json: str = "[]"
    event_ids_json: str = "[]"
    alert_count: int = 0
    mitre_techniques_json: str = "[]"
    evidence_json: str = "{}"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Incident(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    incident_id: str = Field(index=True, unique=True, max_length=256)
    title: str = Field(max_length=256)
    description: str
    severity: int
    status: str = Field(default="open", max_length=32)
    created_at: datetime
    updated_at: datetime
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    correlation_ids_json: str = "[]"
    alert_ids_json: str = "[]"
    event_ids_json: str = "[]"
    mitre_techniques_json: str = "[]"
    evidence_json: str = "{}"
    tags_json: str = "[]"


class RiskAssessment(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    assessment_id: str = Field(index=True, unique=True, max_length=256)
    incident_id: str = Field(index=True, max_length=256)
    risk_score: int
    risk_level: str = Field(max_length=32)
    model_name: str = Field(max_length=128)
    model_version: str = Field(max_length=64)
    feature_version: str = Field(max_length=64)
    scored_at: datetime
    features_json: str = "{}"
    reasons_json: str = "[]"
    feature_contributions_json: str = "{}"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatIntelEnrichment(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    enrichment_id: str = Field(index=True, unique=True, max_length=256)
    incident_id: str = Field(index=True, max_length=256)
    ioc_type: str = Field(index=True, max_length=32)
    ioc_value: str = Field(index=True, max_length=2048)
    classification: str = Field(max_length=32)
    confidence: int
    reputation: str = Field(max_length=64)
    threat_category: str = Field(default="", max_length=128)
    provider: str = Field(max_length=128)
    source_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags_json: str = "[]"
    explanation: str = ""
    lookup_timestamp: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Investigation(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    investigation_id: str = Field(index=True, unique=True, max_length=256)
    incident_id: str = Field(index=True, max_length=256)
    status: str = Field(default="completed", max_length=32)
    summary: str
    confidence: float
    findings_json: str = "[]"
    timeline_json: str = "[]"
    mitre_techniques_json: str = "[]"
    threat_intel_summary_json: str = "{}"
    investigation_gaps_json: str = "[]"
    recommended_next_steps_json: str = "[]"
    possible_response_actions_json: str = "[]"
    provider: str = Field(default="local_dev", max_length=64)
    model_name: str = Field(default="heuristic_deterministic_v1", max_length=128)
    generated_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResponseAction(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    action_id: str = Field(index=True, unique=True, max_length=256)
    incident_id: str = Field(index=True, max_length=256)
    action_type: str = Field(max_length=128)
    status: str = Field(default="proposed", max_length=32)
    requested_at: datetime
    approved_by: str | None = Field(default=None, max_length=256)
    executed_at: datetime | None = None
    result: str | None = None


class AuditEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    audit_id: str = Field(index=True, unique=True, max_length=256)
    timestamp: datetime
    actor: str = Field(max_length=256)
    action: str = Field(max_length=256)
    target: str = Field(max_length=256)
    result: str
    metadata_json: str = "{}"


class Case(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    case_id: str = Field(index=True, unique=True, max_length=256)
    title: str = Field(max_length=256)
    description: str
    severity: int
    priority: str = Field(default="medium", max_length=32)
    status: str = Field(default="open", max_length=32)
    assignee: str | None = Field(default=None, max_length=256)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    incident_ids_json: str = "[]"
    investigation_ids_json: str = "[]"
    tags_json: str = "[]"
    resolution_json: str | None = None


class CaseNoteRecord(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    note_id: str = Field(index=True, unique=True, max_length=256)
    case_id: str = Field(index=True, max_length=256)
    author: str = Field(max_length=256)
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceReferenceRecord(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    evidence_id: str = Field(index=True, unique=True, max_length=256)
    case_id: str = Field(index=True, max_length=256)
    evidence_type: str = Field(max_length=64)
    reference_key: str = Field(index=True, max_length=256)
    description: str = ""
    added_by: str = Field(max_length=256)
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SystemSettings(SQLModel, table=True):
    """Persisted dashboard settings for the local development deployment."""

    id: int | None = Field(default=None, primary_key=True)
    profile_name: str = Field(default="Admin User", max_length=256)
    profile_email: str = Field(default="admin@edms.com", max_length=320)
    tariff_rates_json: str = "[]"
    shifts_json: str = "[]"
    high_threshold: int = Field(default=50, ge=1, le=99)
    critical_threshold: int = Field(default=75, ge=2, le=100)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PersistenceDatasetAsset(SQLModel, table=True):
    __tablename__ = "dataset_asset"
    id: int | None = Field(default=None, primary_key=True)
    dataset_id: str = Field(index=True, unique=True, max_length=256)
    name: str = Field(max_length=256)
    format: str = Field(max_length=64)
    file_path: str
    size_bytes: int
    record_count: int
    column_count: int
    columns_json: str = "[]"
    sensitive_columns_json: str = "[]"
    sensitivity: str = Field(max_length=64)
    schema_hash: str = Field(max_length=128)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata_json: str = "{}"


class PersistenceDatasetActivity(SQLModel, table=True):
    __tablename__ = "dataset_activity"
    id: int | None = Field(default=None, primary_key=True)
    activity_id: str = Field(index=True, unique=True, max_length=256)
    timestamp: datetime
    dataset_id: str = Field(index=True, max_length=256)
    dataset_name: str = Field(max_length=256)
    operation: str = Field(max_length=128)
    actor: str = Field(index=True, max_length=256)
    actor_host: str = Field(max_length=256)
    source_ip: str = Field(max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    records_accessed: int
    records_modified: int
    sensitive_columns_json: str = "[]"
    export_size_bytes: int | None = None
    export_destination: str | None = None
