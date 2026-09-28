# schemas.py – Pydantic models for IncidentForge alert records
"""Data validation schema for rows used by the IncidentForge risk model.

The synthetic generator and the real‑world CSVs share the same column order.  The
Pydantic model mirrors the 15 core features plus the optional mock‑dataset
features.  Only the core features are required – the mock columns can be omitted
or set to ``0.0``.
"""

from pydantic import BaseModel, Field

class AlertRecord(BaseModel):
    inc_sev: float = Field(..., ge=0, le=15, description="Incident severity")
    corr_sev: float = Field(..., ge=0, le=15, description="Correlation severity")
    alert_count: float = Field(..., ge=0)
    event_count: float = Field(..., ge=0)
    corr_count: float = Field(..., ge=0)
    mitre_count: float = Field(..., ge=0)
    has_auth: float = Field(..., ge=0, le=1)
    has_proc: float = Field(..., ge=0, le=1)
    has_net: float = Field(..., ge=0, le=1)
    has_priv: float = Field(..., ge=0, le=1)
    time_span: float = Field(..., ge=0)
    entity_diversity: float = Field(..., ge=0)
    # Optional mock features – default to 0.0 if missing
    has_dataset_activity: float = Field(0.0, ge=0, le=1)
    has_sensitive_data_access: float = Field(0.0, ge=0, le=1)
    has_bulk_export: float = Field(0.0, ge=0, le=1)
    has_dataset_exfiltration: float = Field(0.0, ge=0, le=1)
    dataset_sensitivity: float = Field(0.0, ge=0, le=1)
    records_accessed_normalized: float = Field(0.0, ge=0, le=1)
    records_modified_normalized: float = Field(0.0, ge=0, le=1)
    export_volume_normalized: float = Field(0.0, ge=0, le=1)
    sensitive_columns_count: float = Field(0.0, ge=0, le=1)
    actor_novelty: float = Field(0.0, ge=0, le=1)
    bulk_access_indicator: float = Field(0.0, ge=0, le=1)
    label: int = Field(..., ge=0, le=1, description="Target label (0 = benign, 1 = attack)")

    class Config:
        anystr_lowercase = True
        extra = "ignore"

