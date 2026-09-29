"""Deterministic feature extraction for IncidentForge ML Risk Scoring.

v2.0 extends v1.0 endpoint features with dataset security features.
All v1.0 feature names and semantics are preserved for backward compatibility.

Dataset features (v2.0 additions):
- has_dataset_activity: 1.0 if incident involves dataset operations
- has_sensitive_data_access: 1.0 if CRITICAL/HIGH sensitivity dataset was accessed
- has_bulk_export: 1.0 if bulk access or export operations occurred
- has_dataset_exfiltration: 1.0 if correlation links dataset ops with network/export activity
- dataset_sensitivity: 0.0=LOW, 0.25=MEDIUM, 0.5=HIGH, 1.0=CRITICAL (normalized)
- records_accessed_normalized: records_accessed / 100000 capped at 1.0
- records_modified_normalized: records_modified / 100000 capped at 1.0
- export_volume_normalized: export_size_bytes / 1000000000 (1GB cap) normalized
- sensitive_columns_count: count of distinct sensitive columns accessed, capped at 10
- actor_novelty: 1.0 if unusual/unknown actor detected
- bulk_access_indicator: 1.0 if bulk access rule fired

IMPORTANT: Feature version is bumped to v2.0; existing v1.0 features are preserved
with identical semantics. The model is not claimed to have improved production accuracy
unless evaluated on representative data.
"""

from typing import Any

from ..models.correlation import Correlation
from ..models.incidents import Incident

FEATURE_VERSION = "v2.0"

FEATURE_NAMES: list[str] = [
    # v1.0 endpoint features (unchanged)
    "incident_severity",
    "correlation_severity",
    "alert_count",
    "event_count",
    "correlation_count",
    "mitre_count",
    "has_auth_attack",
    "has_suspicious_process",
    "has_network_activity",
    "has_privilege_escalation",
    "time_span_seconds",
    "entity_diversity",
    # v2.0 dataset security features
    "has_dataset_activity",
    "has_sensitive_data_access",
    "has_bulk_export",
    "has_dataset_exfiltration",
    "dataset_sensitivity",
    "records_accessed_normalized",
    "records_modified_normalized",
    "export_volume_normalized",
    "sensitive_columns_count",
    "actor_novelty",
    "bulk_access_indicator",
]


def extract_features(
    incident: Incident,
    correlation: Correlation | None = None,
) -> dict[str, float]:
    """Extract bounded, numeric, deterministic features from an incident and its correlation.

    Strict security guarantees:
    - Never extracts passwords, tokens, API keys, credentials, or raw payloads.
    - All feature values are finite bounded floats.
    - v1.0 features remain fully backward compatible.
    """
    # 1. Incident severity [0 - 15]
    inc_sev = float(max(0, min(15, incident.severity)))

    # 2. Correlation severity [0 - 15]
    if correlation is not None:
        corr_sev = float(max(0, min(15, correlation.severity)))
    else:
        corr_sev = inc_sev

    # 3. Alert count (>= 0)
    alert_count = float(max(0, len(incident.alert_ids)))

    # 4. Event count (>= 0)
    event_count = float(max(0, len(incident.event_ids)))

    # 5. Correlation count (>= 0)
    corr_count = float(max(1, len(incident.correlation_ids)))

    # 6. MITRE count (>= 0)
    mitre_count = float(len(set(incident.mitre_techniques)))

    # Collect indicators from tags, description, and correlation type
    indicators_text = " ".join(
        incident.tags
        + [incident.title, incident.description]
        + ([correlation.correlation_type, correlation.title] if correlation else [])
    ).lower()

    # 7. Authentication attack
    has_auth = 1.0 if ("auth" in indicators_text or "login" in indicators_text) else 0.0

    # 8. Suspicious process
    has_proc = (
        1.0
        if ("process" in indicators_text or "exec" in indicators_text or ".sh" in indicators_text)
        else 0.0
    )

    # 9. Network activity
    has_net = (
        1.0
        if ("network" in indicators_text or "connection" in indicators_text or "outbound" in indicators_text)
        else 0.0
    )

    # 10. Privilege escalation
    has_priv = (
        1.0
        if ("privilege" in indicators_text or "escalat" in indicators_text or "root" in indicators_text)
        else 0.0
    )

    # 11. Time span seconds (>= 0)
    if incident.first_seen and incident.last_seen:
        span = (incident.last_seen - incident.first_seen).total_seconds()
        time_span = float(max(0.0, span))
    else:
        time_span = 0.0

    # 12. Entity diversity (distinct hosts / users / entities tagged, bounded [1 - 20])
    entity_diversity = float(max(1, min(20, len(set(incident.tags)))))

    # -------------------------------------------------------------------------
    # v2.0 Dataset security features
    # -------------------------------------------------------------------------
    dataset_keywords = (
        "dataset", "bulk_access", "sensitive_column", "exfiltrat",
        "export", "schema_change", "data_access", "data_exfil",
    )
    has_dataset = 1.0 if any(kw in indicators_text for kw in dataset_keywords) else 0.0

    evidence = incident.evidence if isinstance(incident.evidence, dict) else {}

    # 13. Has dataset activity indicator
    has_dataset_activity = has_dataset

    # 14. Sensitive data access (HIGH / CRITICAL sensitivity)
    sensitivity_str = str(evidence.get("dataset_sensitivity", "")).upper()
    has_sensitive = 1.0 if (
        sensitivity_str in ("HIGH", "CRITICAL")
        or "sensitive_data" in indicators_text
        or "sensitive_column" in indicators_text
    ) else 0.0

    # 15. Bulk export indicator
    has_bulk_export = 1.0 if (
        "bulk_access" in indicators_text
        or "export" in indicators_text
        or "exfil" in indicators_text
    ) else 0.0

    # 16. Dataset exfiltration (correlation linking dataset + network)
    has_dataset_exfil = 1.0 if (
        "exfiltrat" in indicators_text
        or "data_exfil" in indicators_text
        or ("dataset" in indicators_text and "network" in indicators_text)
        or ("dataset" in indicators_text and "export" in indicators_text)
    ) else 0.0

    # 17. Dataset sensitivity as normalized float
    sensitivity_map = {"LOW": 0.0, "MEDIUM": 0.25, "HIGH": 0.5, "CRITICAL": 1.0}
    dataset_sensitivity_val = sensitivity_map.get(sensitivity_str, 0.0)

    # 18. Records accessed (normalized 0.0 - 1.0, cap at 100,000)
    records_accessed = float(max(0, int(evidence.get("records_accessed", 0))))
    records_accessed_norm = min(1.0, records_accessed / 100_000.0)

    # 19. Records modified (normalized 0.0 - 1.0, cap at 100,000)
    records_modified = float(max(0, int(evidence.get("records_modified", 0))))
    records_modified_norm = min(1.0, records_modified / 100_000.0)

    # 20. Export volume (normalized 0.0 - 1.0, cap at 1GB)
    export_bytes = float(max(0, int(evidence.get("export_size_bytes", 0))))
    export_vol_norm = min(1.0, export_bytes / 1_000_000_000.0)

    # 21. Sensitive columns count (bounded 0 - 10)
    sens_cols = evidence.get("sensitive_columns", [])
    if isinstance(sens_cols, list):
        sens_col_count = float(min(10, len(sens_cols)))
    else:
        sens_col_count = 0.0

    # 22. Actor novelty (unusual actor detection)
    actor_novelty = 1.0 if "unusual" in indicators_text or "anomaly" in indicators_text else 0.0

    # 23. Bulk access indicator
    bulk_access_ind = 1.0 if (
        "bulk_access" in indicators_text
        or "bulk_sensitive" in indicators_text
    ) else 0.0

    return {
        # v1.0 features
        "incident_severity": inc_sev,
        "correlation_severity": corr_sev,
        "alert_count": alert_count,
        "event_count": event_count,
        "correlation_count": corr_count,
        "mitre_count": mitre_count,
        "has_auth_attack": has_auth,
        "has_suspicious_process": has_proc,
        "has_network_activity": has_net,
        "has_privilege_escalation": has_priv,
        "time_span_seconds": time_span,
        "entity_diversity": entity_diversity,
        # v2.0 dataset features
        "has_dataset_activity": has_dataset_activity,
        "has_sensitive_data_access": has_sensitive,
        "has_bulk_export": has_bulk_export,
        "has_dataset_exfiltration": has_dataset_exfil,
        "dataset_sensitivity": dataset_sensitivity_val,
        "records_accessed_normalized": records_accessed_norm,
        "records_modified_normalized": records_modified_norm,
        "export_volume_normalized": export_vol_norm,
        "sensitive_columns_count": sens_col_count,
        "actor_novelty": actor_novelty,
        "bulk_access_indicator": bulk_access_ind,
    }


def generate_reason_codes(
    features: dict[str, float],
    risk_score: int,
) -> list[str]:
    """Generate deterministic explainability reason codes from extracted feature signals.

    Includes both v1.0 endpoint reasons and v2.0 dataset security reasons.
    """
    reasons: list[str] = []

    # v1.0 reason codes (unchanged)
    if features.get("has_privilege_escalation", 0.0) >= 1.0:
        reasons.append("PRIVILEGE_ESCALATION")

    if features.get("has_suspicious_process", 0.0) >= 1.0:
        reasons.append("SUSPICIOUS_PROCESS_ACTIVITY")

    if features.get("has_network_activity", 0.0) >= 1.0:
        reasons.append("NETWORK_ACTIVITY")

    if features.get("has_auth_attack", 0.0) >= 1.0:
        reasons.append("AUTHENTICATION_ATTACK")

    if features.get("mitre_count", 0.0) >= 2.0:
        reasons.append("MULTIPLE_MITRE_TECHNIQUES")

    if features.get("alert_count", 0.0) >= 3.0:
        reasons.append("HIGH_ALERT_VOLUME")

    if features.get("correlation_severity", 0.0) >= 10.0:
        reasons.append("HIGH_CORRELATION_SEVERITY")

    if features.get("incident_severity", 0.0) >= 10.0:
        reasons.append("HIGH_INCIDENT_SEVERITY")

    # v2.0 dataset reason codes
    if features.get("has_dataset_exfiltration", 0.0) >= 1.0:
        reasons.append("DATASET_EXFILTRATION_RISK")

    if features.get("has_sensitive_data_access", 0.0) >= 1.0:
        reasons.append("SENSITIVE_DATASET_ACCESS")

    if features.get("has_bulk_export", 0.0) >= 1.0:
        reasons.append("BULK_DATA_EXPORT")

    if features.get("dataset_sensitivity", 0.0) >= 1.0:
        reasons.append("CRITICAL_SENSITIVITY_DATASET")

    if features.get("records_accessed_normalized", 0.0) >= 0.5:
        reasons.append("HIGH_RECORD_VOLUME_ACCESSED")

    if features.get("sensitive_columns_count", 0.0) >= 3.0:
        reasons.append("MULTIPLE_SENSITIVE_COLUMNS")

    if features.get("actor_novelty", 0.0) >= 1.0:
        reasons.append("UNUSUAL_ACTOR_DETECTED")

    if not reasons:
        reasons.append("BASELINE_RISK_FACTORS")

    return sorted(reasons)
