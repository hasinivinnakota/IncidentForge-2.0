"""Dataset Security Assessment Service for IncidentForge v2.

Runs a deterministic, rule-based security assessment against a dataset profile.

DESIGN PRINCIPLES:
- Purely deterministic: same input → same output every time.
- No ML model, no external network calls, no subprocess execution.
- Separate from the incident ML risk model.
- Results are explainable and human-readable.
- Sensitive-field detection is heuristic — labels probable, not guaranteed.

SECURITY SCORE (0–100, higher score = lower risk):
  Starts at 100. Deductions applied per finding severity:
    CRITICAL: −25
    HIGH:     −15
    MEDIUM:   −8
    LOW:      −3
  Clamped to [0, 100].

RISK LEVEL derived from score:
  ≥80  → LOW
  ≥60  → MEDIUM
  ≥40  → HIGH
  <40  → CRITICAL
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from ..models.dataset import ColumnProfile, DatasetAsset, SensitivityLevel
from ..models.dataset_assessment import (
    DatasetFinding,
    DatasetSecurityAssessment,
    DatasetSecurityScore,
    FindingSeverity,
    SecurityCheckResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Heuristic patterns for sensitive / dangerous column naming
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pw|passphrase)\b"),
    re.compile(r"(?i)\b(secret|secret_key|private_key|priv_key)\b"),
    re.compile(r"(?i)\b(api_key|apikey|access_key|access_token|auth_token|bearer_token)\b"),
    re.compile(r"(?i)\b(session_token|session_key|session_id)\b"),
    re.compile(r"(?i)\b(client_secret|oauth_secret|jwt_secret)\b"),
    re.compile(r"(?i)\b(encryption_key|aes_key|hmac_key)\b"),
]

_HIGH_RISK_PATTERNS = [
    re.compile(r"(?i)\b(ssn|social_security|national_id|tax_id|sin|aadhaar|aadhar|pan_number)\b"),
    re.compile(r"(?i)\b(credit_card|card_number|card_num|cvv|cvc|ccv|bank_account|account_number|account_num|iban|routing_number|swift)\b"),
    re.compile(r"(?i)\b(salary|payroll|compensation|wage|annual_income|gross_income|net_income|bonus)\b"),
    re.compile(r"(?i)\b(medical_record|health_id|patient_id|diagnosis|prescription)\b"),
    re.compile(r"(?i)\b(biometric|fingerprint|face_id|iris_scan)\b"),
]

_MEDIUM_RISK_PATTERNS = [
    re.compile(r"(?i)\b(email|email_address|mail)\b"),
    re.compile(r"(?i)\b(phone|telephone|mobile|cell|contact_number)\b"),
    re.compile(r"(?i)\b(address|street|zip|postal_code|postcode)\b"),
    re.compile(r"(?i)\b(date_of_birth|dob|birth_date|birthdate)\b"),
    re.compile(r"(?i)\b(customer_id|client_id|user_id|account_id|member_id)\b"),
    re.compile(r"(?i)\b(passport|driver_license|driving_license|license_number)\b"),
    re.compile(r"(?i)\b(full_name|first_name|last_name|surname|given_name)\b"),
    re.compile(r"(?i)\b(transaction|payment|transfer|withdrawal)\b"),
    re.compile(r"(?i)\b(ip_address|mac_address|device_id)\b"),
]

_SCORE_DEDUCTIONS = {
    FindingSeverity.CRITICAL: 25,
    FindingSeverity.HIGH: 15,
    FindingSeverity.MEDIUM: 8,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 0,
}


def _col_norm(name: str) -> str:
    return name.strip().lower().replace("-", "_").replace(" ", "_")


def _matches_any(col_name: str, patterns: list[re.Pattern]) -> bool:
    n = _col_norm(col_name)
    return any(p.search(n) for p in patterns)


class DatasetAssessmentService:
    """Runs a deterministic security assessment against a profiled DatasetAsset."""

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    def assess(self, asset: DatasetAsset) -> DatasetSecurityAssessment:
        """Run all security checks and return a structured assessment."""
        assessment_id = f"assess-{hashlib.sha256(asset.dataset_id.encode()).hexdigest()[:12]}"
        findings: list[DatasetFinding] = []
        checks: list[SecurityCheckResult] = []

        # Run each check in order
        findings.extend(self._check_secret_fields(asset, checks))
        findings.extend(self._check_high_risk_fields(asset, checks))
        findings.extend(self._check_medium_risk_fields(asset, checks))
        findings.extend(self._check_null_heavy_sensitive(asset, checks))
        findings.extend(self._check_schema_anomalies(asset, checks))
        findings.extend(self._check_sensitivity_classification(asset, checks))
        self._check_format_validity(asset, checks)
        self._check_schema_consistency(asset, checks)
        checks.append(SecurityCheckResult(
            check_name="Sensitive-field analysis",
            passed=True,
            detail=f"{len(asset.sensitive_columns)} probable sensitive column(s) classified heuristically",
        ))

        # Compute score
        score_obj = self._compute_score(findings, asset)
        checks.append(SecurityCheckResult(
            check_name="Risk scoring",
            passed=True,
            detail=f"Deterministic score {score_obj.score}/100 ({score_obj.risk_level})",
        ))

        # Count by severity
        counts = {sev: 0 for sev in FindingSeverity}
        for f in findings:
            counts[f.severity] += 1

        return DatasetSecurityAssessment(
            assessment_id=assessment_id,
            dataset_id=asset.dataset_id,
            dataset_name=asset.name,
            asset=asset,
            findings=findings,
            security_score=score_obj,
            checks_performed=checks,
            critical_findings=counts[FindingSeverity.CRITICAL],
            high_findings=counts[FindingSeverity.HIGH],
            medium_findings=counts[FindingSeverity.MEDIUM],
            low_findings=counts[FindingSeverity.LOW],
            info_findings=counts[FindingSeverity.INFO],
            assessed_at=datetime.now(timezone.utc),
        )

    # -----------------------------------------------------------------------
    # Individual checks
    # -----------------------------------------------------------------------

    def _check_secret_fields(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> list[DatasetFinding]:
        findings: list[DatasetFinding] = []
        secret_cols = [c.name for c in asset.columns if _matches_any(c.name, _SECRET_PATTERNS)]

        if secret_cols:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-secret-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.CRITICAL,
                    title="Secret-like or credential field detected",
                    description=(
                        f"Columns with names matching secret/credential patterns were found: "
                        f"{secret_cols}. These may contain passwords, API keys, or tokens. "
                        "Raw values have NOT been read or stored — this finding is based solely on column naming heuristics."
                    ),
                    affected_columns=secret_cols,
                    recommendation=(
                        "Remove credential columns from this dataset. "
                        "Secrets should never be stored in data files. "
                        "Rotate any exposed credentials immediately."
                    ),
                    evidence_summary=(
                        f"{len(secret_cols)} column(s) with secret-like names detected. "
                        "[REDACTED SECRET-LIKE VALUE DETECTED] — raw values are never stored."
                    ),
                )
            )
            checks.append(SecurityCheckResult(
                check_name="Secret-like field scan",
                passed=False,
                severity=FindingSeverity.CRITICAL,
                detail=f"Detected: {secret_cols}",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="Secret-like field scan",
                passed=True,
                detail="No secret-like column names found",
            ))
        return findings

    def _check_high_risk_fields(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> list[DatasetFinding]:
        findings: list[DatasetFinding] = []
        high_cols = [c.name for c in asset.columns if _matches_any(c.name, _HIGH_RISK_PATTERNS)]

        if high_cols:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-highrisk-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.HIGH,
                    title="Highly sensitive identifier fields detected",
                    description=(
                        f"Columns with high-risk sensitivity patterns (financial identifiers, "
                        f"government IDs, medical records) detected: {high_cols}. "
                        "Detection is heuristic — based on column naming only."
                    ),
                    affected_columns=high_cols,
                    recommendation=(
                        "Apply strict access controls, encryption at rest, and audit logging "
                        "for datasets containing financial or government identifier fields. "
                        "Consider pseudonymization or tokenization where appropriate."
                    ),
                    evidence_summary=f"{len(high_cols)} high-risk column(s) by name heuristic",
                )
            )
            checks.append(SecurityCheckResult(
                check_name="High-risk identifier scan",
                passed=False,
                severity=FindingSeverity.HIGH,
                detail=f"Detected: {high_cols}",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="High-risk identifier scan",
                passed=True,
                detail="No high-risk identifier column names found",
            ))
        return findings

    def _check_medium_risk_fields(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> list[DatasetFinding]:
        findings: list[DatasetFinding] = []
        med_cols = [
            c.name for c in asset.columns
            if _matches_any(c.name, _MEDIUM_RISK_PATTERNS)
            and not _matches_any(c.name, _HIGH_RISK_PATTERNS)
            and not _matches_any(c.name, _SECRET_PATTERNS)
        ]

        if med_cols:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-pii-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.MEDIUM,
                    title="Probable PII fields detected (heuristic)",
                    description=(
                        f"Columns with names matching probable PII patterns (email, phone, "
                        f"address, customer ID, name) detected: {med_cols}. "
                        "This is a heuristic scan — actual PII presence depends on data content."
                    ),
                    affected_columns=med_cols,
                    recommendation=(
                        "Ensure data subjects have consented to storage and processing. "
                        "Apply data minimization — only retain fields necessary for the stated purpose. "
                        "Consider anonymization or pseudonymization for analysis datasets."
                    ),
                    evidence_summary=f"{len(med_cols)} probable PII column(s) by name heuristic",
                )
            )
            checks.append(SecurityCheckResult(
                check_name="PII heuristic scan",
                passed=False,
                severity=FindingSeverity.MEDIUM,
                detail=f"Probable PII columns: {med_cols}",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="PII heuristic scan",
                passed=True,
                detail="No probable PII column names detected",
            ))
        return findings

    def _check_null_heavy_sensitive(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> list[DatasetFinding]:
        """Flag sensitive columns with high null ratios or unresolved types."""
        findings: list[DatasetFinding] = []
        column_stats = asset.metadata.get("column_stats") if isinstance(asset.metadata, dict) else {}
        if not isinstance(column_stats, dict):
            column_stats = {}

        null_heavy = []
        duplicate_heavy = []
        for col in asset.columns:
            stats = column_stats.get(col.name) if isinstance(column_stats.get(col.name), dict) else {}
            null_ratio = float(stats.get("null_ratio", 0) or 0)
            dup_ratio = float(stats.get("duplicate_ratio", 0) or 0)
            if col.is_sensitive and null_ratio >= 0.5:
                null_heavy.append(col.name)
            identifier_like = (col.pii_type or "").lower() in {
                "customer_id",
                "account_id",
                "ssn",
                "email",
                "pan",
                "passport",
            } or "id" in col.name.lower()
            if col.is_sensitive and identifier_like and dup_ratio >= 0.6:
                duplicate_heavy.append(col.name)

        if null_heavy:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-null-sensitive-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.MEDIUM,
                    title="Null-heavy sensitive columns",
                    description=(
                        f"Sensitive columns with a high null ratio in the sampled rows: {null_heavy}. "
                        "Incomplete sensitive identifiers can indicate quality issues or partial masking."
                    ),
                    affected_columns=null_heavy,
                    recommendation=(
                        "Review collection completeness for sensitive fields. "
                        "Do not backfill with real production values in shared datasets."
                    ),
                    evidence_summary=f"{len(null_heavy)} sensitive column(s) with sampled null_ratio >= 0.5",
                )
            )
            checks.append(SecurityCheckResult(
                check_name="Null-heavy sensitive column scan",
                passed=False,
                severity=FindingSeverity.MEDIUM,
                detail=f"Null-heavy sensitive columns: {null_heavy}",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="Null-heavy sensitive column scan",
                passed=True,
                detail="No sampled sensitive column exceeded the null-ratio threshold",
            ))

        if duplicate_heavy:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-dup-id-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.LOW,
                    title="Duplicate-heavy sensitive identifiers",
                    description=(
                        f"Sensitive identifier columns with high duplicate ratios in the sample: {duplicate_heavy}. "
                        "This may indicate reused IDs, test data, or a non-unique key."
                    ),
                    affected_columns=duplicate_heavy,
                    recommendation=(
                        "Confirm identifier uniqueness requirements. "
                        "Synthetic or demo datasets may legitimately reuse values."
                    ),
                    evidence_summary=f"{len(duplicate_heavy)} identifier column(s) with sampled duplicate_ratio >= 0.6",
                )
            )
            checks.append(SecurityCheckResult(
                check_name="Duplicate identifier scan",
                passed=False,
                severity=FindingSeverity.LOW,
                detail=f"Duplicate-heavy identifiers: {duplicate_heavy}",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="Duplicate identifier scan",
                passed=True,
                detail="No sampled sensitive identifier exceeded the duplicate-ratio threshold",
            ))

        unknown_type_sensitive = [
            c.name for c in asset.columns
            if c.is_sensitive and (not c.data_type or c.data_type.lower() in ("", "unknown", "object"))
        ]

        if unknown_type_sensitive:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-schema-gap-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.LOW,
                    title="Sensitive columns with unresolved data types",
                    description=(
                        f"Sensitive columns with unknown or object data types: {unknown_type_sensitive}. "
                        "Untyped sensitive columns may indicate schema inconsistency or data quality issues."
                    ),
                    affected_columns=unknown_type_sensitive,
                    recommendation=(
                        "Define explicit data types for all sensitive columns. "
                        "Enforce schema validation at ingestion time."
                    ),
                    evidence_summary=f"{len(unknown_type_sensitive)} sensitive column(s) with unresolved types",
                )
            )
            checks.append(SecurityCheckResult(
                check_name="Schema type consistency",
                passed=False,
                severity=FindingSeverity.LOW,
                detail=f"Untyped sensitive columns: {unknown_type_sensitive}",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="Schema type consistency",
                passed=True,
                detail="All sensitive columns have resolved data types",
            ))
        return findings

    def _check_schema_anomalies(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> list[DatasetFinding]:
        """Detect suspicious schema characteristics: too many columns, unusual names."""
        findings: list[DatasetFinding] = []

        # Unusually large column count
        if asset.column_count > 200:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-schema-wide-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.LOW,
                    title="Unusually wide schema detected",
                    description=(
                        f"Dataset has {asset.column_count} columns which is unusually wide. "
                        "Wide schemas may indicate excessive data collection or schema sprawl."
                    ),
                    affected_columns=[],
                    recommendation=(
                        "Review whether all columns are necessary. "
                        "Apply data minimization principles — collect only what is needed."
                    ),
                    evidence_summary=f"Column count: {asset.column_count}",
                )
            )
            checks.append(SecurityCheckResult(
                check_name="Schema anomaly scan",
                passed=False,
                severity=FindingSeverity.LOW,
                detail=f"Wide schema: {asset.column_count} columns",
            ))
        else:
            checks.append(SecurityCheckResult(
                check_name="Schema anomaly scan",
                passed=True,
                detail=f"Schema width normal: {asset.column_count} columns",
            ))

        # Suspicious column name patterns (e.g. "tmp_", "_raw", "_dump")
        suspicious_names = [
            c.name for c in asset.columns
            if re.search(r"(?i)\b(dump|raw_data|unfiltered|backup|export|extract)\b", c.name)
        ]
        if suspicious_names:
            findings.append(
                DatasetFinding(
                    finding_id=f"find-schema-naming-{asset.dataset_id[:8]}",
                    severity=FindingSeverity.MEDIUM,
                    title="Suspicious column naming patterns",
                    description=(
                        f"Columns with names suggesting raw exports, dumps, or unfiltered data: "
                        f"{suspicious_names}. These may indicate unprocessed or improperly sanitized data."
                    ),
                    affected_columns=suspicious_names,
                    recommendation=(
                        "Review columns with 'dump', 'raw', 'backup', 'export' naming. "
                        "Ensure datasets shared beyond the origin system are properly filtered and sanitized."
                    ),
                    evidence_summary=f"Suspicious naming: {suspicious_names}",
                )
            )
        return findings

    def _check_sensitivity_classification(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> list[DatasetFinding]:
        """Add an informational finding describing the overall dataset sensitivity."""
        findings: list[DatasetFinding] = []
        sev_map = {
            SensitivityLevel.CRITICAL: FindingSeverity.CRITICAL,
            SensitivityLevel.HIGH: FindingSeverity.HIGH,
            SensitivityLevel.MEDIUM: FindingSeverity.MEDIUM,
            SensitivityLevel.LOW: FindingSeverity.INFO,
        }
        finding_sev = sev_map.get(asset.sensitivity, FindingSeverity.INFO)

        if asset.sensitivity in (SensitivityLevel.CRITICAL, SensitivityLevel.HIGH):
            findings.append(
                DatasetFinding(
                    finding_id=f"find-sensitivity-{asset.dataset_id[:8]}",
                    severity=finding_sev,
                    title=f"Dataset classified as {asset.sensitivity.value} sensitivity",
                    description=(
                        f"Dataset '{asset.name}' has been heuristically classified as "
                        f"{asset.sensitivity.value} sensitivity based on {len(asset.sensitive_columns)} "
                        f"detected sensitive column(s): {asset.sensitive_columns[:5]}."
                    ),
                    affected_columns=asset.sensitive_columns[:10],
                    recommendation=(
                        "Apply strict data governance: encryption at rest and in transit, "
                        "role-based access control, comprehensive audit logging, and regular access reviews."
                    ),
                    evidence_summary=(
                        f"Sensitivity: {asset.sensitivity.value}, "
                        f"Sensitive columns: {len(asset.sensitive_columns)}"
                    ),
                )
            )

        checks.append(SecurityCheckResult(
            check_name="Sensitivity classification",
            passed=asset.sensitivity in (SensitivityLevel.LOW, SensitivityLevel.MEDIUM),
            severity=finding_sev,
            detail=f"Overall sensitivity: {asset.sensitivity.value}, sensitive columns: {len(asset.sensitive_columns)}",
        ))
        return findings

    def _check_format_validity(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> None:
        """Informational check: format was already validated at upload time."""
        checks.append(SecurityCheckResult(
            check_name="Format validation",
            passed=True,
            detail=f"Format {asset.format.value.upper()} successfully validated",
        ))

    def _check_schema_consistency(
        self, asset: DatasetAsset, checks: list[SecurityCheckResult]
    ) -> None:
        """Informational check: schema inspection completed."""
        checks.append(SecurityCheckResult(
            check_name="Schema inspection",
            passed=True,
            detail=f"{asset.column_count} columns profiled, {len(asset.sensitive_columns)} sensitive",
        ))

    # -----------------------------------------------------------------------
    # Score computation
    # -----------------------------------------------------------------------

    def _compute_score(
        self, findings: list[DatasetFinding], asset: DatasetAsset | None = None
    ) -> DatasetSecurityScore:
        """Compute deterministic, explainable security score from findings (not an ML benchmark)."""
        score = 100
        factors: list[str] = []

        severity_counts = {sev: 0 for sev in FindingSeverity}
        for f in findings:
            severity_counts[f.severity] += 1
            score -= _SCORE_DEDUCTIONS[f.severity]

        score = max(0, min(100, score))

        if asset is not None:
            high_or_crit_cols = [
                c.name for c in asset.columns
                if c.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.CRITICAL)
            ]
            if high_or_crit_cols:
                factors.append(f"{len(high_or_crit_cols)} highly sensitive column(s)")
            financial = [
                c.name for c in asset.columns
                if (c.pii_type or "") in ("account_id", "credit_card", "financial", "salary", "transaction")
                or _matches_any(c.name, _HIGH_RISK_PATTERNS)
            ]
            if financial:
                factors.append("financial identifiers detected")
            if any("secret" in f.title.lower() or "credential" in f.title.lower() for f in findings):
                factors.append("possible secret-like field")
            if any("schema" in f.title.lower() or "naming" in f.title.lower() for f in findings):
                factors.append("schema anomaly")

        if severity_counts[FindingSeverity.CRITICAL] > 0:
            factors.append(f"{severity_counts[FindingSeverity.CRITICAL]} critical finding(s) detected")
        if severity_counts[FindingSeverity.HIGH] > 0:
            factors.append(f"{severity_counts[FindingSeverity.HIGH]} high-severity finding(s) detected")
        if severity_counts[FindingSeverity.MEDIUM] > 0:
            factors.append(f"{severity_counts[FindingSeverity.MEDIUM]} medium-severity finding(s) detected")
        if severity_counts[FindingSeverity.LOW] > 0:
            factors.append(f"{severity_counts[FindingSeverity.LOW]} low-severity finding(s) detected")
        if not factors:
            factors.append("No significant security concerns found")

        if score >= 80:
            risk_level = "LOW"
        elif score >= 60:
            risk_level = "MEDIUM"
        elif score >= 40:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return DatasetSecurityScore(
            score=score,
            risk_level=risk_level,
            contributing_factors=factors,
        )
