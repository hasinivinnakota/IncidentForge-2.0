"""Tests for the dataset security assessment service.

Tests the DatasetAssessmentService deterministic heuristic engine:
- Sensitive field detection
- Secret-like field detection
- Security score computation
- Finding structure validation
"""

import pytest

from backend.app.models.dataset import ColumnProfile, DatasetAsset, DataFormat, SensitivityLevel
from backend.app.models.dataset_assessment import FindingSeverity
from backend.app.services.dataset_assessment import DatasetAssessmentService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_asset(
    columns: list[dict],
    sensitivity: SensitivityLevel = SensitivityLevel.LOW,
    record_count: int = 1000,
    name: str = "test_dataset",
) -> DatasetAsset:
    cols = [ColumnProfile(**c) for c in columns]
    sensitive_cols = [c.name for c in cols if c.is_sensitive]
    return DatasetAsset(
        dataset_id="test-ds-001",
        name=name,
        format=DataFormat.CSV,
        file_path="/synthetic/test_dataset.csv",
        size_bytes=50000,
        record_count=record_count,
        column_count=len(cols),
        columns=cols,
        sensitive_columns=sensitive_cols,
        sensitivity=sensitivity,
        schema_hash="abc12345",
    )


# ---------------------------------------------------------------------------
# Assessment service: basic
# ---------------------------------------------------------------------------

class TestDatasetAssessmentService:
    def test_assess_clean_dataset_returns_high_score(self):
        """A dataset with no sensitive columns should have a high security score."""
        asset = make_asset([
            {"name": "product_id", "data_type": "integer", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW},
            {"name": "category", "data_type": "string", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW},
            {"name": "price", "data_type": "float", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW},
        ])
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)

        assert assessment.security_score.score >= 80
        assert assessment.security_score.risk_level == "LOW"
        assert len(assessment.findings) == 0

    def test_assess_detects_secret_fields(self):
        """Columns named 'password', 'api_key' must trigger CRITICAL findings."""
        asset = make_asset([
            {"name": "user_id", "data_type": "integer", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW},
            {"name": "password", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
            {"name": "api_key", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
        ], sensitivity=SensitivityLevel.CRITICAL)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)

        critical_findings = [f for f in assessment.findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical_findings) >= 1
        secret_finding = next(
            (f for f in critical_findings if "secret" in f.title.lower() or "credential" in f.title.lower()),
            None,
        )
        assert secret_finding is not None
        assert "password" in secret_finding.affected_columns or "api_key" in secret_finding.affected_columns
        assert assessment.security_score.score < 80

    def test_assess_detects_high_risk_financial_fields(self):
        """Columns named 'account_number', 'salary' should trigger HIGH findings."""
        asset = make_asset([
            {"name": "customer_id", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
            {"name": "account_number", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.HIGH},
            {"name": "salary", "data_type": "float", "is_sensitive": True, "sensitivity": SensitivityLevel.HIGH},
        ], sensitivity=SensitivityLevel.HIGH)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)

        high_findings = [f for f in assessment.findings if f.severity == FindingSeverity.HIGH]
        assert len(high_findings) >= 1
        # Score should be reduced
        assert assessment.security_score.score < 100

    def test_assess_detects_pii_fields(self):
        """Email, phone, address columns should trigger MEDIUM findings."""
        asset = make_asset([
            {"name": "email", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
            {"name": "phone", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
            {"name": "address", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
        ], sensitivity=SensitivityLevel.MEDIUM)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)

        medium_findings = [f for f in assessment.findings if f.severity == FindingSeverity.MEDIUM]
        assert len(medium_findings) >= 1
        pii_finding = next(
            (f for f in medium_findings if "pii" in f.title.lower() or "personal" in f.title.lower()),
            None,
        )
        assert pii_finding is not None

    def test_assess_all_findings_have_required_fields(self):
        """All findings must have finding_id, severity, title, description, recommendation."""
        asset = make_asset([
            {"name": "email", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
            {"name": "account_number", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.HIGH},
            {"name": "password", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
        ], sensitivity=SensitivityLevel.CRITICAL)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)

        for finding in assessment.findings:
            assert finding.finding_id, "finding_id must be non-empty"
            assert finding.severity, "severity must be set"
            assert finding.title, "title must be non-empty"
            assert finding.description, "description must be non-empty"
            assert finding.recommendation, "recommendation must be non-empty"

    def test_score_clamped_to_0_100(self):
        """Security score must always be within [0, 100]."""
        # Dataset with many critical issues
        asset = make_asset([
            {"name": "password", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
            {"name": "secret_key", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
            {"name": "api_key", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
            {"name": "account_number", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.HIGH},
            {"name": "salary", "data_type": "float", "is_sensitive": True, "sensitivity": SensitivityLevel.HIGH},
            {"name": "email", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
        ], sensitivity=SensitivityLevel.CRITICAL)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)
        assert 0 <= assessment.security_score.score <= 100

    def test_score_risk_level_corresponds_to_score(self):
        """Risk level must correspond correctly to the numeric score."""
        asset = make_asset([
            {"name": "product_name", "data_type": "string", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW},
        ])
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)
        score = assessment.security_score.score
        risk = assessment.security_score.risk_level
        if score >= 80:
            assert risk == "LOW"
        elif score >= 60:
            assert risk == "MEDIUM"
        elif score >= 40:
            assert risk == "HIGH"
        else:
            assert risk == "CRITICAL"

    def test_assessment_disclaimer_present(self):
        """Assessment must always include the heuristic disclaimer."""
        asset = make_asset([
            {"name": "id", "data_type": "integer", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW},
        ])
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)
        assert "heuristic" in assessment.disclaimer.lower()

    def test_assessment_checks_performed_not_empty(self):
        """Checks performed list must include at least the standard checks."""
        asset = make_asset([
            {"name": "email", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
        ], sensitivity=SensitivityLevel.MEDIUM)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)
        check_names = {c.check_name for c in assessment.checks_performed}
        assert "Secret-like field scan" in check_names
        assert "PII heuristic scan" in check_names
        assert "Format validation" in check_names
        assert "Schema inspection" in check_names

    def test_assessment_counts_match_findings(self):
        """Critical/high/medium/low/info counts must match actual findings."""
        asset = make_asset([
            {"name": "password", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.CRITICAL},
            {"name": "email", "data_type": "string", "is_sensitive": True, "sensitivity": SensitivityLevel.MEDIUM},
        ], sensitivity=SensitivityLevel.CRITICAL)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)
        total = (
            assessment.critical_findings
            + assessment.high_findings
            + assessment.medium_findings
            + assessment.low_findings
            + assessment.info_findings
        )
        assert total == len(assessment.findings)

    def test_schema_anomaly_wide_dataset(self):
        """A dataset with >200 columns should trigger a LOW schema anomaly finding."""
        many_cols = [
            {"name": f"col_{i}", "data_type": "string", "is_sensitive": False, "sensitivity": SensitivityLevel.LOW}
            for i in range(210)
        ]
        asset = make_asset(many_cols)
        # Override column_count since our helper limits to len(many_cols)
        svc = DatasetAssessmentService()
        assessment = svc.assess(asset)
        anomaly_findings = [
            f for f in assessment.findings
            if "schema" in f.title.lower() or "wide" in f.title.lower()
        ]
        assert len(anomaly_findings) >= 1
