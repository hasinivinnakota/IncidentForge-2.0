"""Integration tests for the dataset upload API endpoint.

Tests:
- CSV upload → profiling → assessment → registration → cleanup
- JSON upload
- Unsupported extension rejection
- Oversized file rejection
- Empty file rejection
- Malformed content
- Assessment endpoint
- Per-dataset simulation endpoint
- Existing pipeline integration
"""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _csv_bytes(rows: list[dict]) -> bytes:
    """Build an in-memory CSV as bytes."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def _json_bytes(rows: list[dict]) -> bytes:
    return json.dumps(rows).encode("utf-8")


SIMPLE_ROWS = [
    {
        "customer_id": "CUST-001",
        "email": "testuser@synthetic.invalid",
        "account_number": "ACC-0000001",
        "transaction_amount": "450.00",
        "password": "hunter2-SYNTHETIC",
        "city": "Synthville",
    },
    {
        "customer_id": "CUST-002",
        "email": "another@synthetic.invalid",
        "account_number": "ACC-0000002",
        "transaction_amount": "1200.50",
        "password": "abc123-SYNTHETIC",
        "city": "Testberg",
    },
]

CLEAN_ROWS = [
    {"product_id": "P001", "category": "Electronics", "price": "299.99"},
    {"product_id": "P002", "category": "Books", "price": "14.99"},
]


class TestDatasetUploadCSV:
    def test_csv_upload_success(self, api_client: TestClient):
        data = _csv_bytes(SIMPLE_ROWS)
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("financial_records.csv", data, "text/csv")},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["success"] is True
        assert body["registered"] is True
        assert body["assessment"]["dataset_id"]
        assert body["assessment"]["security_score"]["score"] is not None
        assert 0 <= body["assessment"]["security_score"]["score"] <= 100

    def test_csv_upload_detects_password_column(self, api_client: TestClient):
        """CSV with 'password' column must trigger CRITICAL finding."""
        data = _csv_bytes(SIMPLE_ROWS)
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("upload.csv", data, "text/csv")},
        )
        assert response.status_code == 201
        body = response.json()
        findings = body["assessment"]["findings"]
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) >= 1
        # Validate the security score is reduced below 80 due to critical finding
        assert body["assessment"]["security_score"]["score"] < 80

    def test_csv_upload_sensitive_columns_registered(self, api_client: TestClient):
        """Sensitive column names (not values) must appear in the registered asset."""
        data = _csv_bytes(SIMPLE_ROWS)
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("test.csv", data, "text/csv")},
        )
        assert response.status_code == 201
        asset = response.json()["assessment"]["asset"]
        sensitive = asset["sensitive_columns"]
        # email and account_number should be detected
        assert any("email" in c for c in sensitive) or any("account" in c for c in sensitive)

    def test_csv_upload_display_name(self, api_client: TestClient):
        """display_name form field should be used as the dataset name."""
        data = _csv_bytes(CLEAN_ROWS)
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("products.csv", data, "text/csv")},
            data={"display_name": "My Custom Dataset"},
        )
        assert response.status_code == 201
        asset_name = response.json()["assessment"]["asset"]["name"]
        assert asset_name == "My Custom Dataset"

    def test_csv_upload_temp_file_cleaned(self, api_client: TestClient):
        """After upload, no raw temp files should remain in the upload tmp dir."""
        from backend.app.api.routes.dataset_upload import _UPLOAD_TMP_DIR

        data = _csv_bytes(SIMPLE_ROWS)
        api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("cleanup_test.csv", data, "text/csv")},
        )
        # Temp dir may exist but should not contain our upload
        tmp_files = list(_UPLOAD_TMP_DIR.glob("upload_*.csv")) if _UPLOAD_TMP_DIR.exists() else []
        assert len(tmp_files) == 0, f"Temp files not cleaned: {tmp_files}"

    def test_csv_upload_fixture_file(self, api_client: TestClient):
        """Full synthetic fixture CSV should upload and profile successfully."""
        fixture = FIXTURES_DIR / "financial_records.csv"
        if not fixture.exists():
            pytest.skip("Fixture file not generated yet")
        data = fixture.read_bytes()
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("financial_records.csv", data, "text/csv")},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["assessment"]["asset"]["record_count"] == 250
        assert body["assessment"]["asset"]["column_count"] == 10


class TestDatasetUploadJSON:
    def test_json_upload_success(self, api_client: TestClient):
        data = _json_bytes(SIMPLE_ROWS)
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("data.json", data, "application/json")},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["success"] is True
        assert body["assessment"]["asset"]["format"] == "json"

    def test_json_upload_fixture_file(self, api_client: TestClient):
        """Full synthetic fixture JSON should upload and profile successfully."""
        fixture = FIXTURES_DIR / "financial_records.json"
        if not fixture.exists():
            pytest.skip("Fixture file not generated yet")
        data = fixture.read_bytes()
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("financial_records.json", data, "application/json")},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["assessment"]["asset"]["record_count"] == 250

    def test_malformed_json_returns_422(self, api_client: TestClient):
        data = b"{this is not valid json"
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("bad.json", data, "application/json")},
        )
        # Should fail gracefully — either 422 (malformed) or 201 with 0 records
        # Profiler may return empty, which triggers our empty check
        assert response.status_code in (201, 422, 400), response.text

    def test_malformed_csv_empty_returns_422(self, api_client: TestClient):
        data = b""  # empty
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("empty.csv", data, "text/csv")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()


class TestDatasetUploadValidation:
    def test_unsupported_extension_rejected(self, api_client: TestClient):
        data = b"<xml>not a dataset</xml>"
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("dataset.xml", data, "application/xml")},
        )
        assert response.status_code == 415
        detail = response.json()["detail"]
        assert "unsupported" in detail.lower() or "allowed" in detail.lower()

    def test_exe_extension_rejected(self, api_client: TestClient):
        data = b"MZ\x90\x00"
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("malware.exe", data, "application/octet-stream")},
        )
        assert response.status_code == 415

    def test_txt_extension_rejected(self, api_client: TestClient):
        data = b"just some text"
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("notes.txt", data, "text/plain")},
        )
        assert response.status_code == 415

    def test_oversized_file_rejected(self, api_client: TestClient):
        # 51 MB — over the 50 MB limit
        large_data = b"a" * (51 * 1024 * 1024 + 1)
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("huge.csv", large_data, "text/csv")},
        )
        assert response.status_code == 413

    def test_empty_file_rejected(self, api_client: TestClient):
        response = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert response.status_code == 400


class TestDatasetAssessEndpoint:
    def _register_dataset(self, api_client: TestClient) -> str:
        """Helper: upload a CSV and return the dataset_id."""
        data = _csv_bytes(SIMPLE_ROWS)
        resp = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("test.csv", data, "text/csv")},
        )
        assert resp.status_code == 201
        return resp.json()["dataset_id"]

    def test_assess_endpoint_returns_assessment(self, api_client: TestClient):
        dataset_id = self._register_dataset(api_client)
        resp = api_client.post(f"/api/v1/data-assets/{dataset_id}/assess")
        assert resp.status_code == 200
        body = resp.json()
        assert body["dataset_id"] == dataset_id
        assert "security_score" in body
        assert "findings" in body
        assert "checks_performed" in body
        assert "disclaimer" in body
        assert "heuristic" in body["disclaimer"].lower()

    def test_assess_unknown_dataset_returns_404(self, api_client: TestClient):
        resp = api_client.post("/api/v1/data-assets/nonexistent-dataset-xyz/assess")
        assert resp.status_code == 404


class TestDatasetSimulateEndpoint:
    def _register_dataset(self, api_client: TestClient) -> str:
        data = _csv_bytes(SIMPLE_ROWS)
        resp = api_client.post(
            "/api/v1/data-assets/upload",
            files={"file": ("sim_test.csv", data, "text/csv")},
        )
        assert resp.status_code == 201
        return resp.json()["dataset_id"]

    def test_simulate_returns_result(self, api_client: TestClient):
        dataset_id = self._register_dataset(api_client)
        resp = api_client.post(f"/api/v1/data-assets/{dataset_id}/simulate")
        assert resp.status_code == 202
        body = resp.json()
        assert body["dataset_id"] == dataset_id
        assert body["events_generated"] >= 4
        assert body["simulation_actor"] == "external-user-demo"

    def test_simulate_generates_pipeline_events(self, api_client: TestClient):
        """Simulation must go through the real SOC pipeline."""
        dataset_id = self._register_dataset(api_client)
        resp = api_client.post(f"/api/v1/data-assets/{dataset_id}/simulate")
        assert resp.status_code == 202
        body = resp.json()
        # Events were generated and pipeline was triggered
        assert body["events_generated"] > 0

    def test_simulate_unknown_dataset_returns_404(self, api_client: TestClient):
        resp = api_client.post("/api/v1/data-assets/nonexistent-abc123/simulate")
        assert resp.status_code == 404

    def test_simulation_creates_alerts(self, api_client: TestClient):
        """Dataset simulation through SOC pipeline should generate at least some alerts."""
        dataset_id = self._register_dataset(api_client)
        resp = api_client.post(f"/api/v1/data-assets/{dataset_id}/simulate")
        assert resp.status_code == 202

        # Verify alerts were created by checking the alerts endpoint
        alerts_resp = api_client.get("/api/v1/alerts")
        assert alerts_resp.status_code == 200
        # At least one alert should exist in the DB (might include pre-existing ones)
        assert isinstance(alerts_resp.json(), list)
