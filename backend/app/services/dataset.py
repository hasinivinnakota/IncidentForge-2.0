"""Dataset Asset management service.

Handles dataset registration, profiling, and catalog management.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from ..models.dataset import DatasetAsset, DatasetActivity
from ..persistence.repositories import DatasetRepository
from .dataset_profiler import DatasetProfiler

logger = logging.getLogger(__name__)


class DatasetService:
    """Manages dataset catalog registration, profiling, and activity recording."""

    def __init__(self, dataset_repository: DatasetRepository):
        self._repo = dataset_repository

    def register_and_profile(
        self,
        file_path: str,
        dataset_id: str | None = None,
        name: str | None = None,
    ) -> DatasetAsset:
        """Profile a local file and register it in the dataset catalog.

        Never stores row-level data; only stores column metadata, schema hash,
        record counts, and sensitivity classification.
        """
        asset = DatasetProfiler.profile_file(
            file_path, dataset_id=dataset_id, name=name, persist_path=False
        )
        self._repo.create_or_update_dataset(asset)
        logger.info(
            "Dataset registered",
            extra={"dataset_id": asset.dataset_id, "sensitivity": asset.sensitivity.value},
        )
        return asset

    def register_asset(self, asset: DatasetAsset) -> DatasetAsset:
        """Register or update an already-constructed DatasetAsset in the catalog."""
        self._repo.create_or_update_dataset(asset)
        return asset

    def get_asset(self, dataset_id: str) -> DatasetAsset | None:
        """Retrieve a dataset asset by ID."""
        record = self._repo.get_dataset(dataset_id)
        if record is None:
            return None
        return self._record_to_domain(record)

    def list_assets(self, limit: int = 100) -> list[DatasetAsset]:
        """List all registered datasets."""
        records = self._repo.list_datasets(limit=limit)
        return [self._record_to_domain(r) for r in records]

    def record_activity(self, activity: DatasetActivity) -> DatasetActivity:
        """Record a dataset activity event in the audit log."""
        self._repo.record_activity(activity)
        return activity

    def list_activities(
        self,
        dataset_id: str | None = None,
        actor: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """List recent dataset activity records."""
        records = self._repo.list_activities(dataset_id=dataset_id, actor=actor, limit=limit)
        import json
        result = []
        for r in records:
            result.append({
                "activity_id": r.activity_id,
                "timestamp": r.timestamp.isoformat(),
                "dataset_id": r.dataset_id,
                "dataset_name": r.dataset_name,
                "operation": r.operation,
                "actor": r.actor,
                "actor_host": r.actor_host,
                "source_ip": r.source_ip,
                "destination_ip": r.destination_ip,
                "records_accessed": r.records_accessed,
                "records_modified": r.records_modified,
                "sensitive_columns": json.loads(r.sensitive_columns_json) if r.sensitive_columns_json else [],
                "export_size_bytes": r.export_size_bytes,
                "export_destination": r.export_destination,
            })
        return result

    @staticmethod
    def _record_to_domain(record) -> DatasetAsset:
        """Convert persistence record to DatasetAsset domain model."""
        import json
        from ..models.dataset import ColumnProfile, DataFormat, SensitivityLevel

        try:
            columns = [
                ColumnProfile.model_validate(c)
                for c in json.loads(record.columns_json or "[]")
            ]
        except Exception:
            columns = []

        try:
            sensitive_cols = json.loads(record.sensitive_columns_json or "[]")
        except Exception:
            sensitive_cols = []

        try:
            metadata = json.loads(record.metadata_json or "{}")
        except Exception:
            metadata = {}

        return DatasetAsset(
            dataset_id=record.dataset_id,
            name=record.name,
            format=DataFormat(record.format),
            file_path=record.file_path,
            size_bytes=record.size_bytes,
            record_count=record.record_count,
            column_count=record.column_count,
            columns=columns,
            sensitive_columns=sensitive_cols,
            sensitivity=SensitivityLevel(record.sensitivity),
            schema_hash=record.schema_hash,
            created_at=record.created_at,
            updated_at=record.updated_at,
            metadata=metadata,
        )
