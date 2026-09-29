"""Dataset Profiler for IncidentForge v2.

Inspects synthetic/local datasets (CSV, JSON, Parquet) and determines:
- format, record count, column schema, inferred types
- candidate sensitive fields (heuristic / probable, not guaranteed PII)
- sensitivity classification (LOW, MEDIUM, HIGH, CRITICAL)
- deterministic schema hash
- bounded sample statistics (null/duplicate ratios) without persisting values

STRICT CONSTRAINTS:
- Heuristic/rule-based metadata classification only (no claim of perfect PII detection).
- Read-only inspection; bounds memory usage by streaming or sample inspection.
- Purely file-based; no database engine or external network calls.
- Never stores raw row values in the returned DatasetAsset.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from ..models.dataset import (
    ColumnProfile,
    DataFormat,
    DatasetAsset,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

NOT_PERSISTED_PATH = "not-persisted"
_SAMPLE_ROW_LIMIT = 100

# Deterministic patterns for candidate sensitive columns
_CRITICAL_PATTERNS = [
    re.compile(r"(?i)\b(ssn|social_security|national_id|tax_id|sin|aadhaar|aadhar)\b"),
    re.compile(
        r"(?i)\b(credit_card|card_number|card_num|cvv|cvc|ccv|banking_pin|"
        r"private_key|secret_key|password|passwd|passphrase|api_key|apikey|"
        r"access_token|auth_token|bearer_token|session_token|client_secret)\b"
    ),
    re.compile(r"(?i)\b(pan_number|passport)\b"),
]

_HIGH_PATTERNS = [
    re.compile(
        r"(?i)\b(salary|compensation|wage|annual_income|gross_income|net_income|bonus|"
        r"bank_account|account_number|account_num|account_id|routing_num|iban|swift|"
        r"financial|revenue|payroll|token)\b"
    ),
    re.compile(r"(?i)\b(medical_record|health_id|patient_id|diagnosis|biometric)\b"),
    re.compile(r"(?i)\b(secret)\b"),
]

_MEDIUM_PATTERNS = [
    re.compile(
        r"(?i)\b(email|email_address|phone|telephone|mobile|cell|contact_number|"
        r"address|street|zip_code|postal_code|postcode|birth_date|date_of_birth|dob|"
        r"employee_id|customer_id|user_id|client_id|member_id|driver_license|"
        r"driving_license|full_name|first_name|last_name|surname|given_name|"
        r"customer_name|transaction|payment|transfer)\b"
    ),
]

# Exact-name matches that word-boundary regex would over- or under-match
_CRITICAL_EXACT = frozenset({"pan", "token", "password", "secret", "ssn", "cvv", "cvc"})
_MEDIUM_EXACT = frozenset({"name", "email", "phone", "address", "dob"})

# Value-level regex patterns for sample data inspection (never persisted)
_VALUE_SSN_PATTERN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_VALUE_EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
_VALUE_PHONE_PATTERN = re.compile(r"^\+?1?\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$")
_VALUE_CREDIT_CARD_PATTERN = re.compile(r"^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$")
_VALUE_SECRET_LIKE = re.compile(
    r"(?i)^(sk-|pk_|ghp_|xox[baprs]-|eyJ[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16})$"
)


def _col_norm(name: str) -> str:
    return name.strip().lower().replace("-", "_").replace(" ", "_")


class DatasetProfiler:
    """Deterministic, read-only dataset profiler and sensitivity classifier."""

    @staticmethod
    def classify_column(name: str, sample_values: list[Any] | None = None) -> tuple[bool, str | None, SensitivityLevel]:
        """Classify a single column by name and sample values.

        Returns (is_sensitive, pii_type, sensitivity_level).
        Detection is heuristic / probable — not a guarantee of PII presence.
        """
        col_norm = _col_norm(name)

        if col_norm in _CRITICAL_EXACT or any(p.search(col_norm) for p in _CRITICAL_PATTERNS):
            if "ssn" in col_norm or "social" in col_norm or "national" in col_norm or "aadhaar" in col_norm or "aadhar" in col_norm:
                return True, "ssn", SensitivityLevel.CRITICAL
            if "card" in col_norm or "cvv" in col_norm or "cvc" in col_norm:
                return True, "credit_card", SensitivityLevel.CRITICAL
            if "password" in col_norm or "passwd" in col_norm:
                return True, "password", SensitivityLevel.CRITICAL
            if "api_key" in col_norm or "token" in col_norm or "secret" in col_norm:
                return True, "secret", SensitivityLevel.CRITICAL
            if col_norm in ("pan",) or "pan_number" in col_norm:
                return True, "pan", SensitivityLevel.CRITICAL
            if "passport" in col_norm:
                return True, "passport", SensitivityLevel.CRITICAL
            return True, "credential_or_identity", SensitivityLevel.CRITICAL

        if any(p.search(col_norm) for p in _HIGH_PATTERNS):
            if "salary" in col_norm or "compensation" in col_norm or "payroll" in col_norm:
                return True, "salary", SensitivityLevel.HIGH
            if "account" in col_norm or "iban" in col_norm or "bank" in col_norm:
                return True, "account_id", SensitivityLevel.HIGH
            if "token" in col_norm:
                return True, "token", SensitivityLevel.HIGH
            return True, "financial", SensitivityLevel.HIGH

        if col_norm in _MEDIUM_EXACT or any(p.search(col_norm) for p in _MEDIUM_PATTERNS):
            if "email" in col_norm:
                return True, "email", SensitivityLevel.MEDIUM
            if "phone" in col_norm or "mobile" in col_norm or "cell" in col_norm:
                return True, "phone", SensitivityLevel.MEDIUM
            if "address" in col_norm or "zip" in col_norm or "street" in col_norm:
                return True, "address", SensitivityLevel.MEDIUM
            if "dob" in col_norm or "birth" in col_norm:
                return True, "dob", SensitivityLevel.MEDIUM
            if "employee" in col_norm:
                return True, "employee_id", SensitivityLevel.MEDIUM
            if "customer_id" in col_norm or col_norm == "customer_id":
                return True, "customer_id", SensitivityLevel.MEDIUM
            if "name" in col_norm:
                return True, "name", SensitivityLevel.MEDIUM
            if "transaction" in col_norm or "payment" in col_norm:
                return True, "transaction", SensitivityLevel.MEDIUM
            return True, "personal_identifier", SensitivityLevel.MEDIUM

        if sample_values:
            non_empty = [str(v).strip() for v in sample_values if v is not None and str(v).strip()]
            for val in non_empty[:20]:
                if _VALUE_SSN_PATTERN.match(val):
                    return True, "ssn", SensitivityLevel.CRITICAL
                if _VALUE_CREDIT_CARD_PATTERN.match(val):
                    return True, "credit_card", SensitivityLevel.CRITICAL
                if _VALUE_SECRET_LIKE.match(val):
                    return True, "secret", SensitivityLevel.CRITICAL
                if _VALUE_EMAIL_PATTERN.match(val):
                    return True, "email", SensitivityLevel.MEDIUM
                if _VALUE_PHONE_PATTERN.match(val):
                    return True, "phone", SensitivityLevel.MEDIUM

        return False, None, SensitivityLevel.LOW

    @staticmethod
    def _column_stats(sample_values: list[Any], sampled_rows: int) -> dict[str, Any]:
        """Compute sanitized sample statistics. Never includes raw values."""
        if sampled_rows <= 0:
            return {"sampled_rows": 0, "null_ratio": 0.0, "duplicate_ratio": 0.0}
        nulls = sum(1 for v in sample_values if v is None or str(v).strip() == "")
        non_empty = [str(v).strip() for v in sample_values if v is not None and str(v).strip()]
        unique = len(set(non_empty))
        dup_ratio = 0.0
        if non_empty:
            dup_ratio = round(1.0 - (unique / len(non_empty)), 4)
        return {
            "sampled_rows": sampled_rows,
            "null_ratio": round(nulls / sampled_rows, 4),
            "duplicate_ratio": dup_ratio,
        }

    @classmethod
    def profile_csv(cls, path: Path) -> tuple[int, list[ColumnProfile], dict[str, Any]]:
        """Profile a CSV file safely by reading headers and sampling bounded rows."""
        record_count = 0
        columns: list[ColumnProfile] = []
        stats: dict[str, Any] = {}

        with open(path, mode="r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            headers = next(reader, None)
            if not headers or all(not str(h).strip() for h in headers):
                raise ValueError("CSV file has no header row")

            samples: dict[str, list[Any]] = {h: [] for h in headers}
            for row in reader:
                record_count += 1
                if record_count <= _SAMPLE_ROW_LIMIT:
                    for i, h in enumerate(headers):
                        samples[h].append(row[i] if i < len(row) else "")

            sampled_rows = min(record_count, _SAMPLE_ROW_LIMIT)
            for h in headers:
                col_samples = samples.get(h, [])
                is_sens, pii, sens = cls.classify_column(h, col_samples)
                inferred_type = cls._infer_type(col_samples)
                columns.append(
                    ColumnProfile(
                        name=h,
                        data_type=inferred_type,
                        is_sensitive=is_sens,
                        pii_type=pii,
                        sensitivity=sens,
                    )
                )
                stats[h] = cls._column_stats(col_samples, sampled_rows)

        return record_count, columns, stats

    @classmethod
    def profile_json(cls, path: Path) -> tuple[int, list[ColumnProfile], dict[str, Any]]:
        """Profile a JSON or JSONL file safely. Raises ValueError on malformed input."""
        record_count = 0
        columns: list[ColumnProfile] = []
        stats: dict[str, Any] = {}

        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            first_char = ""
            while True:
                ch = f.read(1)
                if not ch:
                    break
                if not ch.isspace():
                    first_char = ch
                    break
            f.seek(0)

            sample_records: list[dict[str, Any]] = []

            if first_char == "[":
                try:
                    data = json.load(f)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Malformed JSON: {exc.msg}") from exc
                if not isinstance(data, list):
                    raise ValueError("JSON root must be an array of objects or a JSON object")
                record_count = len(data)
                for rec in data[:_SAMPLE_ROW_LIMIT]:
                    if isinstance(rec, dict):
                        sample_records.append(rec)
                if record_count > 0 and not sample_records:
                    raise ValueError("JSON array does not contain object records")
            elif first_char == "{":
                # Single object or JSON Lines starting with an object
                raw = f.read()
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        record_count = 1
                        sample_records = [data]
                    elif isinstance(data, list):
                        record_count = len(data)
                        sample_records = [r for r in data[:_SAMPLE_ROW_LIMIT] if isinstance(r, dict)]
                    else:
                        raise ValueError("JSON root must be an object or an array of objects")
                except json.JSONDecodeError:
                    # JSON Lines
                    record_count = 0
                    sample_records = []
                    for line in raw.splitlines():
                        line_str = line.strip()
                        if not line_str:
                            continue
                        record_count += 1
                        if len(sample_records) < _SAMPLE_ROW_LIMIT:
                            try:
                                rec = json.loads(line_str)
                            except json.JSONDecodeError as exc:
                                raise ValueError(f"Malformed JSONL: {exc.msg}") from exc
                            if isinstance(rec, dict):
                                sample_records.append(rec)
                    if record_count == 0:
                        raise ValueError("Malformed JSON")
            else:
                raise ValueError("File does not appear to be valid JSON (expected object or array)")

        all_keys: set[str] = set()
        for rec in sample_records:
            all_keys.update(rec.keys())

        sampled_rows = len(sample_records)
        for key in sorted(all_keys):
            col_samples = [rec.get(key) for rec in sample_records]
            is_sens, pii, sens = cls.classify_column(key, col_samples)
            inferred_type = cls._infer_type(col_samples)
            columns.append(
                ColumnProfile(
                    name=key,
                    data_type=inferred_type,
                    is_sensitive=is_sens,
                    pii_type=pii,
                    sensitivity=sens,
                )
            )
            stats[key] = cls._column_stats(col_samples, sampled_rows)

        return record_count, columns, stats

    @classmethod
    def profile_parquet(cls, path: Path) -> tuple[int, list[ColumnProfile], dict[str, Any]]:
        """Profile a Parquet file using metadata; sample a bounded first row-group only."""
        try:
            import pyarrow.parquet as pq
        except ImportError:
            return cls._profile_parquet_fastparquet(path)

        try:
            pf = pq.ParquetFile(str(path))
        except Exception as exc:
            raise ValueError(f"Invalid Parquet file: {exc}") from exc

        record_count = int(pf.metadata.num_rows) if pf.metadata is not None else 0
        schema = pf.schema_arrow
        sample_table = None
        if pf.num_row_groups > 0:
            try:
                sample_table = pf.read_row_group(0)
                if sample_table.num_rows > _SAMPLE_ROW_LIMIT:
                    sample_table = sample_table.slice(0, _SAMPLE_ROW_LIMIT)
            except Exception:
                sample_table = None

        columns: list[ColumnProfile] = []
        stats: dict[str, Any] = {}
        sampled_rows = sample_table.num_rows if sample_table is not None else 0

        for field in schema:
            col_name = field.name
            col_type = str(field.type)
            sample_vals: list[Any] = []
            if sample_table is not None and col_name in sample_table.column_names:
                try:
                    sample_vals = sample_table.column(col_name).to_pylist()
                except Exception:
                    sample_vals = []
            is_sens, pii, sens = cls.classify_column(col_name, sample_vals)
            columns.append(
                ColumnProfile(
                    name=col_name,
                    data_type=col_type,
                    is_sensitive=is_sens,
                    pii_type=pii,
                    sensitivity=sens,
                )
            )
            stats[col_name] = cls._column_stats(sample_vals, sampled_rows or len(sample_vals))

        return record_count, columns, stats

    @classmethod
    def _profile_parquet_fastparquet(cls, path: Path) -> tuple[int, list[ColumnProfile], dict[str, Any]]:
        try:
            import fastparquet
        except ImportError as exc:
            raise ValueError(
                "Parquet support requires the 'pyarrow' package. Install it to profile Parquet files."
            ) from exc

        try:
            pf = fastparquet.ParquetFile(str(path))
        except Exception as exc:
            raise ValueError(f"Invalid Parquet file: {exc}") from exc

        record_count = int(pf.count)
        columns: list[ColumnProfile] = []
        stats: dict[str, Any] = {}

        for col_name in pf.columns:
            col_type = "string"
            if hasattr(pf, "dtypes") and col_name in pf.dtypes:
                col_type = str(pf.dtypes[col_name])
            sample_vals: list[Any] = []
            try:
                df_sample = pf.to_pandas(columns=[col_name]).head(_SAMPLE_ROW_LIMIT)
                sample_vals = df_sample[col_name].tolist()
            except Exception:
                sample_vals = []
            is_sens, pii, sens = cls.classify_column(col_name, sample_vals)
            columns.append(
                ColumnProfile(
                    name=col_name,
                    data_type=col_type,
                    is_sensitive=is_sens,
                    pii_type=pii,
                    sensitivity=sens,
                )
            )
            stats[col_name] = cls._column_stats(sample_vals, len(sample_vals))

        return record_count, columns, stats

    @classmethod
    def profile_file(
        cls,
        file_path: str | Path,
        dataset_id: str | None = None,
        name: str | None = None,
        persist_path: bool = False,
    ) -> DatasetAsset:
        """Profile a file and return a fully classified DatasetAsset domain model."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Dataset file not found: {file_path}")

        ext = p.suffix.lower().lstrip(".")
        stats: dict[str, Any] = {}
        if ext == "csv":
            fmt = DataFormat.CSV
            record_count, columns, stats = cls.profile_csv(p)
        elif ext in ("json", "jsonl"):
            fmt = DataFormat.JSON
            record_count, columns, stats = cls.profile_json(p)
        elif ext in ("parquet", "pq"):
            fmt = DataFormat.PARQUET
            record_count, columns, stats = cls.profile_parquet(p)
        else:
            raise ValueError(f"Unsupported dataset format '{ext}'. Must be csv, json, or parquet.")

        overall_sensitivity = SensitivityLevel.LOW
        sensitive_cols: list[str] = []

        for col in columns:
            if col.is_sensitive:
                sensitive_cols.append(col.name)
            if col.sensitivity == SensitivityLevel.CRITICAL:
                overall_sensitivity = SensitivityLevel.CRITICAL
            elif col.sensitivity == SensitivityLevel.HIGH and overall_sensitivity not in (SensitivityLevel.CRITICAL,):
                overall_sensitivity = SensitivityLevel.HIGH
            elif col.sensitivity == SensitivityLevel.MEDIUM and overall_sensitivity not in (
                SensitivityLevel.CRITICAL,
                SensitivityLevel.HIGH,
            ):
                overall_sensitivity = SensitivityLevel.MEDIUM

        schema_signature = ":".join(f"{c.name}:{c.data_type}" for c in sorted(columns, key=lambda x: x.name))
        schema_hash = hashlib.sha256(schema_signature.encode("utf-8")).hexdigest()[:16]

        ds_id = dataset_id or f"ds-{hashlib.sha256(f'{p.name}:{schema_hash}'.encode()).hexdigest()[:12]}"
        ds_name = name or p.stem

        stored_path = str(p.resolve()) if persist_path else NOT_PERSISTED_PATH

        return DatasetAsset(
            dataset_id=ds_id,
            name=ds_name,
            format=fmt,
            file_path=stored_path,
            size_bytes=p.stat().st_size if p.exists() else 0,
            record_count=record_count,
            column_count=len(columns),
            columns=columns,
            sensitive_columns=sensitive_cols,
            sensitivity=overall_sensitivity,
            schema_hash=schema_hash,
            metadata={
                "profiler_version": "v2.0",
                "classification_mode": "deterministic_heuristic",
                "classification_disclaimer": (
                    "Sensitive-field detection is heuristic and indicates probable "
                    "sensitive data. It is not a guarantee of complete PII discovery."
                ),
                "column_stats": stats,
                "original_filename_ext": ext,
            },
        )

    @staticmethod
    def _infer_type(sample_values: list[Any]) -> str:
        """Infer basic data type from sample values."""
        non_empty = [v for v in sample_values if v is not None and str(v).strip()]
        if not non_empty:
            return "string"

        all_int = True
        all_float = True
        for v in non_empty:
            s = str(v).strip()
            try:
                int(s)
            except (ValueError, TypeError):
                all_int = False
            try:
                float(s)
            except (ValueError, TypeError):
                all_float = False

        if all_int:
            return "integer"
        if all_float:
            return "float"
        return "string"
