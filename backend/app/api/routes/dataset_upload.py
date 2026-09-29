"""Dataset Upload & Security Assessment endpoint.

POST /api/v1/data-assets/upload
  - Accepts multipart/form-data with a CSV, JSON, or Parquet file.
  - Writes the upload to a safe temporary directory (never using user-supplied paths).
  - Profiles the dataset (metadata only — no raw rows returned).
  - Runs a deterministic security assessment.
  - Registers sanitized metadata in the catalog.
  - Removes the temporary raw file in a finally-block (always cleaned up).
  - Returns a full DatasetUploadResult with assessment and findings.

SECURITY CONTROLS:
  - Extension allowlist: .csv .json .jsonl .parquet
  - Content-type validation (best-effort, not trusted alone)
  - Max file size: 50 MB
  - Temporary files use uuid4 names — no path from user input
  - Path traversal: impossible (we never use user filename as path)
  - Cleanup: always in finally block
  - No shell/subprocess execution on uploaded content
  - No raw rows persisted
  - Logs contain metadata only (no file content)
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlmodel import Session

from ...database import get_session
from ...models.dataset_assessment import DatasetUploadResult
from ...persistence.repositories import DatasetRepository
from ...services.dataset import DatasetService
from ...services.dataset_assessment import DatasetAssessmentService
from ...services.dataset_profiler import DatasetProfiler

router = APIRouter(prefix="/api/v1/data-assets", tags=["data-assets"])
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
_ALLOWED_EXTENSIONS = frozenset({"csv", "json", "jsonl", "parquet"})
_NOT_PERSISTED_PATH = "not-persisted"

# Temp directory: always inside system temp, never in the repo
_UPLOAD_TMP_DIR = Path(tempfile.gettempdir()) / "incidentforge_uploads"


def _ensure_tmp_dir() -> Path:
    """Ensure the upload temp directory exists. Never inside the project repo."""
    _UPLOAD_TMP_DIR.mkdir(parents=True, exist_ok=True)
    return _UPLOAD_TMP_DIR


def _safe_extension(filename: str) -> str | None:
    """Extract extension from user filename ONLY for allowlist check. Never used as path."""
    # Use only the final suffix; ignore directory components (path-traversal names).
    safe_name = Path(filename.replace("\\", "/")).name
    suffix = Path(safe_name).suffix.lstrip(".").lower()
    return suffix if suffix in _ALLOWED_EXTENSIONS else None


def _validate_content_matches_extension(ext: str, raw_bytes: bytes) -> None:
    """Do not trust the filename alone — reject obvious content/extension mismatches."""
    head = raw_bytes[:16]
    stripped = raw_bytes.lstrip()[:8]

    if ext == "parquet":
        if not raw_bytes.startswith(b"PAR1"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="File content does not match the Parquet format (missing PAR1 magic bytes).",
            )
        return

    if ext in ("json", "jsonl"):
        if stripped[:1] not in (b"{", b"["):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="File content does not appear to be JSON (expected '{' or '[').",
            )
        return

    if ext == "csv":
        if raw_bytes.startswith(b"PAR1"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="File content looks like Parquet, not CSV.",
            )
        if stripped[:1] in (b"{", b"["):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="File content looks like JSON, not CSV.",
            )
        return

    _ = head  # unused; kept for future magic-byte expansion


def get_dataset_service(session: Session = Depends(get_session)) -> DatasetService:
    return DatasetService(DatasetRepository(session))


@router.post(
    "/upload",
    response_model=DatasetUploadResult,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and assess a dataset",
    description=(
        "Upload a CSV, JSON, or Parquet file for security profiling and assessment. "
        "The raw file is NEVER persisted — it is processed in a temporary directory "
        "and removed after profiling. Only sanitized metadata is registered."
    ),
)
async def upload_dataset(
    file: Annotated[UploadFile, File(description="CSV, JSON, or Parquet dataset file")],
    display_name: Annotated[
        str | None,
        Form(description="Optional human-readable display name for the dataset"),
    ] = None,
    svc: DatasetService = Depends(get_dataset_service),
) -> DatasetUploadResult:
    """Upload a dataset file, run security assessment, register sanitized metadata."""

    # -----------------------------------------------------------------------
    # 1. Validate filename extension (allowlist)
    # -----------------------------------------------------------------------
    original_filename = file.filename or "upload"
    ext = _safe_extension(original_filename)
    if ext is None:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"Unsupported file format. Allowed formats: "
                f"{sorted(_ALLOWED_EXTENSIONS)}. "
                f"Received filename: {original_filename!r}"
            ),
        )

    logger.info(
        "Dataset upload received",
        extra={"filename_ext": ext, "content_type": file.content_type},
    )

    # -----------------------------------------------------------------------
    # 2. Read file into memory with size guard
    # -----------------------------------------------------------------------
    try:
        raw_bytes = await file.read(_MAX_UPLOAD_BYTES + 1)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file",
        ) from exc

    if len(raw_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {_MAX_UPLOAD_BYTES // (1024*1024)} MB",
        )

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # -----------------------------------------------------------------------
    # 3. Write to safe temp file (uuid4 name — never user-supplied path)
    # -----------------------------------------------------------------------
    tmp_dir = _ensure_tmp_dir()
    safe_tmp_name = f"upload_{uuid.uuid4().hex}.{ext}"
    tmp_path = tmp_dir / safe_tmp_name  # No user input in path

    _validate_content_matches_extension(ext, raw_bytes)

    tmp_path.write_bytes(raw_bytes)
    logger.info(
        "Dataset saved to temporary path",
        extra={"tmp_size_bytes": len(raw_bytes), "ext": ext},
    )

    # -----------------------------------------------------------------------
    # 4. Profile + Assess + Register — always cleanup in finally
    # -----------------------------------------------------------------------
    result: DatasetUploadResult | None = None
    try:
        ds_name = display_name.strip() if display_name and display_name.strip() else Path(original_filename).stem
        dataset_id = f"ds-{hashlib.sha256(raw_bytes).hexdigest()[:12]}-{uuid.uuid4().hex[:6]}"

        try:
            asset = DatasetProfiler.profile_file(
                str(tmp_path),
                dataset_id=dataset_id,
                name=ds_name,
                persist_path=False,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Dataset structure error: {exc}",
            ) from exc
        except Exception as exc:
            logger.warning("Dataset profiling failed", extra={"ext": ext, "error": type(exc).__name__})
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Failed to profile dataset. Ensure the file is a valid, well-formed CSV, JSON, or Parquet.",
            ) from exc

        if asset.record_count == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Dataset appears to be empty or could not be parsed. Check file format and encoding.",
            )

        asset.file_path = _NOT_PERSISTED_PATH

        assessor = DatasetAssessmentService()
        assessment = assessor.assess(asset)

        asset.metadata["security_score"] = assessment.security_score.score
        asset.metadata["security_risk_level"] = assessment.security_score.risk_level
        asset.metadata["finding_count"] = len(assessment.findings)
        asset.metadata["assessed_at"] = assessment.assessed_at.isoformat()
        asset.metadata["findings_summary"] = [
            {
                "finding_id": f.finding_id,
                "severity": f.severity.value,
                "title": f.title,
                "affected_columns": f.affected_columns,
                "recommendation": f.recommendation,
            }
            for f in assessment.findings
        ]
        asset.metadata["contributing_factors"] = assessment.security_score.contributing_factors
        # Never persist sampled values — column_stats already contains ratios only
        assessment.asset.file_path = _NOT_PERSISTED_PATH

        svc.register_asset(asset)

        logger.info(
            "Dataset registered after upload assessment",
            extra={
                "dataset_id": asset.dataset_id,
                "sensitivity": asset.sensitivity.value,
                "security_score": assessment.security_score.score,
                "finding_count": len(assessment.findings),
            },
        )

        result = DatasetUploadResult(
            success=True,
            dataset_id=asset.dataset_id,
            assessment=assessment,
            registered=True,
            temp_file_cleaned=False,
            message=f"Dataset '{ds_name}' profiled and registered successfully.",
        )

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception("Unexpected error during dataset upload processing")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Dataset processing failed unexpectedly. Please try again.",
        ) from exc

    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
                if result is not None:
                    result.temp_file_cleaned = True
                logger.info("Temporary dataset file removed", extra={"ext": ext})
        except Exception:
            logger.warning("Failed to remove temporary dataset file", extra={"ext": ext})

    return result
