"""Minimal Hindsight helper for IncidentForge.

The Hindsight SDK (https://github.com/google/hindsight) provides automatic
metadata capture for ML pipelines.  This wrapper simply:
  • Starts a Hindsight session at the beginning of training.
  • Logs key parameters (seed, dataset name, version, etc.).
  • Emits a “model_trained” event with the path to the persisted artifact.
  • Gracefully degrades when the SDK is not installed.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:
    # The real SDK may be installed as `hindsight`.  If not, we fall back to a no‑op.
    from hindsight import Hindsight, Event
    _HIND = Hindsight()
    _AVAILABLE = True
except Exception:  # pragma: no cover
    _HIND = None
    _AVAILABLE = False
    logger.debug("Hindsight SDK not available – running in no‑op mode.")


def start_training(session_id: str, params: Dict[str, Any]) -> None:
    """Start a Hindsight session and log training parameters."""
    if not _AVAILABLE:
        return
    _HIND.start(session_id=session_id, tags=params)
    logger.info("Hindsight training session started: %s", session_id)


def log_model_artifact(artifact_path: str, metadata: Dict[str, Any]) -> None:
    """Emit a model‑trained event with artifact location and any extra metadata."""
    if not _AVAILABLE:
        return
    evt = Event(
        name="model_trained",
        description="IncidentForge risk model persisted",
        data={"artifact_path": artifact_path, **metadata},
    )
    _HIND.log(evt)
    logger.info("Hindsight logged model artifact: %s", artifact_path)


def finish_training() -> None:
    """Close the Hindsight session."""
    if not _AVAILABLE:
        return
    _HIND.finish()
    logger.info("Hindsight training session finished.")
