"""Risk model interface and implementations for IncidentForge."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import logging
import math
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES, FEATURE_VERSION, generate_reason_codes

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelPrediction:
    risk_score: int  # 0 - 100
    risk_level: str  # low, medium, high, critical
    probability: float  # 0.0 - 1.0
    reason_codes: list[str]
    feature_contributions: dict[str, float]
    model_name: str
    model_version: str
    feature_version: str


def probability_to_score_and_level(probability: float) -> tuple[int, str]:
    """Convert raw probability to 0-100 risk score and discrete SOC risk level."""
    clamped = max(0.0, min(1.0, probability))
    risk_score = int(round(clamped * 100))
    risk_score = max(0, min(100, risk_score))

    if risk_score < 25:
        risk_level = "low"
    elif risk_score < 50:
        risk_level = "medium"
    elif risk_score < 75:
        risk_level = "high"
    else:
        risk_level = "critical"

    return risk_score, risk_level


class RiskModel(ABC):
    """Abstract baseline for all IncidentForge risk scoring models."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_version(self) -> str:
        pass

    @property
    @abstractmethod
    def feature_version(self) -> str:
        pass

    @abstractmethod
    def predict(self, features: dict[str, float]) -> ModelPrediction:
        """Score an incident from extracted features."""
        pass


class BaselineLogisticRiskModel(RiskModel):
    """Calibrated, interpretable Logistic Regression risk model for SOC incidents.

    Can operate either directly from a trained scikit-learn pipeline artifact or
    from calibrated learned weights stored in a local metadata artifact.
    """

    def __init__(
        self,
        artifact_path: Path | None = None,
        metadata_path: Path | None = None,
    ):
        self._model_name = "baseline_logistic_regression"
        self._model_version = "v1.0"
        self._feature_version = FEATURE_VERSION
        self._pipeline: Any = None

        default_artifacts_dir = Path(__file__).resolve().parent / "artifacts"
        effective_artifact = artifact_path or (default_artifacts_dir / "risk_model_v1.joblib")
        effective_metadata = metadata_path or (default_artifacts_dir / "model_metadata_v1.json")

        # Calibrated default weights learned from synthetic SOC incident distributions
        self._weights: dict[str, float] = {
            # v1.0 endpoint weights (unchanged)
            "incident_severity": 0.25,
            "correlation_severity": 0.35,
            "alert_count": 0.40,
            "event_count": 0.15,
            "correlation_count": 0.20,
            "mitre_count": 0.60,
            "has_auth_attack": 0.80,
            "has_suspicious_process": 0.90,
            "has_network_activity": 0.70,
            "has_privilege_escalation": 1.20,
            "time_span_seconds": 0.0001,
            "entity_diversity": 0.20,
            # v2.0 dataset security weights
            "has_dataset_activity": 0.50,
            "has_sensitive_data_access": 1.00,
            "has_bulk_export": 0.90,
            "has_dataset_exfiltration": 1.30,
            "dataset_sensitivity": 0.80,
            "records_accessed_normalized": 0.60,
            "records_modified_normalized": 0.70,
            "export_volume_normalized": 0.75,
            "sensitive_columns_count": 0.30,
            "actor_novelty": 0.80,
            "bulk_access_indicator": 0.65,
        }
        self._intercept: float = -4.5

        # Attempt to load metadata if available
        if effective_metadata and effective_metadata.exists():
            try:
                with open(effective_metadata, encoding="utf-8") as f:
                    meta = json.load(f)
                    self._model_name = meta.get("model_name", self._model_name)
                    self._model_version = meta.get("model_version", self._model_version)
                    if "weights" in meta:
                        self._weights = meta["weights"]
                    if "intercept" in meta:
                        self._intercept = float(meta["intercept"])
            except Exception as e:
                logger.warning(f"Failed to load model metadata from {effective_metadata}: {e}")

        # Attempt to load trained artifact if available
        if effective_artifact and effective_artifact.exists():
            try:
                import joblib

                self._pipeline = joblib.load(effective_artifact)
                logger.info(f"Loaded trained ML artifact from {effective_artifact}")
            except Exception as e:
                logger.warning(f"Failed to load artifact from {effective_artifact}: {e}")

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def feature_version(self) -> str:
        return self._feature_version

    def predict(self, features: dict[str, float]) -> ModelPrediction:
        contributions: dict[str, float] = {}

        if self._pipeline is not None:
            try:
                import numpy as np

                vector = np.array([[features.get(k, 0.0) for k in FEATURE_NAMES]])
                proba = float(self._pipeline.predict_proba(vector)[0][1])
            except Exception:
                proba = self._calculate_sigmoid_proba(features, contributions)
        else:
            proba = self._calculate_sigmoid_proba(features, contributions)

        if not contributions:
            for k in FEATURE_NAMES:
                val = features.get(k, 0.0)
                w = self._weights.get(k, 0.0)
                contributions[k] = round(val * w, 4)

        risk_score, risk_level = probability_to_score_and_level(proba)
        reasons = generate_reason_codes(features, risk_score)

        return ModelPrediction(
            risk_score=risk_score,
            risk_level=risk_level,
            probability=round(proba, 4),
            reason_codes=reasons,
            feature_contributions=contributions,
            model_name=self.model_name,
            model_version=self.model_version,
            feature_version=self.feature_version,
        )

    def _calculate_sigmoid_proba(
        self, features: dict[str, float], contributions: dict[str, float]
    ) -> float:
        z = self._intercept
        for k in FEATURE_NAMES:
            val = features.get(k, 0.0)
            w = self._weights.get(k, 0.0)
            c = val * w
            contributions[k] = round(c, 4)
            z += c

        # Sigmoid clamping to prevent overflow
        if z >= 40.0:
            return 1.0
        if z <= -40.0:
            return 0.0
        return 1.0 / (1.0 + math.exp(-z))
