"""Training and evaluation pipeline for IncidentForge ML Risk Model.

Generates a deterministic synthetic SOC incident dataset, trains a baseline
Logistic Regression model, computes evaluation metrics (precision, recall, f1,
ROC-AUC, average precision / PR-AUC, confusion matrix), and persists the
model artifact and metadata.
"""

from datetime import datetime, timezone
import json
import logging
import math
from pathlib import Path
import random
from typing import Any

from .features import FEATURE_NAMES, FEATURE_VERSION

logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_FILE = ARTIFACTS_DIR / "risk_model_v1.joblib"
METADATA_FILE = ARTIFACTS_DIR / "model_metadata_v1.json"


def generate_synthetic_dataset(
    n_samples: int = 400, seed: int = 42
) -> tuple[list[list[float]], list[int]]:
    """Generate a deterministic synthetic SOC dataset for development and testing.

    NOTE: This dataset is synthetic development data for development and validation.
    It does NOT claim real-world SOC benchmark accuracy.
    """
    rng = random.Random(seed)
    X: list[list[float]] = []
    y: list[int] = []

    for _ in range(n_samples):
        # 50% benign / low-risk, 50% correlated multi-stage attack
        is_attack = rng.random() < 0.50

        if is_attack:
            inc_sev = rng.uniform(8.0, 14.0)
            corr_sev = rng.uniform(8.0, 15.0)
            alert_count = float(rng.randint(2, 8))
            event_count = float(rng.randint(3, 15))
            corr_count = float(rng.randint(1, 3))
            mitre_count = float(rng.randint(1, 5))
            has_auth = 1.0 if rng.random() < 0.70 else 0.0
            has_proc = 1.0 if rng.random() < 0.80 else 0.0
            has_net = 1.0 if rng.random() < 0.65 else 0.0
            has_priv = 1.0 if rng.random() < 0.60 else 0.0
            time_span = rng.uniform(60.0, 3600.0)
            entity_diversity = float(rng.randint(2, 6))
            label = 1
        else:
            inc_sev = rng.uniform(2.0, 7.0)
            corr_sev = rng.uniform(2.0, 7.0)
            alert_count = float(rng.randint(1, 2))
            event_count = float(rng.randint(1, 4))
            corr_count = 1.0
            mitre_count = float(rng.randint(0, 1))
            has_auth = 1.0 if rng.random() < 0.20 else 0.0
            has_proc = 1.0 if rng.random() < 0.15 else 0.0
            has_net = 1.0 if rng.random() < 0.10 else 0.0
            has_priv = 0.0
            time_span = rng.uniform(0.0, 300.0)
            entity_diversity = 1.0
            label = 0

        row = [
            round(inc_sev, 2),
            round(corr_sev, 2),
            alert_count,
            event_count,
            corr_count,
            mitre_count,
            has_auth,
            has_proc,
            has_net,
            has_priv,
            round(time_span, 1),
            entity_diversity,
            # 11 Dataset mock features
            1.0 if is_attack and rng.random() < 0.2 else 0.0,  # has_dataset_activity
            1.0 if is_attack and rng.random() < 0.1 else 0.0,  # has_sensitive_data_access
            0.0,  # has_bulk_export
            0.0,  # has_dataset_exfiltration
            0.0,  # dataset_sensitivity
            0.0,  # records_accessed_normalized
            0.0,  # records_modified_normalized
            0.0,  # export_volume_normalized
            0.0,  # sensitive_columns_count
            0.0,  # actor_novelty
            0.0,  # bulk_access_indicator
        ]
        X.append(row)
        y.append(label)

    return X, y


def _compute_metrics(
    y_true: list[int], y_pred: list[int], y_proba: list[float]
) -> dict[str, Any]:
    """Compute classification evaluation metrics in pure Python."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    # Trapezoidal ROC-AUC approximation
    pairs = sorted(zip(y_proba, y_true), key=lambda p: p[0], reverse=True)
    positives = sum(y_true)
    negatives = len(y_true) - positives

    if positives > 0 and negatives > 0:
        tpr_prev, fpr_prev = 0.0, 0.0
        auc = 0.0
        tp_accum, fp_accum = 0, 0
        for p, label in pairs:
            if label == 1:
                tp_accum += 1
            else:
                fp_accum += 1
            tpr = tp_accum / positives
            fpr = fp_accum / negatives
            auc += (fpr - fpr_prev) * (tpr + tpr_prev) / 2.0
            tpr_prev, fpr_prev = tpr, fpr
    else:
        auc = 0.5

    # Average Precision (PR-AUC)
    if positives > 0:
        ap = 0.0
        tp_c = 0
        for i, (prob, label) in enumerate(pairs, start=1):
            if label == 1:
                tp_c += 1
                precision_at_i = tp_c / i
                ap += precision_at_i
        pr_auc = ap / positives
    else:
        pr_auc = 0.0

    return {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "average_precision_pr_auc": round(pr_auc, 4),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def train_and_evaluate(
    seed: int = 42,
    artifacts_dir: Path | None = None,
) -> dict[str, Any]:
    """Train baseline Logistic Regression pipeline, evaluate, and save artifact."""
    target_dir = artifacts_dir or ARTIFACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate synthetic dataset
    X, y = generate_synthetic_dataset(n_samples=400, seed=seed)
    n_total = len(X)
    n_train = int(n_total * 0.75)

    # Shuffle deterministically
    indices = list(range(n_total))
    rng = random.Random(seed)
    rng.shuffle(indices)

    X_train = [X[i] for i in indices[:n_train]]
    y_train = [y[i] for i in indices[:n_train]]
    X_test = [X[i] for i in indices[n_train:]]
    y_test = [y[i] for i in indices[n_train:]]

    # Check if scikit-learn is available
    sklearn_available = False
    sklearn_version = "not_installed"
    try:
        import joblib
        import numpy as np
        import sklearn
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        sklearn_available = True
        sklearn_version = sklearn.__version__
    except ImportError:
        pass

    if sklearn_available:
        pipeline = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        C=1.0,
                        random_state=seed,
                        max_iter=1000,
                        class_weight="balanced",
                    ),
                ),
            ]
        )
        pipeline.fit(np.array(X_train), np.array(y_train))
        y_proba = pipeline.predict_proba(np.array(X_test))[:, 1].tolist()
        y_pred = pipeline.predict(np.array(X_test)).tolist()

        clf = pipeline.named_steps["classifier"]
        scaler = pipeline.named_steps["scaler"]
        raw_coefs = clf.coef_[0] / scaler.scale_
        weights_dict = {
            FEATURE_NAMES[i]: round(float(raw_coefs[i]), 4)
            for i in range(len(FEATURE_NAMES))
        }
        intercept = float(
            clf.intercept_[0] - np.sum(clf.coef_[0] * scaler.mean_ / scaler.scale_)
        )
        joblib.dump(pipeline, target_dir / "risk_model_v1.joblib")
    else:
        # Exact deterministic pure Python Logistic Regression with standardization & L2 penalty
        n_features = len(FEATURE_NAMES)
        means = [
            sum(X_train[r][c] for r in range(len(X_train))) / len(X_train)
            for c in range(n_features)
        ]
        stds = [
            math.sqrt(
                sum((X_train[r][c] - means[c]) ** 2 for r in range(len(X_train)))
                / len(X_train)
            )
            or 1.0
            for c in range(n_features)
        ]

        # Standardize train
        X_train_std = [
            [(X_train[r][c] - means[c]) / stds[c] for c in range(n_features)]
            for r in range(len(X_train))
        ]

        # Gradient descent
        w = [0.0] * n_features
        b = 0.0
        lr = 0.05
        l2_reg = 0.01

        for _ in range(500):
            grad_w = [l2_reg * wi for wi in w]
            grad_b = 0.0
            for r in range(len(X_train_std)):
                z = b + sum(w[c] * X_train_std[r][c] for c in range(n_features))
                z = max(-40.0, min(40.0, z))
                p = 1.0 / (1.0 + math.exp(-z))
                err = p - y_train[r]
                for c in range(n_features):
                    grad_w[c] += err * X_train_std[r][c] / len(X_train_std)
                grad_b += err / len(X_train_std)

            for c in range(n_features):
                w[c] -= lr * grad_w[c]
            b -= lr * grad_b

        # Compute unscaled weights
        weights_dict = {
            FEATURE_NAMES[c]: round(w[c] / stds[c], 4) for c in range(n_features)
        }
        intercept = round(b - sum(w[c] * means[c] / stds[c] for c in range(n_features)), 4)

        # Test evaluation
        y_proba = []
        y_pred = []
        for r in range(len(X_test)):
            z = intercept + sum(weights_dict[FEATURE_NAMES[c]] * X_test[r][c] for c in range(n_features))
            z = max(-40.0, min(40.0, z))
            p = 1.0 / (1.0 + math.exp(-z))
            y_proba.append(p)
            y_pred.append(1 if p >= 0.5 else 0)

    metrics = _compute_metrics(y_test, y_pred, y_proba)

    metadata = {
        "model_name": "baseline_logistic_regression",
        "model_version": "v1.0",
        "feature_version": FEATURE_VERSION,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "scikit_learn_version": sklearn_version,
        "features": FEATURE_NAMES,
        "weights": weights_dict,
        "intercept": intercept,
        "evaluation_metrics": metrics,
        "dataset_info": {
            "type": "synthetic_development_data",
            "n_samples": len(X),
            "seed": seed,
            "note": "For development and testing only. Does not claim real-world SOC benchmark performance.",
        },
    }

    meta_path = target_dir / "model_metadata_v1.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Model metadata persisted to {meta_path}")
    return metadata


if __name__ == "__main__":
    train_and_evaluate()
