import tempfile
from pathlib import Path

from backend.app.ml.train import generate_synthetic_dataset, train_and_evaluate


def test_synthetic_dataset_generation_deterministic() -> None:
    X1, y1 = generate_synthetic_dataset(n_samples=50, seed=123)
    X2, y2 = generate_synthetic_dataset(n_samples=50, seed=123)
    assert X1 == X2
    assert y1 == y2
    assert len(X1) == 50
    assert len(y1) == 50


def test_synthetic_dataset_different_seeds() -> None:
    X1, _ = generate_synthetic_dataset(n_samples=50, seed=1)
    X2, _ = generate_synthetic_dataset(n_samples=50, seed=2)
    assert X1 != X2


def test_synthetic_dataset_balance() -> None:
    _, y = generate_synthetic_dataset(n_samples=200, seed=42)
    positives = sum(y)
    assert 70 <= positives <= 130


def test_train_and_evaluate_generates_metadata() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta = train_and_evaluate(seed=42, artifacts_dir=Path(tmp_dir))
        assert meta["model_name"] == "baseline_logistic_regression"
        assert meta["model_version"] == "v1.0"
        assert meta["feature_version"] == "v2.0"
        assert "evaluation_metrics" in meta
        metrics = meta["evaluation_metrics"]
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert "roc_auc" in metrics
        assert "average_precision_pr_auc" in metrics
        assert "confusion_matrix" in metrics

        # Verify saved files
        meta_file = Path(tmp_dir) / "model_metadata_v1.json"
        assert meta_file.exists()
