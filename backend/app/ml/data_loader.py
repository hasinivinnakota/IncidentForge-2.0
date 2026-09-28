# data_loader.py – unified loader for real‑world CSVs and the synthetic generator
"""Utility module to load datasets for IncidentForge.

The original IncidentForge project ships with a synthetic data generator used for
development. Real‑world CSVs are stored under ``datasets/real_world`` with the
following sub‑folders:

- ``attack-simulations``
- ``sample-alerts``
- ``benign-baselines``

Each folder contains a ``train.csv`` file that follows the same column order as
the synthetic data (see ``train.py`` for the feature list).

The ``load_dataset`` function abstracts the source – callers pass a logical
dataset name and receive a ``pandas.DataFrame`` ready for validation.
"""

from pathlib import Path
import pandas as pd

# Compute repository root relative to this file (3 parents up from this module)
REPO_ROOT = Path(__file__).resolve().parents[3]

# Logical name → CSV path mapping
DATASET_CONFIG = {
    "synthetic": REPO_ROOT / "datasets" / "synthetic" / "train.csv",
    "attack-simulations": REPO_ROOT / "datasets" / "real_world" / "attack-simulations" / "train.csv",
    "sample-alerts": REPO_ROOT / "datasets" / "real_world" / "sample-alerts" / "train.csv",
    "benign-baselines": REPO_ROOT / "datasets" / "real_world" / "benign-baselines" / "train.csv",
}

def load_dataset(name: str) -> pd.DataFrame:
    """Load a dataset by logical name and return a pandas DataFrame.

    Parameters
    ----------
    name: str
        One of the keys in ``DATASET_CONFIG``.
    Raises
    ------
    ValueError
        If the name is unknown.
    FileNotFoundError
        If the CSV file does not exist.
    """
    if name not in DATASET_CONFIG:
        raise ValueError(
            f"Dataset '{name}' not recognised. Available: {list(DATASET_CONFIG)}"
        )
    path = DATASET_CONFIG[name]
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found at {path}")
    return pd.read_csv(path)

def available_datasets() -> list[str]:
    """Return a list of supported dataset identifiers."""
    return list(DATASET_CONFIG.keys())

