"""Generate synthetic dataset fixtures for IncidentForge testing.

ALL DATA IS SYNTHETIC / FAKE. No real personal information.
Generates:
  - tests/fixtures/financial_records.csv
  - tests/fixtures/financial_records.json

These are used in tests for the upload endpoint and security assessment pipeline.
Parquet fixture is generated at test time (requires pandas/pyarrow dependencies).
"""

import csv
import json
import os
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Synthetic data — clearly fake values
# ---------------------------------------------------------------------------

SYNTHETIC_ROWS = [
    {
        "customer_id": f"CUST-{1000 + i:04d}",
        "customer_name": f"Test Customer {i}",
        "email": f"testuser{i}@synthetic-demo.invalid",
        "account_number": f"ACC-{5000 + i:08d}",
        "transaction_amount": round(100.0 + (i * 17.33) % 9900, 2),
        "transaction_date": f"2026-0{(i % 9) + 1:01d}-{(i % 28) + 1:02d}",
        "customer_phone": f"+1-555-{(i * 7 + 100) % 900:03d}-{(i * 13 + 1000) % 9000:04d}",
        "city": ["Synthville", "Testberg", "Demotown", "Fakefield", "Simulacra"][i % 5],
        "risk_score": round((i * 3.7) % 100, 1),
        "account_status": ["active", "inactive", "suspended"][i % 3],
    }
    for i in range(250)
]


def generate_csv() -> Path:
    out = FIXTURE_DIR / "financial_records.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SYNTHETIC_ROWS[0].keys())
        writer.writeheader()
        writer.writerows(SYNTHETIC_ROWS)
    return out


def generate_json() -> Path:
    out = FIXTURE_DIR / "financial_records.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(SYNTHETIC_ROWS, f, indent=2)
    return out


def generate_all() -> dict[str, Path]:
    return {
        "csv": generate_csv(),
        "json": generate_json(),
    }


if __name__ == "__main__":
    results = generate_all()
    for fmt, path in results.items():
        print(f"Generated {fmt}: {path} ({path.stat().st_size} bytes)")
