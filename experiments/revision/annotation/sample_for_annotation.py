"""
Blind Annotation Sampler & Template Generator (41-CVE Exploratory Benchmark)
============================================================================

Samples 20 real records from `data/benchmark/cves.csv` with a fixed seed
(`20261127`) and writes:
- `experiments/revision/annotation/blind_sheet.csv`: ONLY `cve_id` and `description`
  (no VRS, no input scores, no reference_priority, no independent_label).
- `experiments/revision/annotation/annotation_template.csv`: empty rater sheet
  with columns `rater_id,cve_id,grade,confidence,notes`.

Usage:
    python3 -m experiments.revision.annotation.sample_for_annotation
"""

import csv
import random
from pathlib import Path
from typing import List


BENCHMARK_CSV = Path("data/benchmark/cves.csv")
OUT_DIR = Path("experiments/revision/annotation")
BLIND_CSV = OUT_DIR / "blind_sheet.csv"
TEMPLATE_CSV = OUT_DIR / "annotation_template.csv"

SEED = 20261127
SAMPLE_SIZE = 20


def generate_blind_annotation_files(
    benchmark_path: Path = BENCHMARK_CSV,
    blind_path: Path = BLIND_CSV,
    template_path: Path = TEMPLATE_CSV,
    sample_size: int = SAMPLE_SIZE,
    seed: int = SEED,
) -> List[dict]:
    with open(benchmark_path, "r", encoding="utf-8") as f:
        rows = [
            r
            for r in csv.DictReader(f)
            if not r["cve_id"].strip().startswith("CVE-2024-9999")
        ]

    rng = random.Random(seed)
    sampled = rng.sample(rows, k=min(sample_size, len(rows)))
    sampled.sort(key=lambda r: r["cve_id"])

    blind_path.parent.mkdir(parents=True, exist_ok=True)
    with open(blind_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "description"])
        writer.writeheader()
        for r in sampled:
            writer.writerow({"cve_id": r["cve_id"].strip(), "description": r["description"].strip()})

    with open(template_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rater_id", "cve_id", "grade", "confidence", "notes"])
        writer.writeheader()
        for r in sampled:
            writer.writerow(
                {
                    "rater_id": "",
                    "cve_id": r["cve_id"].strip(),
                    "grade": "",
                    "confidence": "",
                    "notes": "",
                }
            )

    return sampled


if __name__ == "__main__":
    items = generate_blind_annotation_files()
    print(f"Generated blind_sheet.csv and annotation_template.csv with {len(items)} records (seed={SEED}).")
