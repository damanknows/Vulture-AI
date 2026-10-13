"""
Vulture-AI Unified Reproducibility Experiment Runner
===================================================

This script executes the complete end-to-end experimental evaluation pipeline:
1. Validates benchmark integrity and computes dataset SHA-256 hash.
2. Runs all 5 baseline prioritization methods.
3. Runs all 5 architectural and component ablation conditions.
4. Computes deterministic evaluation metrics (NDCG@10, P@10, R@10, Spearman rho).
5. Generates LaTeX tables and empirical ranking plots.
6. Records complete environment provenance and configuration metadata in
   experiments/results/reproducibility_manifest.json.

Reproduction Command:
    python experiments/reproduce_all.py
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import sys
import matplotlib
import numpy as np
import scipy

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generate_data import load_and_validate_benchmark, compute_benchmark_sha256
from risk_engine import DEFAULT_WEIGHTS
from experiments.run_baselines import run_baselines
from experiments.run_ablation import run_ablation
from experiments.compute_metrics import compute_all
from experiments.make_tables import make_tables


def run_reproducible_pipeline(benchmark_path: str = "data/benchmark/cves.csv"):
    print("=" * 70)
    print("VULTURE-AI REPRODUCIBLE EXPERIMENT PIPELINE")
    print("=" * 70)

    # 1. Benchmark Integrity Check & Hash
    print("\n[Step 1/5] Validating benchmark dataset integrity...")
    records, sha256_hash = load_and_validate_benchmark(benchmark_path)
    print(f"  Benchmark File: {benchmark_path}")
    print(f"  Verified Rows:  {len(records)} records (39 real public CVEs + 2 synthetic missing-data edge cases)")
    print(f"  SHA-256 Hash:   {sha256_hash}")

    # 2. Run Baselines
    print("\n[Step 2/5] Running baseline prioritization models...")
    baseline_results = run_baselines(benchmark_path)

    # 3. Run Ablation Study
    print("\n[Step 3/5] Running ablation study (component & architectural)...")
    ablation_results = run_ablation(benchmark_path)

    # 4. Compute Metrics
    print("\n[Step 4/5] Computing deterministic ranking metrics...")
    metrics_results = compute_all()

    # 5. Generate Tables & Figures
    print("\n[Step 5/5] Generating LaTeX tables and empirical ranking plots...")
    make_tables()

    # 6. Record Full Provenance Manifest
    manifest = {
        "execution_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_provenance": {
            "filepath": benchmark_path,
            "sha256": sha256_hash,
            "record_count": len(records),
            "real_cve_count": 39,
            "synthetic_edge_case_count": 2,
            "synthetic_records": [
                "CVE-2024-99991 (missing CVSS edge-case)",
                "CVE-2024-99992 (missing EPSS edge-case)"
            ],
            "sources": [
                "NIST NVD (CVSS v3.1 base score)",
                "FIRST.org EPSS (Live API probability snapshot)",
                "CISA KEV Catalog (Active exploitation listing)",
                "CISA SSVC Decision Rubric (Ordinal reference priorities; author-curated heuristic judgments)"
            ]
        },
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "numpy_version": np.__version__,
            "scipy_version": scipy.__version__,
            "matplotlib_version": matplotlib.__version__
        },
        "experimental_settings": {
            "vrs_default_weights": DEFAULT_WEIGHTS,
            "missing_data_policies": {
                "missing_cvss": "bucket='unavailable', vrs=None, ranked last",
                "missing_epss_default": 0.0,
                "missing_exposure_default": 0.5,
                "missing_criticality_default": 0.5
            },
            "tie_breaking_order": [
                "1. Bucket tier (urgent KEV matches sort first)",
                "2. Numerical VRS score (descending)",
                "3. Primary CVE ID (alphabetical ascending)"
            ],
            "evaluation_thresholds": {
                "tau_act": 3,
                "tau_actionable": 2,
                "k_budget": 10
            },
            "ablation_weight_policy": "Proportional renormalization: w_j' = w_j / sum(active_w)"
        },
        "results_summary": metrics_results
    }

    manifest_path = "experiments/results/reproducibility_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[DONE] Provenance manifest saved to {manifest_path}")
    print("=" * 70)
    return manifest


if __name__ == "__main__":
    run_reproducible_pipeline()
