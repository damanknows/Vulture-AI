"""
Vulture-AI Ablation Study Runner
================================

This module implements a mathematically principled, reproducible ablation study
for the Vulture Risk Score (VRS) prioritization architecture.

Methodological Policies:
1. Proportional Renormalization Policy:
   When ablating component i, its weight is set to 0.0 and remaining weights are
   proportionally rescaled:
       w_j' = w_j / sum_{k not ablated} w_k
   This completely avoids arbitrary, ungrounded manual weight redistribution.

2. Bucket-Policy vs. Continuous-Score Architectural Ablation:
   Evaluates full VRS weights with and without the KEV-first urgent bucket override
   (use_buckets=False) to isolate categorical filtering from continuous scoring.

3. Constant Population Guarantee:
   Every ablation condition evaluates the identical 41-CVE benchmark population
   against identical reference labels and tie-breaking rules.
"""

import json
import os
import sys
from typing import Dict, List

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import DEFAULT_WEIGHTS, rank_findings
from experiments.run_baselines import load_benchmark


def ablate_weights(base_weights: Dict[str, float], components_to_remove: List[str]) -> Dict[str, float]:
    """
    Proportionally renormalizes remaining weights when removing components.
    Ensures weights strictly sum to 1.0 without arbitrary guesswork.
    """
    active_keys = [k for k in base_weights if k not in components_to_remove]
    active_sum = sum(base_weights[k] for k in active_keys)
    if active_sum <= 0:
        raise ValueError("Cannot ablate all components; remaining sum must be > 0.")

    new_weights = {}
    for k in base_weights:
        if k in components_to_remove:
            new_weights[k] = 0.0
        else:
            new_weights[k] = round(base_weights[k] / active_sum, 6)

    # Adjust rounding discrepancy if any
    diff = round(1.0 - sum(new_weights.values()), 6)
    if diff != 0.0:
        first_active = active_keys[0]
        new_weights[first_active] = round(new_weights[first_active] + diff, 6)

    return new_weights


def run_ablation(benchmark_path="data/benchmark/cves.csv"):
    findings, ref_ranking, relevance_dict = load_benchmark(benchmark_path)

    # 1. Full VRS Model (Default weights + Urgent Bucket override)
    full_weights = dict(DEFAULT_WEIGHTS)
    full_ranked = rank_findings(findings, weights=full_weights, use_buckets=True)
    full_ranking = [r["primary_cve"] for r in full_ranked]

    # 2. No EPSS Component (w_E = 0, proportional renormalization)
    no_epss_weights = ablate_weights(DEFAULT_WEIGHTS, ["w_E"])
    no_epss_ranked = rank_findings(findings, weights=no_epss_weights, use_buckets=True)
    no_epss_ranking = [r["primary_cve"] for r in no_epss_ranked]

    # 3. No KEV Component (w_K = 0, proportional renormalization)
    no_kev_weights = ablate_weights(DEFAULT_WEIGHTS, ["w_K"])
    no_kev_ranked = rank_findings(findings, weights=no_kev_weights, use_buckets=True)
    no_kev_ranking = [r["primary_cve"] for r in no_kev_ranked]

    # 4. No Environmental Context (w_N = 0, w_A = 0, proportional renormalization)
    no_context_weights = ablate_weights(DEFAULT_WEIGHTS, ["w_N", "w_A"])
    no_context_ranked = rank_findings(findings, weights=no_context_weights, use_buckets=True)
    no_context_ranking = [r["primary_cve"] for r in no_context_ranked]

    # 5. No Bucket Policy (Pure Continuous VRS Score Ranking, use_buckets=False)
    no_bucket_ranked = rank_findings(findings, weights=full_weights, use_buckets=False)
    no_bucket_ranking = [r["primary_cve"] for r in no_bucket_ranked]

    ablation_results = {
        "benchmark_file": benchmark_path,
        "sample_count": len(findings),
        "configurations": {
            "vrs_full": {"weights": full_weights, "use_buckets": True, "description": "Full VRS with KEV-first bucket policy"},
            "vrs_no_epss": {"weights": no_epss_weights, "use_buckets": True, "description": "EPSS ablated with proportional renormalization"},
            "vrs_no_kev": {"weights": no_kev_weights, "use_buckets": True, "description": "KEV weight ablated with proportional renormalization"},
            "vrs_no_context": {"weights": no_context_weights, "use_buckets": True, "description": "Exposure & Criticality ablated (technical metrics only)"},
            "vrs_no_buckets": {"weights": full_weights, "use_buckets": False, "description": "Full weights ranked purely by continuous numerical score (no bucket override)"}
        },
        "vrs_full": full_ranking,
        "vrs_no_epss": no_epss_ranking,
        "vrs_no_kev": no_kev_ranking,
        "vrs_no_context": no_context_ranking,
        "vrs_no_buckets": no_bucket_ranking
    }

    os.makedirs("experiments/results", exist_ok=True)
    output_path = "experiments/results/ablation.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2)

    print(f"Computed ablation rankings for {len(findings)} records across 5 conditions.")
    print(f"Saved ablation outputs to {output_path}")
    return ablation_results


if __name__ == "__main__":
    run_ablation()
