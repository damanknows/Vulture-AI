"""
Vulture-AI Benchmark Metrics Computation
========================================

Computes evaluation metrics across all baseline methods and ablation conditions:
- NDCG@10 (Normalized Discounted Cumulative Gain at rank 10)
- Precision@10 & Recall@10 at Primary Threshold (tau = 3, Act / Emergency)
- Precision@10 & Recall@10 at Secondary Threshold (tau = 2, Actionable)
- Spearman Rank Correlation Coefficient (rho, mid-rank tie-corrected)

Ensures identical 41-CVE population and ground-truth relevance across all models.
"""

import json
import os
import sys
from typing import Dict, Any

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from metrics import (
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    spearman_correlation,
    validate_ranking_population,
    THRESHOLD_ACT,
    THRESHOLD_ACTIONABLE,
)


def compute_all(
    baselines_path="experiments/results/baselines.json",
    ablation_path="experiments/results/ablation.json",
    metrics_out_path="experiments/results/metrics.json",
    table_out_path="experiments/results/metrics_table.md"
) -> Dict[str, Any]:
    with open(baselines_path, "r", encoding="utf-8") as f:
        baselines = json.load(f)

    ablation = {}
    if os.path.exists(ablation_path):
        try:
            with open(ablation_path, "r", encoding="utf-8") as f:
                ablation = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load ablation results: {e}", file=sys.stderr)

    reference = baselines["reference"]
    relevance_dict = baselines["relevance_dict"]

    models = {
        "CVSS-only": baselines["cvss_only"],
        "EPSS-only": baselines["epss_only"],
        "KEV-first": baselines["kev_first"],
        "CVSS+EPSS+KEV": baselines["combo_baseline"],
        "VRS Proposed": baselines["vrs_v1"]
    }

    if "vrs_no_epss" in ablation:
        models["VRS (No EPSS)"] = ablation["vrs_no_epss"]
    if "vrs_no_kev" in ablation:
        models["VRS (No KEV)"] = ablation["vrs_no_kev"]
    if "vrs_no_context" in ablation:
        models["VRS (No Context)"] = ablation["vrs_no_context"]
    if "vrs_no_buckets" in ablation:
        models["VRS (No Bucket Override)"] = ablation["vrs_no_buckets"]

    headers = [
        "Model",
        "NDCG@10",
        "P@10 (Act)",
        "R@10 (Act)",
        "P@10 (Actionable)",
        "R@10 (Actionable)",
        "Spearman"
    ]
    header_str = " | ".join(headers)
    sep_str = " | ".join(["---"] * len(headers))

    table_lines = [f"| {header_str} |", f"| {sep_str} |"]
    print(header_str)
    print("-" * len(header_str))

    out_results = {}
    for name, ranking in models.items():
        # Validate exact population matching reference
        validate_ranking_population(ranking, reference)

        n10 = ndcg_at_k(ranking, relevance_dict, k=10)
        p10_act = precision_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACT)
        r10_act = recall_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACT)
        p10_actionable = precision_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE)
        r10_actionable = recall_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE)
        sp = spearman_correlation(ranking, reference)

        out_results[name] = {
            "ndcg10": n10,
            "precision10_act": p10_act,
            "recall10_act": r10_act,
            "precision10_actionable": p10_actionable,
            "recall10_actionable": r10_actionable,
            "spearman": sp
        }

        row = (
            f"| {name} | {n10:.4f} | {p10_act:.4f} | {r10_act:.4f} | "
            f"{p10_actionable:.4f} | {r10_actionable:.4f} | {sp:.4f} |"
        )
        print(f"{name:25} | NDCG@10: {n10:.4f} | P@10 (Act): {p10_act:.4f} | R@10 (Act): {r10_act:.4f} | Spearman: {sp:.4f}")
        table_lines.append(row)

    os.makedirs(os.path.dirname(table_out_path), exist_ok=True)
    with open(table_out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(table_lines) + "\n")

    with open(metrics_out_path, "w", encoding="utf-8") as f:
        json.dump(out_results, f, indent=2)

    print(f"\nMetrics written to {metrics_out_path} and {table_out_path}")
    return out_results


if __name__ == "__main__":
    compute_all()
