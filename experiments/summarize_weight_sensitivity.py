"""
Summarize Full-Rank Stability Across Weight Sensitivity Configurations
=====================================================================

Reads the frozen `experiments/revision/sensitivity/results.json` and computes
Spearman rho, Kendall tau, and Top-10 overlap between `original` and each
alternative weight configuration.

Usage:
    python3 -m experiments.summarize_weight_sensitivity
"""

import json
from pathlib import Path
from typing import Dict, List

import scipy.stats

from experiments.metrics import spearman_correlation


IN_PATH = Path("experiments/revision/sensitivity/results.json")
OUT_PATH = Path("experiments/revision/sensitivity/stability_summary.json")


def summarize_sensitivity(
    in_path: Path = IN_PATH,
    out_path: Path = OUT_PATH,
) -> Dict[str, object]:
    with open(in_path, "r", encoding="utf-8") as f:
        rankings: Dict[str, List[str]] = json.load(f)

    if "original" not in rankings:
        raise KeyError("Expected 'original' ranking in sensitivity results.")

    ref = rankings["original"]
    ref_pos = {cid: idx + 1 for idx, cid in enumerate(ref)}
    ref_top10 = set(ref[:10])

    per_config = {}
    rhos = []
    taus = []
    overlaps = []

    for name, order in rankings.items():
        if name == "original":
            continue
        rho = spearman_correlation(order, ref)
        order_pos = {cid: idx + 1 for idx, cid in enumerate(order)}
        x = [order_pos[cid] for cid in ref]
        y = [ref_pos[cid] for cid in ref]
        tau = float(round(float(scipy.stats.kendalltau(x, y).statistic), 4))
        top10_overlap = len(ref_top10.intersection(order[:10]))

        per_config[name] = {
            "spearman_rho": rho,
            "kendall_tau": tau,
            "top10_overlap": top10_overlap,
            "top10_overlap_fraction": round(top10_overlap / 10.0, 4),
        }
        rhos.append(rho)
        taus.append(tau)
        overlaps.append(top10_overlap)

    summary = {
        "source": str(in_path),
        "reference_config": "original",
        "n_records": len(ref),
        "n_perturbations": len(per_config),
        "per_configuration": per_config,
        "aggregate": {
            "spearman_rho_min": min(rhos) if rhos else 0.0,
            "spearman_rho_max": max(rhos) if rhos else 0.0,
            "spearman_rho_mean": round(sum(rhos) / len(rhos), 4) if rhos else 0.0,
            "kendall_tau_min": min(taus) if taus else 0.0,
            "kendall_tau_max": max(taus) if taus else 0.0,
            "kendall_tau_mean": round(sum(taus) / len(taus), 4) if taus else 0.0,
            "top10_overlap_min": min(overlaps) if overlaps else 0,
            "top10_overlap_max": max(overlaps) if overlaps else 0,
        },
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary


if __name__ == "__main__":
    res = summarize_sensitivity()
    print(json.dumps(res["aggregate"], indent=2))
