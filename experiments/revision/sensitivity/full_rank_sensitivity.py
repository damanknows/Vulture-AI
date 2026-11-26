"""
Full-Rank Weight Sensitivity Analysis (41-CVE Exploratory Benchmark)
==================================================================

Computes the full 41-record VRS ordering for each weight configuration in
`experiments/revision/sensitivity/configurations.json` and measures:
- Spearman rho and Kendall tau against the default (`original`) ordering
- Top-5, Top-10, and Top-15 overlap
- Maximum per-record rank shift and the CVE IDs with the largest shifts

Saves output to `experiments/revision/sensitivity/full_rank_results.json`.

Usage:
    python3 -m experiments.revision.sensitivity.full_rank_sensitivity
"""

import json
import math
from pathlib import Path
from typing import Dict, List

import scipy.stats

from experiments.metrics import spearman_correlation
from experiments.run_baselines import load_benchmark
from risk_engine import DEFAULT_WEIGHTS, rank_findings


CONFIGS_PATH = Path("experiments/revision/sensitivity/configurations.json")
BENCHMARK_PATH = Path("data/benchmark/cves.csv")
OUT_PATH = Path("experiments/revision/sensitivity/full_rank_results.json")


def run_full_rank_sensitivity(
    configs_path: Path = CONFIGS_PATH,
    benchmark_path: Path = BENCHMARK_PATH,
    out_path: Path = OUT_PATH,
) -> Dict[str, object]:
    with open(configs_path, "r", encoding="utf-8") as f:
        configs: Dict[str, Dict[str, float]] = json.load(f)

    for name, w in configs.items():
        total = sum(w.values())
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"Configuration {name} weights sum to {total}, expected 1.0")

    findings, _, _ = load_benchmark(str(benchmark_path))
    default_order = [r["primary_cve"] for r in rank_findings(findings, weights=DEFAULT_WEIGHTS)]
    default_pos = {cid: idx + 1 for idx, cid in enumerate(default_order)}

    orderings: Dict[str, List[str]] = {}
    per_config: Dict[str, dict] = {}
    rhos: List[float] = []
    taus: List[float] = []
    max_shifts: List[int] = []

    for name, weights in configs.items():
        order = [r["primary_cve"] for r in rank_findings(findings, weights=weights)]
        orderings[name] = order
        pos = {cid: idx + 1 for idx, cid in enumerate(order)}

        if name == "original":
            assert order == default_order, "Original config must reproduce DEFAULT_WEIGHTS ordering"

        rho = spearman_correlation(order, default_order)
        x = [pos[cid] for cid in default_order]
        y = [default_pos[cid] for cid in default_order]
        tau = float(round(float(scipy.stats.kendalltau(x, y).statistic), 4))

        top5 = len(set(default_order[:5]).intersection(order[:5]))
        top10 = len(set(default_order[:10]).intersection(order[:10]))
        top15 = len(set(default_order[:15]).intersection(order[:15]))

        shifts = {cid: abs(pos[cid] - default_pos[cid]) for cid in default_order}
        max_shift = max(shifts.values())
        max_shift_cves = sorted([cid for cid, s in shifts.items() if s == max_shift])

        per_config[name] = {
            "weights": weights,
            "spearman_rho": rho,
            "kendall_tau": tau,
            "top5_overlap": top5,
            "top10_overlap": top10,
            "top15_overlap": top15,
            "max_rank_shift": max_shift,
            "max_shift_cves": max_shift_cves,
        }
        if name != "original":
            rhos.append(rho)
            taus.append(tau)
            max_shifts.append(max_shift)

    output = {
        "configs_source": str(configs_path),
        "benchmark": str(benchmark_path),
        "n_records": len(default_order),
        "reference_config": "original",
        "per_configuration": per_config,
        "aggregate_excluding_original": {
            "spearman_rho_min": min(rhos),
            "spearman_rho_max": max(rhos),
            "spearman_rho_mean": round(sum(rhos) / len(rhos), 4),
            "kendall_tau_min": min(taus),
            "kendall_tau_max": max(taus),
            "kendall_tau_mean": round(sum(taus) / len(taus), 4),
            "max_rank_shift_overall": max(max_shifts),
        },
        "orderings": orderings,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    return output


if __name__ == "__main__":
    res = run_full_rank_sensitivity()
    print(json.dumps(res["aggregate_excluding_original"], indent=2))
