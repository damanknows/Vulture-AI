"""
CVSS v3.1 Environmental/Threat Proxy Baseline (41-CVE Exploratory Benchmark)
============================================================================

CVSS v4.0 vectors are unavailable in `data/benchmark/cves.csv` (which stores
only scalar CVSS v3.x base scores). This module implements a clearly labeled
CVSS v3.1 environmental/threat proxy (`v3.1 environmental proxy`) using:
- Temporal/Threat multiplier from KEV / EPSS:
  KEV=1 -> 1.00 (High/Functional), EPSS>=0.1 -> 0.97, else 0.94
- Environmental criticality multiplier from asset criticality A:
  A>=0.66 -> 1.15 (High CR/IR/AR), A>=0.33 -> 1.00 (Medium), else 0.85 (Low)
- Exposure modifier from network exposure N: (0.75 + 0.25 * N)
Score = min(10.0, cvss_base * threat_mult * crit_mult * exp_mult).

This is a scalar proxy, NOT equivalent to full CVSS v4.0 equations.

Usage:
    python3 -m experiments.revision.baselines.cvss_env_baseline
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from experiments import revision_statistics as stats
from experiments.metrics import (
    THRESHOLD_ACT,
    THRESHOLD_ACTIONABLE,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    spearman_correlation,
)
from experiments.run_baselines import load_benchmark
from risk_engine import rank_findings


BENCHMARK_CSV = Path("data/benchmark/cves.csv")
OUT_JSON = Path("experiments/revision/baselines/results_cvss_env.json")


def compute_cvss_v31_env_proxy(finding: dict) -> Optional[float]:
    match = finding["cve_matches"][0]
    base = finding["finding"]
    cvss = match.get("cvss_score")
    if cvss is None:
        return None
    epss = match.get("epss_probability")
    kev = bool(match.get("kev_listed"))
    n_val = float(base["network_exposure"]) if base.get("network_exposure") is not None else 0.5
    a_val = float(base["asset_criticality"]) if base.get("asset_criticality") is not None else 0.5

    if kev:
        threat_mult = 1.00
    elif epss is not None and float(epss) >= 0.1:
        threat_mult = 0.97
    else:
        threat_mult = 0.94

    if a_val >= 0.66:
        crit_mult = 1.15
    elif a_val >= 0.33:
        crit_mult = 1.00
    else:
        crit_mult = 0.85

    exp_mult = 0.75 + 0.25 * n_val
    return round(min(10.0, float(cvss) * threat_mult * crit_mult * exp_mult), 4)


def run_cvss_env_baseline(
    benchmark_path: Path = BENCHMARK_CSV,
    out_path: Path = OUT_JSON,
) -> Dict[str, object]:
    findings, ref_ranking, relevance_dict = load_benchmark(str(benchmark_path))
    scored: List[Tuple[str, Optional[float]]] = []
    for f in findings:
        cid = f["cve_matches"][0]["cve_id"]
        scored.append((cid, compute_cvss_v31_env_proxy(f)))

    scored.sort(key=lambda x: (-x[1] if x[1] is not None else float("inf"), x[0]))
    ranking = [x[0] for x in scored]

    metrics = {
        "ndcg@10": ndcg_at_k(ranking, relevance_dict, k=10),
        "precision@10_act": precision_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACT),
        "recall@10_act": recall_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACT),
        "AP@10": precision_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE),
        "AR@10": recall_at_k(ranking, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE),
        "spearman": spearman_correlation(ranking, ref_ranking),
    }

    ids, checked_labels, _, _ = stats.load_labels(str(benchmark_path))
    index = {cid: i for i, cid in enumerate(ids)}
    grades = np.array([checked_labels[cid] for cid in ids])
    ref_pos = stats._Ranking("reference", ref_ranking, index).pos
    vrs_ranking = [r["primary_cve"] for r in rank_findings(findings)]
    vrs_model = stats._Ranking("VRS Proposed", vrs_ranking, index)
    env_model = stats._Ranking("CVSS v3.1 env proxy", ranking, index)

    draws = stats.make_indices(len(ids), stats.DEFAULT_ITERATIONS, stats.DEFAULT_SEED, "plain", grades)
    samples = np.vstack([np.arange(len(ids)), draws])
    vrs_vals = np.array([[m[k] for k in stats.METRICS] for m in (stats.metrics_for_sample(i, vrs_model, ref_pos, grades) for i in samples)])
    env_vals = np.array([[m[k] for k in stats.METRICS] for m in (stats.metrics_for_sample(i, env_model, ref_pos, grades) for i in samples)])

    paired_ci = {}
    for j, met in enumerate(stats.METRICS):
        diff = vrs_vals[:, j] - env_vals[:, j]
        valid = diff[1:][np.isfinite(diff[1:])]
        lo, hi = np.percentile(valid, [2.5, 97.5])
        lo_r, hi_r = round(float(lo), 4), round(float(hi), 4)
        paired_ci[met] = {
            "observed_diff": round(float(diff[0]), 4),
            "ci_95": [lo_r, hi_r],
            "significant_95": bool(lo_r > 0.0 or hi_r < 0.0),
        }

    output = {
        "baseline_label": "CVSS v3.1 environmental proxy",
        "cvss_v4_vectors_available": False,
        "caveat": "CVSS v4.0 vectors are absent from data/benchmark/cves.csv; this is a scalar CVSS v3.1 environmental/threat proxy and is NOT equivalent to CVSS v4.0.",
        "benchmark": str(benchmark_path),
        "n_records": len(findings),
        "metrics": metrics,
        "paired_bootstrap_vrs_minus_proxy": paired_ci,
        "ranking": ranking,
        "per_record_scores": {cid: sc for cid, sc in scored},
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    return output


if __name__ == "__main__":
    rep = run_cvss_env_baseline()
    print(json.dumps({"metrics": rep["metrics"], "caveat": rep["caveat"]}, indent=2))
