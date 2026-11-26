"""
SSVC Decision-Tree Baseline (Vendored, Cited) on Exploratory 41-CVE Benchmark
=============================================================================

Vendored, cited implementation of the CISA / SEI SSVC v2.0 decision tree:
  - J. M. Spring et al., "Prioritizing Vulnerability Response: A Stakeholder-Specific
    Vulnerability Categorization (SSVC)," CMU/SEI-2019-TR-005, 2019.
  - CISA, "Stakeholder-Specific Vulnerability Categorization (SSVC)," v2.0.

Evaluates the 41-CVE exploratory benchmark (`data/benchmark/cves.csv`), computes
ranking metrics and paired bootstrap CIs vs VRS, and tests sensitivity across
all 2x2 combinations of the two default assumptions (Automatable, Public Well-being).

Usage:
    python3 -m experiments.revision.baselines.ssvc_baseline
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
OUT_JSON = Path("experiments/revision/baselines/results_ssvc.json")

EPSS_POC_THRESHOLD = 0.1
CVSS_TOTAL_THRESHOLD = 9.0
DEFAULT_AUTOMATABLE = "yes"
DEFAULT_PUBLIC_WELLBEING = "minimal"

SSVC_TIER_SCORE = {
    "Act": 3,
    "Attend": 2,
    "Track*": 1,
    "Track": 1,
}


def mission_wellbeing_impact(mission_prevalence: str, public_wellbeing: str) -> str:
    """Combines Mission Prevalence and Public Well-being into {low, medium, high}."""
    if mission_prevalence == "essential" or public_wellbeing == "irreversible":
        return "high"
    if mission_prevalence == "support" or public_wellbeing == "material":
        return "medium"
    return "low"


def evaluate_ssvc_tree(
    exploitation: str,
    automatable: str,
    technical_impact: str,
    mission_prevalence: str,
    public_wellbeing: str,
) -> str:
    """
    Vendored, cited CISA/SEI SSVC v2.0 4-tier decision function.
    Returns one of: "Track", "Track*", "Attend", "Act".
    """
    mw = mission_wellbeing_impact(mission_prevalence, public_wellbeing)

    if exploitation == "active":
        if automatable == "yes" and technical_impact == "total":
            return "Act" if mw in ("medium", "high") else "Attend"
        if automatable == "yes" and technical_impact == "partial":
            return "Act" if mw == "high" else "Attend"
        if automatable == "no" and technical_impact == "total":
            return "Act" if mw == "high" else "Attend"
        # automatable == "no" and technical_impact == "partial"
        if mw == "high":
            return "Attend"
        return "Track*" if mw == "medium" else "Track"

    if exploitation == "poc":
        if automatable == "yes" and technical_impact == "total":
            if mw == "high":
                return "Act"
            return "Attend" if mw == "medium" else "Track*"
        if automatable == "yes" and technical_impact == "partial":
            if mw == "high":
                return "Attend"
            return "Track*" if mw == "medium" else "Track"
        if automatable == "no" and technical_impact == "total":
            if mw == "high":
                return "Attend"
            return "Track*" if mw == "medium" else "Track"
        # automatable == "no" and technical_impact == "partial"
        return "Track*" if mw == "high" else "Track"

    # exploitation == "none"
    if automatable == "yes" and technical_impact == "total":
        if mw == "high":
            return "Attend"
        return "Track*" if mw == "medium" else "Track"
    if (automatable == "yes" and technical_impact == "partial") or (
        automatable == "no" and technical_impact == "total"
    ):
        return "Track*" if mw == "high" else "Track"
    return "Track"


def map_finding_to_ssvc_inputs(
    finding: dict,
    automatable_default: str = DEFAULT_AUTOMATABLE,
    public_wellbeing_default: str = DEFAULT_PUBLIC_WELLBEING,
    epss_poc_threshold: float = EPSS_POC_THRESHOLD,
) -> Dict[str, str]:
    match = finding["cve_matches"][0]
    base = finding["finding"]

    kev = bool(match.get("kev_listed"))
    epss = match.get("epss_probability")
    cvss = match.get("cvss_score")
    crit = base.get("asset_criticality")
    a_val = float(crit) if crit is not None else 0.5

    if kev:
        exploitation = "active"
    elif epss is not None and float(epss) >= epss_poc_threshold:
        exploitation = "poc"
    else:
        exploitation = "none"

    technical_impact = "total" if (cvss is not None and float(cvss) >= CVSS_TOTAL_THRESHOLD) else "partial"

    if a_val >= 0.66:
        mission_prevalence = "essential"
    elif a_val >= 0.33:
        mission_prevalence = "support"
    else:
        mission_prevalence = "negligible"

    return {
        "exploitation": exploitation,
        "automatable": automatable_default,
        "technical_impact": technical_impact,
        "mission_prevalence": mission_prevalence,
        "public_wellbeing": public_wellbeing_default,
    }


def rank_ssvc(
    findings: List[dict],
    automatable_default: str = DEFAULT_AUTOMATABLE,
    public_wellbeing_default: str = DEFAULT_PUBLIC_WELLBEING,
) -> Tuple[List[str], Dict[str, dict]]:
    scored = []
    per_record: Dict[str, dict] = {}
    for f in findings:
        cid = f["cve_matches"][0]["cve_id"]
        inputs = map_finding_to_ssvc_inputs(f, automatable_default, public_wellbeing_default)
        outcome = evaluate_ssvc_tree(**inputs)
        tier_score = SSVC_TIER_SCORE[outcome]
        scored.append((cid, tier_score, outcome, inputs))

    scored.sort(key=lambda x: (-x[1], x[0]))
    ranking = [x[0] for x in scored]
    for rank_idx, (cid, tier_score, outcome, inputs) in enumerate(scored, start=1):
        per_record[cid] = {
            "rank": rank_idx,
            "ssvc_outcome": outcome,
            "ssvc_tier_score": tier_score,
            "inputs": inputs,
        }
    return ranking, per_record


def run_ssvc_baseline(
    benchmark_path: Path = BENCHMARK_CSV,
    out_path: Path = OUT_JSON,
) -> Dict[str, object]:
    findings, ref_ranking, relevance_dict = load_benchmark(str(benchmark_path))
    ssvc_ranking, per_record = rank_ssvc(findings, DEFAULT_AUTOMATABLE, DEFAULT_PUBLIC_WELLBEING)

    metrics = {
        "ndcg@10": ndcg_at_k(ssvc_ranking, relevance_dict, k=10),
        "precision@10_act": precision_at_k(ssvc_ranking, relevance_dict, k=10, threshold=THRESHOLD_ACT),
        "recall@10_act": recall_at_k(ssvc_ranking, relevance_dict, k=10, threshold=THRESHOLD_ACT),
        "precision@10_actionable": precision_at_k(ssvc_ranking, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE),
        "recall@10_actionable": recall_at_k(ssvc_ranking, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE),
        "spearman": spearman_correlation(ssvc_ranking, ref_ranking),
    }

    # Paired bootstrap VRS minus SSVC (same B=2000, seed=20261126, plain strategy as Table II)
    ids, checked_labels, _, _ = stats.load_labels(str(benchmark_path))
    index = {cid: i for i, cid in enumerate(ids)}
    grades = np.array([checked_labels[cid] for cid in ids])
    ref_pos = stats._Ranking("reference", ref_ranking, index).pos
    vrs_ranking = [r["primary_cve"] for r in rank_findings(findings)]
    vrs_model = stats._Ranking("VRS Proposed", vrs_ranking, index)
    ssvc_model = stats._Ranking("SSVC tree", ssvc_ranking, index)

    draws = stats.make_indices(len(ids), stats.DEFAULT_ITERATIONS, stats.DEFAULT_SEED, "plain", grades)
    samples = np.vstack([np.arange(len(ids)), draws])
    vrs_vals = np.array([[m[k] for k in stats.METRICS] for m in (stats.metrics_for_sample(i, vrs_model, ref_pos, grades) for i in samples)])
    ssvc_vals = np.array([[m[k] for k in stats.METRICS] for m in (stats.metrics_for_sample(i, ssvc_model, ref_pos, grades) for i in samples)])

    paired_ci = {}
    for j, met in enumerate(stats.METRICS):
        diff = vrs_vals[:, j] - ssvc_vals[:, j]
        valid = diff[1:][np.isfinite(diff[1:])]
        lo, hi = np.percentile(valid, [2.5, 97.5])
        lo_r, hi_r = round(float(lo), 4), round(float(hi), 4)
        paired_ci[met] = {
            "vrs_observed": round(float(vrs_vals[0, j]), 4),
            "ssvc_observed": round(float(ssvc_vals[0, j]), 4),
            "observed_diff": round(float(diff[0]), 4),
            "ci_95": [lo_r, hi_r],
            "significant_95": bool(lo_r > 0.0 or hi_r < 0.0),
        }

    # 2x2 assumption sensitivity (Automatable x Public Well-being)
    sensitivity = {}
    rhos = []
    for auto in ("yes", "no"):
        for pw in ("minimal", "material"):
            r_order, _ = rank_ssvc(findings, auto, pw)
            rho = spearman_correlation(r_order, ref_ranking)
            ndcg = ndcg_at_k(r_order, relevance_dict, k=10)
            key = f"automatable={auto}|public_wellbeing={pw}"
            sensitivity[key] = {"spearman": rho, "ndcg@10": ndcg}
            rhos.append(rho)

    output = {
        "implementation_provenance": "vendored, cited (CISA/SEI SSVC v2.0; Spring et al. CMU/SEI-2019-TR-005)",
        "benchmark": str(benchmark_path),
        "n_records": len(findings),
        "config": {
            "epss_poc_threshold": EPSS_POC_THRESHOLD,
            "cvss_total_threshold": CVSS_TOTAL_THRESHOLD,
            "automatable_default": DEFAULT_AUTOMATABLE,
            "automatable_assumption": "Default 'yes' (no per-record automatable field in cves.csv).",
            "public_wellbeing_default": DEFAULT_PUBLIC_WELLBEING,
            "public_wellbeing_assumption": "Default 'minimal' (no public well-being field in cves.csv).",
            "tier_mapping": SSVC_TIER_SCORE,
        },
        "metrics": metrics,
        "paired_bootstrap_vrs_minus_ssvc": paired_ci,
        "assumption_sensitivity_2x2": {
            "combinations": sensitivity,
            "spearman_min": min(rhos),
            "spearman_max": max(rhos),
        },
        "ranking": ssvc_ranking,
        "per_record": per_record,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    return output


if __name__ == "__main__":
    res = run_ssvc_baseline()
    print(json.dumps({"metrics": res["metrics"], "sensitivity": res["assumption_sensitivity_2x2"]}, indent=2))
