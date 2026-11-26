"""
Vulture-AI Phase 3: Statistical Validation and Bootstrap Analysis
=================================================================

Uncertainty analysis and paired comparison of VRS against the baselines.
This module does NOT change ranking models, benchmark labels, or the original
results. It reads ``data/benchmark/cves.csv`` and writes only to
``experiments/revision/statistics/``.

Resampling strategy (documented in report.md)
---------------------------------------------
* Unit of resampling: benchmark record (one CVE row), n = 41.
* ``plain``: n indices drawn uniformly with replacement from the 41 records
  (nonparametric record bootstrap).
* ``stratified``: records are resampled with replacement *within* each
  reference grade (Act/Attend/Track/Defer). This fixes the number of relevant
  items per stratum, which otherwise fluctuates and drives the recall
  denominators. It is a sensitivity analysis, not a replacement for ``plain``.
* Paired design: for each iteration the SAME index vector is applied to every
  ranking. A ranking of the sample is obtained by restricting the full ranking
  to the drawn items, preserving its order. Duplicate draws of one CVE are
  distinct items (``record#j``) and are ordered adjacently by draw index, so
  the ranking is a deterministic permutation of the sample.

Metric definitions (identical to ``experiments/metrics.py`` at K=10, unrounded)
-------------------------------------------------------------------------------
* NDCG@10: sum_{i<=10} (2^g_i - 1)/log2(i+1) / IDCG@10, where IDCG uses all
  sample grades sorted descending. Undefined (NaN) if the sample has no g>0.
* Precision@10 (tau): hits in top 10 with g >= tau, divided by K=10 (fixed).
* Recall@10 (tau): hits in top 10 with g >= tau, divided by the number of
  sample items with g >= tau. NaN if that number is 0.
  - tau=3 is "Act" (Act-only relevance).
  - tau=2 is "Actionable" (Act or Attend).
* Spearman rho between predicted and reference order of sample items
  (both are permutations, so there are no ties; closed form
  1 - 6*sum(d^2)/(n(n^2-1))). NaN for n < 2.
* Kendall tau-a (permutation pairs, no ties): used only for ranking
  similarity, not for ground-truth performance.

Ranking similarity (VRS vs baseline) and performance against the reference are
reported in separate columns (``comparison_type``) and must not be conflated.
"""

from __future__ import annotations

import csv
import gzip
import json
import math
import os
import re
import sys
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import scipy.stats

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk_engine import rank_findings  # noqa: E402
from context_baselines import (  # noqa: E402
    compute_baseline_epss_exposure,
    compute_baseline_exposure_criticality,
    compute_baseline_context_enhanced_cvss,
    compute_baseline_epss_context,
)
from experiments.run_baselines import load_benchmark  # noqa: E402  (pure loader; no writes)

BENCHMARK_PATH = "data/benchmark/cves.csv"
EXPECTED_SHA256 = "27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e"
PHASE2_ORIGINAL = "experiments/revision/baselines/results_original.json"
PHASE2_CONTEXT = "experiments/revision/baselines/results_context.json"
OUT_DIR = "experiments/revision/statistics"

K = 10
TAU_ACT = 3
TAU_ACTIONABLE = 2
VALID_GRADES = {"Act": 3, "Attend": 2, "Track": 1, "Defer": 0}
SYNTHETIC_IDS = ("CVE-2024-99991", "CVE-2024-99992")

DEFAULT_ITERATIONS = 2000
MAX_ITERATIONS = 5000
MIN_ITERATIONS = 1
DEFAULT_SEED = 20261126
STRATEGIES = ("plain", "stratified")
TOPK_LEVELS = (5, 10, 15)

VRS = "VRS Proposed"
ORIGINAL_MODELS = ["CVSS-only", "EPSS-only", "KEV-first", "CVSS+EPSS+KEV", "VRS Proposed"]
CONTEXT_MODELS = ["EPSS×Exposure", "Exposure×Criticality", "Context-Enhanced CVSS", "EPSS×Context"]

METRICS = [
    "ndcg@10",
    "precision@10_act",
    "recall@10_act",
    "precision@10_actionable",
    "recall@10_actionable",
    "spearman",
]
CEILING_VALUE = {m: 1.0 for m in METRICS}  # best achievable value for each metric

CI_LEVEL = 0.95
SPLIT_HALF_DRIFT_WARN = 0.05
SMALL_N_WARN = 100


# ---------------------------------------------------------------------------
# Input loading and ranking reconstruction
# ---------------------------------------------------------------------------

def sha256_of(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_labels(path: str = BENCHMARK_PATH) -> Tuple[List[str], Dict[str, int], Dict[str, bool], Dict[str, Optional[int]]]:
    """
    Read record IDs, reference grades, synthetic flags, and reference priorities.

    Raises ValueError for missing or invalid independent_label (no silent fallback).
    """
    cves: List[str] = []
    grades: Dict[str, int] = {}
    synthetic: Dict[str, bool] = {}
    ref_priority: Dict[str, Optional[int]] = {}
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cid = row["cve_id"].strip()
            label = (row.get("independent_label") or "").strip()
            if label not in VALID_GRADES:
                raise ValueError(f"Missing or invalid independent_label for {cid!r}: {label!r}")
            if cid in grades:
                raise ValueError(f"Duplicate cve_id in benchmark: {cid}")
            cves.append(cid)
            grades[cid] = VALID_GRADES[label]
            is_syn = cid in SYNTHETIC_IDS or "SYNTHETIC" in (row.get("description") or "")
            synthetic[cid] = is_syn
            rp = (row.get("reference_priority") or "").strip()
            ref_priority[cid] = int(rp) if rp else None
    if not cves:
        raise ValueError("Benchmark is empty")
    return cves, grades, synthetic, ref_priority


def _rank_by_score(findings: Sequence[dict], score_fn) -> List[str]:
    """Descending score, None last, ascending CVE ID tie-break (same as run_baselines)."""
    items = []
    for f in findings:
        cid = f["cve_matches"][0]["cve_id"]
        s = score_fn(f)
        items.append((s is None, -(s if s is not None else 0.0), cid))
    items.sort()
    return [cid for _, _, cid in items]


def build_rankings(findings: Sequence[dict]) -> Dict[str, List[str]]:
    """
    Rebuild all nine rankings from the benchmark inputs.

    Tie-breaks replicate experiments/run_baselines.py (scores descending, ascending CVE ID).
    VRS uses risk_engine.rank_findings (bucket order, then VRS, then CVE ID).
    """
    from risk_engine import compute_kev_first, compute_cvss_epss_kev, compute_cvss_only, compute_epss_only

    rankings = {
        "CVSS-only": _rank_by_score(findings, compute_cvss_only),
        "EPSS-only": _rank_by_score(findings, compute_epss_only),
        "KEV-first": _rank_by_score(findings, compute_kev_first),
        "CVSS+EPSS+KEV": _rank_by_score(findings, compute_cvss_epss_kev),
        "VRS Proposed": [r["primary_cve"] for r in rank_findings(list(findings))],
    }
    rankings["EPSS×Exposure"] = _rank_by_score(findings, compute_baseline_epss_exposure)
    rankings["Exposure×Criticality"] = _rank_by_score(findings, compute_baseline_exposure_criticality)
    rankings["Context-Enhanced CVSS"] = _rank_by_score(findings, compute_baseline_context_enhanced_cvss)
    rankings["EPSS×Context"] = _rank_by_score(findings, compute_baseline_epss_context)
    return rankings


def verify_against_phase2(rankings: Dict[str, List[str]],
                          original_path: str = PHASE2_ORIGINAL,
                          context_path: str = PHASE2_CONTEXT) -> Dict[str, bool]:
    """Assert rebuilt rankings equal the saved Phase 2 rankings. Raises on mismatch."""
    with open(original_path, "r", encoding="utf-8") as f:
        orig = json.load(f)
    with open(context_path, "r", encoding="utf-8") as f:
        ctx = json.load(f)
    saved = {**orig, **ctx}
    report = {}
    for name in ORIGINAL_MODELS + CONTEXT_MODELS:
        ok = list(saved[name]) == list(rankings[name])
        report[name] = ok
        if not ok:
            raise ValueError(f"Rebuilt ranking for {name!r} does not match Phase 2 output")
    return report


# ---------------------------------------------------------------------------
# Resampling
# ---------------------------------------------------------------------------

def make_indices(n: int, n_iter: int, seed: int, strategy: str, grades: Optional[np.ndarray] = None) -> np.ndarray:
    """
    Return an (n_iter, n) int array of record indices. Deterministic for a fixed seed.

    ``plain``: uniform with replacement over all n records.
    ``stratified``: within each grade stratum, resampled with replacement at the
    stratum's original size; strata are concatenated in grade order so every row
    has length n.
    """
    if n <= 0:
        raise ValueError("Cannot resample an empty dataset")
    if not (MIN_ITERATIONS <= n_iter <= MAX_ITERATIONS):
        raise ValueError(f"n_iter must be in [{MIN_ITERATIONS}, {MAX_ITERATIONS}], got {n_iter}")
    if strategy not in STRATEGIES:
        raise ValueError(f"Unknown strategy {strategy!r}")
    rng = np.random.default_rng(seed)
    if strategy == "plain":
        return rng.integers(0, n, size=(n_iter, n))
    if grades is None or len(grades) != n:
        raise ValueError("stratified resampling requires one grade per record")
    cols = []
    for g in sorted(set(int(x) for x in grades)):
        members = np.flatnonzero(grades == g)
        cols.append(members[rng.integers(0, len(members), size=(n_iter, len(members)))])
    return np.concatenate(cols, axis=1)


# ---------------------------------------------------------------------------
# Metrics on a resampled sample
# ---------------------------------------------------------------------------

class _Ranking:
    """Holds a model's rank position per record and its name."""

    def __init__(self, name: str, ranking: Sequence[str], cve_index: Dict[str, int]):
        if len(ranking) == 0 or len(cve_index) == 0:
            raise ValueError(f"Ranking {name!r} is empty; cannot evaluate an empty dataset")
        if len(set(ranking)) != len(ranking):
            raise ValueError(f"Duplicate identifiers in ranking {name!r}")
        if set(ranking) != set(cve_index):
            raise ValueError(f"Ranking {name!r} population differs from benchmark")
        self.name = name
        self.pos = np.empty(len(ranking), dtype=np.int64)
        for p, cid in enumerate(ranking):
            self.pos[cve_index[cid]] = p


def _sample_view(idx: np.ndarray, pred: _Ranking, ref_pos: np.ndarray, grades: np.ndarray):
    """
    For one sample (array of record indices, length n), return the predicted
    order of draws, their grades in that order, and the predicted/reference
    ranks of each draw (0-based).
    """
    n = len(idx)
    draw_id = np.arange(n)
    pred_order = np.lexsort((draw_id, pred.pos[idx]))  # predicted order of draws
    pred_rank = np.empty(n, dtype=np.int64)
    pred_rank[pred_order] = np.arange(n)
    ref_order = np.lexsort((draw_id, ref_pos[idx]))
    ref_rank = np.empty(n, dtype=np.int64)
    ref_rank[ref_order] = np.arange(n)
    g_sorted = grades[idx][pred_order]
    return pred_order, pred_rank, ref_rank, g_sorted


def _ndcg_at_k(g_sorted: np.ndarray, all_grades: np.ndarray, k: int = K) -> float:
    top = g_sorted[:k]
    dcg = float(np.sum((2.0 ** top - 1.0) / np.log2(np.arange(2, len(top) + 2))))
    ideal = np.sort(all_grades)[::-1][:k]
    idcg = float(np.sum((2.0 ** ideal - 1.0) / np.log2(np.arange(2, len(ideal) + 2))))
    if idcg <= 0.0:
        return float("nan")
    return dcg / idcg


def _precision_at_k(g_sorted: np.ndarray, tau: int, k: int = K) -> float:
    return float(np.sum(g_sorted[:k] >= tau)) / k


def _recall_at_k(g_sorted: np.ndarray, all_grades: np.ndarray, tau: int, k: int = K) -> float:
    n_rel = int(np.sum(all_grades >= tau))
    if n_rel == 0:
        return float("nan")
    return float(np.sum(g_sorted[:k] >= tau)) / n_rel


def _spearman(pred_rank: np.ndarray, ref_rank: np.ndarray) -> float:
    n = len(pred_rank)
    if n < 2:
        return float("nan")
    d = (pred_rank - ref_rank).astype(float)
    return 1.0 - 6.0 * float(np.sum(d * d)) / (n * (n * n - 1.0))


def metrics_for_sample(idx: np.ndarray, pred: _Ranking, ref_pos: np.ndarray, grades: np.ndarray) -> Dict[str, float]:
    """All six metrics for one model on one sample (unrounded, NaN if undefined)."""
    _, pred_rank, ref_rank, g_sorted = _sample_view(idx, pred, ref_pos, grades)
    all_g = grades[idx]
    return {
        "ndcg@10": _ndcg_at_k(g_sorted, all_g),
        "precision@10_act": _precision_at_k(g_sorted, TAU_ACT),
        "recall@10_act": _recall_at_k(g_sorted, all_g, TAU_ACT),
        "precision@10_actionable": _precision_at_k(g_sorted, TAU_ACTIONABLE),
        "recall@10_actionable": _recall_at_k(g_sorted, all_g, TAU_ACTIONABLE),
        "spearman": _spearman(pred_rank, ref_rank),
    }


def ranking_similarity(idx: np.ndarray, a: _Ranking, b: _Ranking, ref_pos: np.ndarray, grades: np.ndarray) -> Dict[str, float]:
    """Similarity of two rankings on the same sample (not performance vs ground truth)."""
    n = len(idx)
    _, ra, _, _ = _sample_view(idx, a, ref_pos, grades)
    _, rb, _, _ = _sample_view(idx, b, ref_pos, grades)
    out: Dict[str, float] = {}
    if n >= 2:
        d = (ra - rb).astype(float)
        out["spearman_vs_model"] = 1.0 - 6.0 * float(np.sum(d * d)) / (n * (n * n - 1.0))
        tau = scipy.stats.kendalltau(ra, rb).statistic
        out["kendall_tau_vs_model"] = float(tau) if not np.isnan(tau) else float("nan")
    else:
        out["spearman_vs_model"] = float("nan")
        out["kendall_tau_vs_model"] = float("nan")
    oa = np.lexsort((np.arange(n), a.pos[idx]))
    ob = np.lexsort((np.arange(n), b.pos[idx]))
    for k in TOPK_LEVELS:
        kk = min(k, n)
        inter = len(set(oa[:kk].tolist()) & set(ob[:kk].tolist()))
        out[f"top{k}_overlap"] = inter / k
    return out


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def _pct_ci(values: np.ndarray, level: float = CI_LEVEL) -> Tuple[float, float]:
    vals = values[~np.isnan(values)]
    if vals.size == 0:
        return float("nan"), float("nan")
    lo = (1.0 - level) / 2.0 * 100.0
    hi = 100.0 - lo
    return float(np.percentile(vals, lo)), float(np.percentile(vals, hi))


def summarize(values: np.ndarray, observed: float, ceiling: Optional[float]) -> Dict[str, object]:
    """Bootstrap summary for one metric over B iterations."""
    B = len(values)
    valid = values[~np.isnan(values)]
    n_valid = int(valid.size)
    mean = float(np.mean(valid)) if n_valid else float("nan")
    sd = float(np.std(valid, ddof=1)) if n_valid > 1 else float("nan")
    lo, hi = _pct_ci(values)
    half = B // 2
    lo1, hi1 = _pct_ci(values[:half]) if half else (float("nan"), float("nan"))
    lo2, hi2 = _pct_ci(values[half:]) if half else (float("nan"), float("nan"))
    drift = max(abs(lo1 - lo2), abs(hi1 - hi2)) if half and not any(math.isnan(x) for x in (lo1, hi1, lo2, hi2)) else float("nan")
    ceiling_frac = float(np.mean(np.isclose(valid, ceiling))) if (ceiling is not None and n_valid) else float("nan")
    degenerate = bool(n_valid == 0 or (n_valid > 1 and np.isclose(sd, 0.0)))
    return {
        "observed": observed,
        "bootstrap_mean": mean,
        "bootstrap_sd": sd,
        "ci_low": lo,
        "ci_high": hi,
        "n_iterations": B,
        "n_valid": n_valid,
        "fraction_valid": n_valid / B if B else float("nan"),
        "fraction_at_ceiling": ceiling_frac,
        "degenerate": degenerate,
        "split_half_ci_drift": drift,
    }


def interpret_difference(observed: float, lo: float, hi: float, degenerate: bool, n_valid: int, n_iter: int) -> str:
    if degenerate or n_valid == 0:
        return ("Degenerate: the paired difference has no variation across bootstrap samples "
                "(or is undefined). No difference can be resolved on this benchmark.")
    if lo > 0 or hi < 0:
        sign = "VRS higher" if lo > 0 else "baseline higher"
        return (f"Descriptive only: the 95% percentile bootstrap interval excludes 0 ({sign}). "
                "This is not a hypothesis test and no p-value is reported. Reference labels are author-curated "
                "and records are not independent.")
    return ("The 95% percentile bootstrap interval includes 0. The data do not resolve a difference "
            "in this direction at n=41.")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_analysis(
    benchmark_path: str = BENCHMARK_PATH,
    n_iter: int = DEFAULT_ITERATIONS,
    seed: int = DEFAULT_SEED,
    out_dir: str = OUT_DIR,
    verify_phase2: bool = True,
    write: bool = True,
) -> Dict[str, object]:
    if not (MIN_ITERATIONS <= n_iter <= MAX_ITERATIONS):
        raise ValueError(f"iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}")

    sha = sha256_of(benchmark_path)
    if sha != EXPECTED_SHA256:
        raise ValueError(f"Benchmark hash mismatch: expected {EXPECTED_SHA256}, got {sha}")

    cves, grade_map, synthetic, ref_priority = load_labels(benchmark_path)
    findings, ref_ranking, relevance = load_benchmark(benchmark_path)
    if {c: v for c, v in relevance.items()} != grade_map:
        raise ValueError("Relevance mapping in run_baselines.load_benchmark disagrees with independent_label column")

    n = len(cves)
    cve_index = {c: i for i, c in enumerate(cves)}
    grades = np.array([grade_map[c] for c in cves], dtype=np.int64)
    if set(ref_ranking) != set(cves):
        raise ValueError("Reference ranking population differs from benchmark")
    ref_pos = np.empty(n, dtype=np.int64)
    for p, cid in enumerate(ref_ranking):
        ref_pos[cve_index[cid]] = p

    rankings = build_rankings(findings)
    verified = verify_against_phase2(rankings) if verify_phase2 else {}
    models = {name: _Ranking(name, rankings[name], cve_index) for name in ORIGINAL_MODELS + CONTEXT_MODELS}
    vrs = models[VRS]
    baselines = [m for m in ORIGINAL_MODELS + CONTEXT_MODELS if m != VRS]

    identity = np.arange(n)
    observed = {name: metrics_for_sample(identity, m, ref_pos, grades) for name, m in models.items()}

    summary_rows = []
    paired_rows = []
    stability_rows = []
    iteration_rows = []  # (strategy, iteration, kind, model_or_pair, metric, value)
    strategy_meta = {}

    for strategy in STRATEGIES:
        idx_mat = make_indices(n, n_iter, seed, strategy, grades)
        strategy_meta[strategy] = {"seed": seed, "iterations": n_iter, "resampled_units": n}

        per_model = {name: {m: np.full(n_iter, np.nan) for m in METRICS} for name in models}
        per_stab = {b: {k: np.full(n_iter, np.nan) for k in ("spearman_vs_model", "kendall_tau_vs_model", "top5_overlap", "top10_overlap", "top15_overlap")} for b in baselines}
        for b_i in range(n_iter):
            idx = idx_mat[b_i]
            for name, m in models.items():
                vals = metrics_for_sample(idx, m, ref_pos, grades)
                for metric in METRICS:
                    per_model[name][metric][b_i] = vals[metric]
            for b in baselines:
                sim = ranking_similarity(idx, vrs, models[b], ref_pos, grades)
                for key in per_stab[b]:
                    per_stab[b][key][b_i] = sim[key]

        # Bootstrap summary per model and metric
        for name in models:
            for metric in METRICS:
                ceil = CEILING_VALUE[metric]
                s = summarize(per_model[name][metric], observed[name][metric], ceil)
                summary_rows.append({"strategy": strategy, "model": name, "metric": metric, **s})
                if write:
                    for b_i, v in enumerate(per_model[name][metric]):
                        iteration_rows.append((strategy, b_i, "metric", name, metric, v))

        # Paired differences (VRS - baseline) on identical samples
        for b in baselines:
            for metric in METRICS:
                diff = per_model[VRS][metric] - per_model[b][metric]
                obs_diff = observed[VRS][metric] - observed[b][metric]
                if np.isnan(obs_diff):
                    obs_diff = float("nan")
                s = summarize(diff, obs_diff, None)
                excludes0 = bool((not s["degenerate"]) and s["n_valid"] > 0 and (s["ci_low"] > 0 or s["ci_high"] < 0))
                paired_rows.append({
                    "strategy": strategy,
                    "baseline": b,
                    "vrs": VRS,
                    "metric": metric,
                    "baseline_observed": observed[b][metric],
                    "vrs_observed": observed[VRS][metric],
                    "observed_difference": obs_diff,
                    "bootstrap_mean_difference": s["bootstrap_mean"],
                    "bootstrap_sd_difference": s["bootstrap_sd"],
                    "ci_low": s["ci_low"],
                    "ci_high": s["ci_high"],
                    "n_iterations": n_iter,
                    "n_valid": s["n_valid"],
                    "interval_excludes_zero": excludes0,
                    "degenerate": s["degenerate"],
                    "split_half_ci_drift": s["split_half_ci_drift"],
                    "interpretation": interpret_difference(obs_diff, s["ci_low"], s["ci_high"], s["degenerate"], s["n_valid"], n_iter),
                })
                if write:
                    for b_i, v in enumerate(diff):
                        iteration_rows.append((strategy, b_i, "paired_difference", f"VRS minus {b}", metric, v))

        # Ranking stability (similarity between rankings; not ground truth)
        for b in baselines:
            sim_obs = ranking_similarity(identity, vrs, models[b], ref_pos, grades)
            for key in ("spearman_vs_model", "kendall_tau_vs_model", "top5_overlap", "top10_overlap", "top15_overlap"):
                s = summarize(per_stab[b][key], sim_obs[key], CEILING_VALUE.get("spearman") if key == "spearman_vs_model" else None)
                stability_rows.append({
                    "strategy": strategy,
                    "comparison_type": "ranking_similarity",
                    "model_a": VRS,
                    "model_b": b,
                    "statistic": key,
                    "observed": sim_obs[key],
                    "bootstrap_mean": s["bootstrap_mean"],
                    "bootstrap_sd": s["bootstrap_sd"],
                    "ci_low": s["ci_low"],
                    "ci_high": s["ci_high"],
                    "n_iterations": n_iter,
                    "n_valid": s["n_valid"],
                })
        # Ground-truth agreement, kept separate from ranking similarity
        for name in models:
            s_obs = observed[name]["spearman"]
            s = summarize(per_model[name]["spearman"], s_obs, 1.0)
            stability_rows.append({
                "strategy": strategy,
                "comparison_type": "performance_vs_reference_labels",
                "model_a": name,
                "model_b": "reference_priority",
                "statistic": "spearman",
                "observed": s_obs,
                "bootstrap_mean": s["bootstrap_mean"],
                "bootstrap_sd": s["bootstrap_sd"],
                "ci_low": s["ci_low"],
                "ci_high": s["ci_high"],
                "n_iterations": n_iter,
                "n_valid": s["n_valid"],
            })
        # keep stability iteration distributions for the "sensitivity to resampling" statement
        strategy_meta[strategy]["stability_draws"] = {b: {k: float(np.nanstd(v)) for k, v in per_stab[b].items()} for b in baselines}

    # Actionable metric verification on the observed data
    actionable_check = _verify_actionable(models, cves, grades, observed)

    warnings = build_warnings(cves, grades, synthetic, n_iter, summary_rows, paired_rows, observed, rankings)

    report = {
        "phase": "Phase 3: statistical validation and bootstrap analysis",
        "benchmark": {
            "file": benchmark_path,
            "sha256": sha,
            "n_records": n,
            "n_synthetic": int(sum(1 for c in cves if synthetic[c])),
            "synthetic_ids": [c for c in cves if synthetic[c]],
            "grade_counts": {lbl: int(np.sum(grades == g)) for lbl, g in VALID_GRADES.items()},
            "reference_labels": "author-curated SSVC-inspired rubric (not independent ground truth)",
        },
        "configuration": {
            "iterations": n_iter,
            "max_iterations": MAX_ITERATIONS,
            "seed": seed,
            "strategies": list(STRATEGIES),
            "ci_method": "percentile bootstrap, 95%, linear interpolation (numpy default)",
            "k": K,
            "thresholds": {"act": TAU_ACT, "actionable": TAU_ACTIONABLE},
            "topk_levels": list(TOPK_LEVELS),
            "numpy": np.__version__,
            "scipy": scipy.__version__,
        },
        "phase2_rankings_reproduced": verified,
        "observed_metrics": observed,
        "actionable_verification": actionable_check,
        "tests_considered": {
            "paired_t_test": "not used: metric differences are not normal or independent; a single ranking per model yields one observation",
            "wilcoxon_or_sign_test_on_records": "not used: NDCG/Recall/Spearman are not per-record additive; no per-query distribution exists",
            "bootstrap_percentile_interval": "used, descriptive only",
            "p_values": "not reported: no valid null distribution exists for this design",
        },
        "warnings": warnings,
        "limitations": LIMITATIONS,
        "strategy_meta": strategy_meta,
    }

    if write:
        _write_outputs(out_dir, report, summary_rows, paired_rows, stability_rows, iteration_rows)
    return report


def _verify_actionable(models, cves, grades, observed) -> Dict[str, object]:
    """Confirm the Actionable P@10/R@10 definitions against metrics.py."""
    from experiments.metrics import precision_at_k, recall_at_k, THRESHOLD_ACTIONABLE

    rel = {c: int(grades[i]) for i, c in enumerate(cves)}
    checks = {}
    for name, m in models.items():
        ranking = [c for c, _ in sorted(((cves[i], int(m.pos[i])) for i in range(len(cves))), key=lambda x: x[1])]
        p_ref = precision_at_k(ranking, rel, k=K, threshold=THRESHOLD_ACTIONABLE)
        r_ref = recall_at_k(ranking, rel, k=K, threshold=THRESHOLD_ACTIONABLE)
        checks[name] = {
            "precision_metrics_py": p_ref,
            "recall_metrics_py": r_ref,
            "precision_matches": abs(round(observed[name]["precision@10_actionable"], 4) - p_ref) < 1e-9,
            "recall_matches": abs(round(observed[name]["recall@10_actionable"], 4) - r_ref) < 1e-9,
        }
    n_actionable = int(np.sum(grades >= TAU_ACTIONABLE))
    return {
        "definition_precision": "|{i in top-10 : grade_i >= 2}| / 10. Denominator fixed at K=10.",
        "definition_recall": "|{i in top-10 : grade_i >= 2}| / |{r in benchmark : grade_r >= 2}|. Denominator is the count of Act+Attend records.",
        "relevant_population_size": n_actionable,
        "ties": "Scores are tied-broken by ascending CVE ID (ranking is a strict permutation). Bootstrap draws tie-break by draw index.",
        "per_model": checks,
        "all_match_metrics_py": all(v["precision_matches"] and v["recall_matches"] for v in checks.values()),
        "discriminative": len({round(observed[n]["precision@10_actionable"], 6) for n in observed}) > 1,
    }


LIMITATIONS = [
    "Sample size: n=41 records; 2 of them (CVE-2024-99991/99992) are synthetic, so 39 are real CVEs.",
    "Reference labels are author-curated SSVC-inspired judgments, not independent ground truth.",
    "Circularity: reference labels use KEV, EPSS, exposure and criticality, which are the same inputs VRS uses. Agreement with the reference is construct consistency, not predictive validity.",
    "Non-independence: records share vendors and products (e.g. several Microsoft, Apache and Linux entries), so i.i.d. record resampling understates clustering.",
    "Discreteness: with n=41 each record shifts the metrics by discrete steps. Recall denominators are fixed small integers (15 Act, 27 Actionable).",
    "Ceiling: VRS attains NDCG@10=1.0 and P@10(Act)=1.0 on the observed data, so the bootstrap distribution is truncated at 1.0 and CI endpoints are biased low.",
    "Duplicates: with-replacement resampling of n=41 leaves about 63% of distinct records in each sample (1-(1-1/n)^n) and ~37% of draws are duplicates. Duplicate draws are counted as separate items, so a record drawn twice can occupy two top-10 slots and inflate hit counts and the weight of that record.",
    "Percentile CI: no bias correction (BCa) is applied. Coverage at n=41 with ceiling and discrete metrics is not guaranteed.",
    "Bootstrap quantifies sampling variability of the benchmark composition only. It does not represent the population of real-world vulnerabilities.",
    "No significance tests are reported. Each model has one ranking over one benchmark, so there is no independent observation set for a classical test. Bootstrap intervals are descriptive.",
    "Multiplicity: 8 baseline comparisons x 6 metrics x 2 strategies are reported with no adjustment; interval exclusion is not a confirmed effect.",
    "Actionable P@10 and R@10 are non-discriminative on this benchmark (see actionable_verification).",
]


def build_warnings(cves, grades, synthetic, n_iter, summary_rows, paired_rows, observed, rankings) -> List[str]:
    w: List[str] = []
    n = len(cves)
    if n < SMALL_N_WARN:
        w.append(f"SMALL SAMPLE: n={n} < {SMALL_N_WARN}. Bootstrap intervals are unstable at this size.")
    n_syn = sum(1 for c in cves if synthetic[c])
    if n_syn:
        w.append(f"SYNTHETIC RECORDS: {n_syn} of {n} records are synthetic edge cases (no real CVE). They are included as in the original benchmark.")
    if observed[VRS]["ndcg@10"] >= 1.0 - 1e-12:
        w.append("CEILING: VRS NDCG@10 is 1.0 on the observed data. The bootstrap distribution is truncated at 1.0.")
    if observed[VRS]["precision@10_act"] >= 1.0 - 1e-12:
        w.append("CEILING: VRS P@10(Act) is 1.0 on the observed data.")
    for r in summary_rows:
        if r["degenerate"]:
            w.append(f"DEGENERATE: {r['strategy']}/{r['model']}/{r['metric']} has zero bootstrap variance or no valid iterations.")
        elif r["fraction_at_ceiling"] == r["fraction_at_ceiling"] and r["fraction_at_ceiling"] >= 0.5:
            w.append(f"CEILING: {r['strategy']}/{r['model']}/{r['metric']} is at its maximum in {r['fraction_at_ceiling']:.1%} of iterations.")
        if r["n_valid"] < 0.95 * r["n_iterations"]:
            w.append(f"UNSTABLE: {r['strategy']}/{r['model']}/{r['metric']} has only {r['n_valid']}/{r['n_iterations']} valid iterations.")
        if r["split_half_ci_drift"] == r["split_half_ci_drift"] and r["split_half_ci_drift"] > SPLIT_HALF_DRIFT_WARN:
            w.append(f"UNSTABLE INTERVAL: {r['strategy']}/{r['model']}/{r['metric']} split-half CI drift {r['split_half_ci_drift']:.3f} > {SPLIT_HALF_DRIFT_WARN}.")
    for p in paired_rows:
        if p["degenerate"]:
            w.append(f"DEGENERATE COMPARISON: {p['strategy']} VRS vs {p['baseline']} on {p['metric']}: no variation in paired difference.")
    if n_iter < DEFAULT_ITERATIONS:
        w.append(f"ITERATIONS: {n_iter} < {DEFAULT_ITERATIONS}; Monte Carlo error of the CI endpoints is larger.")
    w.append("AUTHOR-CURATED LABELS: reference grades come from the authors' SSVC-inspired rubric, not independent ground truth.")
    w.append("NON-INDEPENDENT LABELS: reference labels use the same features as VRS (KEV, EPSS, exposure, criticality).")
    w.append("NO SIGNIFICANCE CLAIMS: intervals are descriptive. No p-values are reported.")
    return w


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _fmt(v):
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.6f}"
    if isinstance(v, (np.floating,)):
        return _fmt(float(v))
    return v


def _write_outputs(out_dir, report, summary_rows, paired_rows, stability_rows, iteration_rows):
    os.makedirs(out_dir, exist_ok=True)

    def write_csv(name, rows, fields):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow({k: _fmt(r.get(k)) for k in fields})

    write_csv("bootstrap_results.csv", summary_rows, [
        "strategy", "model", "metric", "observed", "bootstrap_mean", "bootstrap_sd",
        "ci_low", "ci_high", "n_iterations", "n_valid", "fraction_valid",
        "fraction_at_ceiling", "degenerate", "split_half_ci_drift",
    ])
    write_csv("paired_comparisons.csv", paired_rows, [
        "strategy", "baseline", "vrs", "metric", "baseline_observed", "vrs_observed",
        "observed_difference", "bootstrap_mean_difference", "bootstrap_sd_difference",
        "ci_low", "ci_high", "n_iterations", "n_valid", "interval_excludes_zero",
        "degenerate", "split_half_ci_drift", "interpretation",
    ])
    write_csv("ranking_stability.csv", stability_rows, [
        "strategy", "comparison_type", "model_a", "model_b", "statistic", "observed",
        "bootstrap_mean", "bootstrap_sd", "ci_low", "ci_high", "n_iterations", "n_valid",
    ])
    with gzip.open(os.path.join(out_dir, "bootstrap_iterations.csv.gz"), "wt", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["strategy", "iteration", "kind", "model_or_pair", "metric", "value"])
        for strategy, it, kind, name, metric, v in iteration_rows:
            w.writerow([strategy, it, kind, name, metric, _fmt(float(v)) if not np.isnan(v) else ""])

    with open(os.path.join(out_dir, "statistical_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=lambda o: float(o) if isinstance(o, np.floating) else str(o))

    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write(render_markdown(report, summary_rows, paired_rows, stability_rows))


def _md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        lines.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(lines)


def _f(v, d=4):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    return f"{v:.{d}f}"


def render_markdown(report, summary_rows, paired_rows, stability_rows) -> str:
    cfg = report["configuration"]
    bm = report["benchmark"]
    out = []
    out.append("# Phase 3: Statistical Validation and Bootstrap Analysis\n")
    out.append("Generated by `experiments/revision_statistics.py`. Do not edit by hand.\n")
    out.append("## Setup\n")
    out.append(f"- Benchmark: `{bm['file']}` (SHA-256 `{bm['sha256'][:16]}...`), n={bm['n_records']} ({bm['n_synthetic']} synthetic)")
    out.append(f"- Reference labels: {bm['reference_labels']}")
    out.append(f"- Iterations: {cfg['iterations']} (max {cfg['max_iterations']}), seed {cfg['seed']}, strategies: {', '.join(cfg['strategies'])}")
    out.append(f"- CI: {cfg['ci_method']}")
    out.append(f"- numpy {cfg['numpy']}, scipy {cfg['scipy']}\n")

    out.append("## Resampling strategy\n")
    out.append("Records (n=41) are resampled with replacement. `plain` draws uniformly. `stratified` resamples within each reference grade (sensitivity). Every model in an iteration uses the same indices (paired). Duplicate draws are distinct items.\n")

    out.append("## Observed metrics and bootstrap summary (plain)\n")
    rows = []
    for r in summary_rows:
        if r["strategy"] != "plain":
            continue
        rows.append([r["model"], r["metric"], _f(r["observed"]), _f(r["bootstrap_mean"]), _f(r["bootstrap_sd"]),
                     f"[{_f(r['ci_low'])}, {_f(r['ci_high'])}]", _f(r["fraction_at_ceiling"], 3), r["n_valid"]])
    out.append(_md_table(["Model", "Metric", "Observed", "Boot mean", "Boot SD", "95% CI", "Frac. at ceiling", "Valid"], rows) + "\n")

    out.append("## Paired comparisons: VRS minus baseline (plain)\n")
    rows = []
    for p in paired_rows:
        if p["strategy"] != "plain":
            continue
        rows.append([p["baseline"], p["metric"], _f(p["baseline_observed"]), _f(p["vrs_observed"]),
                     _f(p["observed_difference"]), f"[{_f(p['ci_low'])}, {_f(p['ci_high'])}]",
                     p["n_iterations"], "yes" if p["interval_excludes_zero"] else "no"])
    out.append(_md_table(["Baseline", "Metric", "Baseline", "VRS", "Diff", "95% paired CI", "B", "Excl. 0"], rows) + "\n")
    out.append("Interpretation is descriptive. No p-values are reported. See `paired_comparisons.csv` for per-row text.\n")

    out.append("## Ranking stability\n")
    rows = []
    for s in stability_rows:
        if s["strategy"] != "plain":
            continue
        rows.append([s["comparison_type"], s["model_a"], s["model_b"], s["statistic"], _f(s["observed"]),
                     f"[{_f(s['ci_low'])}, {_f(s['ci_high'])}]"])
    out.append(_md_table(["Type", "A", "B", "Statistic", "Observed", "Bootstrap 95% CI"], rows) + "\n")
    out.append("`ranking_similarity` measures agreement between two rankings. `performance_vs_reference_labels` measures agreement with author-curated labels. They are not interchangeable.\n")

    out.append("## Actionable Precision@10 / Recall@10\n")
    av = report["actionable_verification"]
    out.append(f"- Precision: {av['definition_precision']}")
    out.append(f"- Recall: {av['definition_recall']}")
    out.append(f"- Relevant population (grade >= 2): {av['relevant_population_size']}")
    out.append(f"- Ties: {av['ties']}")
    out.append(f"- Matches `metrics.py` for every model: {av['all_match_metrics_py']}")
    out.append(f"- Discriminative on observed data: {av['discriminative']}. All models score the same P@10 and R@10 (see Observed table), so these metrics do not separate methods here.\n")

    out.append("## Warnings\n")
    for x in report["warnings"]:
        out.append(f"- {x}")
    out.append("")
    out.append("## Limitations\n")
    for x in report["limitations"]:
        out.append(f"- {x}")
    out.append("")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Phase 3 bootstrap and paired statistics")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--out", default=OUT_DIR)
    args = p.parse_args(argv)
    report = run_analysis(n_iter=args.iterations, seed=args.seed, out_dir=args.out)
    print(f"Wrote statistics to {args.out}")
    print(f"Iterations: {args.iterations}, seed: {args.seed}, n={report['benchmark']['n_records']}")
    print(f"Warnings: {len(report['warnings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
