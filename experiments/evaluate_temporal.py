"""
Temporal Exploitation Outcome Benchmark (TEOB) Evaluation Pipeline
==================================================================

Evaluates prioritization methods on `data/benchmark/temporal/teob_2026-07-01_90d.csv`
against future 90-day CISA KEV additions (`future_kev_within_horizon`).

Key methodological properties:
- Uses unrounded full-precision scores for ranking (rounding only for display).
- Uses exact analytical tie-aware expected metrics (NDCG@10, Precision@10,
  Recall@10/50/100, Average Precision) so arbitrary CVE ID tie-breaking never
  distorts performance.
- Uses paired stratified bootstrap (resampling positive and negative CVEs
  separately with identical indices across methods) with explicit seed.

Usage:
    python3 -m experiments.evaluate_temporal
"""

import csv
import json
import math
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from risk_engine import DEFAULT_WEIGHTS


TEOB_CSV = Path("data/benchmark/temporal/teob_2026-07-01_90d.csv")
TEOB_MANIFEST = Path("data/benchmark/temporal/teob_manifest.json")
OUT_JSON = Path("experiments/revision/teob_evaluation.json")
OUT_MD = Path("experiments/revision/teob_evaluation.md")

EVAL_METRICS = (
    "ndcg@10",
    "precision@10",
    "recall@10",
    "recall@50",
    "recall@100",
    "average_precision",
)


def _score_key(val: Optional[float]) -> float:
    return float(val) if val is not None else -float("inf")


def tie_blocks(scores: Sequence[Optional[float]], labels: Sequence[int]) -> List[Tuple[int, int, float]]:
    """
    Groups items by exact descending score into tied blocks.

    Returns:
        List of (block_size, block_positives, block_score) ordered from highest
        score to lowest score (missing scores `None` grouped at `-inf`).
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have identical lengths.")
    if not scores:
        return []

    paired = sorted(
        ((_score_key(s), int(lbl)) for s, lbl in zip(scores, labels)),
        key=lambda x: x[0],
        reverse=True,
    )
    blocks: List[Tuple[int, int, float]] = []
    cur_score = paired[0][0]
    n_b = 0
    p_b = 0
    for sc, lbl in paired:
        if sc == cur_score:
            n_b += 1
            p_b += lbl
        else:
            blocks.append((n_b, p_b, cur_score))
            cur_score = sc
            n_b = 1
            p_b = lbl
    blocks.append((n_b, p_b, cur_score))
    return blocks


def tie_aware_ndcg_at_k(scores: Sequence[Optional[float]], labels: Sequence[int], k: int = 10) -> float:
    """Exact expected binary NDCG@K under uniform random tie-breaking."""
    n = len(scores)
    if n == 0 or k <= 0:
        return 0.0
    total_pos = sum(int(x) for x in labels)
    if total_pos == 0:
        return 0.0

    cutoff = min(k, n)
    idcg = sum(1.0 / math.log2(i + 2) for i in range(min(cutoff, total_pos)))
    if idcg <= 0.0:
        return 0.0

    dcg = 0.0
    rank_idx = 0
    for n_b, p_b, _ in tie_blocks(scores, labels):
        if rank_idx >= cutoff:
            break
        take = min(n_b, cutoff - rank_idx)
        exp_rel = p_b / n_b
        for j in range(take):
            dcg += exp_rel / math.log2(rank_idx + j + 2)
        rank_idx += take
    return dcg / idcg


def tie_aware_precision_at_k(scores: Sequence[Optional[float]], labels: Sequence[int], k: int = 10) -> float:
    """
    Exact expected Precision@K under uniform random tie-breaking.
    When N < k, divides by min(k, N) = N.
    """
    n = len(scores)
    if n == 0 or k <= 0:
        return 0.0
    cutoff = min(k, n)
    exp_hits = 0.0
    rank_idx = 0
    for n_b, p_b, _ in tie_blocks(scores, labels):
        if rank_idx >= cutoff:
            break
        take = min(n_b, cutoff - rank_idx)
        exp_hits += take * (p_b / n_b)
        rank_idx += take
    return exp_hits / cutoff


def tie_aware_recall_at_k(scores: Sequence[Optional[float]], labels: Sequence[int], k: int = 10) -> float:
    """Exact expected Recall@K under uniform random tie-breaking."""
    n = len(scores)
    if n == 0 or k <= 0:
        return 0.0
    total_pos = sum(int(x) for x in labels)
    if total_pos == 0:
        return 0.0
    cutoff = min(k, n)
    exp_hits = 0.0
    rank_idx = 0
    for n_b, p_b, _ in tie_blocks(scores, labels):
        if rank_idx >= cutoff:
            break
        take = min(n_b, cutoff - rank_idx)
        exp_hits += take * (p_b / n_b)
        rank_idx += take
    return exp_hits / total_pos


def tie_aware_average_precision(scores: Sequence[Optional[float]], labels: Sequence[int]) -> float:
    """
    Exact analytical expected binary Average Precision over all uniform
    random permutations within tied score blocks.
    """
    n = len(scores)
    if n == 0:
        return 0.0
    total_pos = sum(int(x) for x in labels)
    if total_pos == 0:
        return 0.0

    ap_sum = 0.0
    p_before = 0
    s_before = 0
    for n_b, p_b, _ in tie_blocks(scores, labels):
        if p_b > 0:
            if n_b == 1:
                ap_sum += (1.0 + p_before) / (s_before + 1.0)
            else:
                block_sum = 0.0
                for r in range(1, n_b + 1):
                    exp_prec = (1.0 + p_before + (p_b - 1.0) * (r - 1.0) / (n_b - 1.0)) / (s_before + r)
                    block_sum += exp_prec
                ap_sum += (p_b / n_b) * block_sum
        p_before += p_b
        s_before += n_b
    return ap_sum / total_pos


def compute_all_metrics(scores: Sequence[Optional[float]], labels: Sequence[int]) -> Dict[str, float]:
    return {
        "ndcg@10": tie_aware_ndcg_at_k(scores, labels, k=10),
        "precision@10": tie_aware_precision_at_k(scores, labels, k=10),
        "recall@10": tie_aware_recall_at_k(scores, labels, k=10),
        "recall@50": tie_aware_recall_at_k(scores, labels, k=50),
        "recall@100": tie_aware_recall_at_k(scores, labels, k=100),
        "average_precision": tie_aware_average_precision(scores, labels),
    }


def load_teob_records(csv_path: Path = TEOB_CSV) -> Tuple[List[dict], Dict[str, object]]:
    records = []
    cvss_status_counts: Counter = Counter()
    cvss_missing = 0
    epss_missing = 0

    with open(csv_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cid = row["cve_id"].strip()
            cvss_val = float(row["cvss_as_of_cutoff"]) if row["cvss_as_of_cutoff"] else None
            epss_val = float(row["epss_as_of_cutoff"]) if row["epss_as_of_cutoff"] else None
            kev_val = int(row["kev_at_cutoff"])
            label = int(row["future_kev_within_horizon"])

            if cvss_val is None:
                cvss_missing += 1
            if epss_val is None:
                epss_missing += 1
            if "cvss_status_at_cutoff" in row:
                cvss_status_counts[row["cvss_status_at_cutoff"]] += 1

            records.append(
                {
                    "cve_id": cid,
                    "cvss": cvss_val,
                    "epss": epss_val,
                    "kev": kev_val == 1,
                    "label": label,
                }
            )

    coverage = {
        "cvss_available": len(records) - cvss_missing,
        "cvss_missing": cvss_missing,
        "epss_available": len(records) - epss_missing,
        "epss_missing": epss_missing,
        "cvss_status_counts": dict(cvss_status_counts),
    }
    return records, coverage


def compute_unrounded_scores(records: List[dict]) -> Dict[str, List[Optional[float]]]:
    """
    Computes unrounded full-precision scores for each method using frozen
    `DEFAULT_WEIGHTS` from `risk_engine.py` and documented missing-data policies.
    """
    w_c = DEFAULT_WEIGHTS["w_C"]
    w_e = DEFAULT_WEIGHTS["w_E"]
    w_k = DEFAULT_WEIGHTS["w_K"]
    w_n = DEFAULT_WEIGHTS["w_N"]
    w_a = DEFAULT_WEIGHTS["w_A"]

    scores: Dict[str, List[Optional[float]]] = {
        "CVSS-only": [],
        "EPSS-only": [],
        "KEV-first": [],
        "CVSS+EPSS+KEV": [],
        "VRS (default context=0.5)": [],
    }

    for r in records:
        cvss = r["cvss"]
        epss = r["epss"]
        kev = r["kev"]

        # 1. CVSS-only
        scores["CVSS-only"].append(100.0 * (cvss / 10.0) if cvss is not None else None)

        # 2. EPSS-only (unrounded)
        scores["EPSS-only"].append(100.0 * epss if epss is not None else None)

        # 3. KEV-first
        k_val = 100.0 if kev else 0.0
        c_val = cvss if cvss is not None else 0.0
        scores["KEV-first"].append(k_val + c_val)

        # 4. CVSS+EPSS+KEV
        if cvss is None:
            scores["CVSS+EPSS+KEV"].append(None)
        else:
            c_norm = cvss / 10.0
            e_norm = epss if epss is not None else 0.0
            k_norm = 1.0 if kev else 0.0
            scores["CVSS+EPSS+KEV"].append(100.0 * ((c_norm + e_norm + k_norm) / 3.0))

        # 5. VRS (default N=0.5, A=0.5, K=1 if kev else 0)
        if cvss is None:
            scores["VRS (default context=0.5)"].append(None)
        else:
            c_norm = cvss / 10.0
            e_norm = epss if epss is not None else 0.0
            k_norm = 1.0 if kev else 0.0
            bucket_offset = 1000.0 if (k_norm == 1.0 and w_k > 0) else 0.0
            vrs_raw = 100.0 * (w_c * c_norm + w_e * e_norm + w_k * k_norm + w_n * 0.5 + w_a * 0.5)
            scores["VRS (default context=0.5)"].append(bucket_offset + vrs_raw)

    return scores


def summarize_ties(scores: Sequence[Optional[float]], labels: Sequence[int]) -> Dict[str, int]:
    blocks = tie_blocks(scores, labels)
    if not blocks:
        return {"n_unique_blocks": 0, "largest_tie_block": 0, "top_block_size": 0}
    return {
        "n_unique_blocks": len(blocks),
        "largest_tie_block": max(b[0] for b in blocks),
        "top_block_size": blocks[0][0],
    }


def evaluate_teob(
    csv_path: Path = TEOB_CSV,
    n_boot: int = 1000,
    seed: int = 20261127,
    write_outputs: bool = True,
) -> dict:
    records, coverage = load_teob_records(csv_path)
    labels = [r["label"] for r in records]
    method_scores = compute_unrounded_scores(records)

    n_total = len(records)
    n_pos = sum(labels)
    n_neg = n_total - n_pos

    raw_metrics: Dict[str, Dict[str, float]] = {}
    rounded_metrics: Dict[str, Dict[str, float]] = {}
    tie_stats: Dict[str, Dict[str, int]] = {}

    for name, sc in method_scores.items():
        m = compute_all_metrics(sc, labels)
        raw_metrics[name] = m
        rounded_metrics[name] = {k: round(v, 4) for k, v in m.items()}
        tie_stats[name] = summarize_ties(sc, labels)

    # Paired stratified bootstrap (preserving n_pos and n_neg; identical indices across methods)
    rng = np.random.default_rng(seed)
    pos_idx = np.array([i for i, lbl in enumerate(labels) if lbl == 1], dtype=int)
    neg_idx = np.array([i for i, lbl in enumerate(labels) if lbl == 0], dtype=int)
    labels_arr = np.array(labels, dtype=int)
    score_arrays = {
        name: np.array([_score_key(x) for x in sc], dtype=float)
        for name, sc in method_scores.items()
    }

    vrs_name = "VRS (default context=0.5)"
    boot_diffs: Dict[str, Dict[str, List[float]]] = {
        name: {met: [] for met in EVAL_METRICS}
        for name in method_scores
        if name != vrs_name
    }

    n_valid_boot = 0
    if len(pos_idx) > 0 and len(neg_idx) > 0 and n_boot > 0:
        for _ in range(n_boot):
            samp_pos = rng.choice(pos_idx, size=len(pos_idx), replace=True)
            samp_neg = rng.choice(neg_idx, size=len(neg_idx), replace=True)
            samp = np.concatenate([samp_pos, samp_neg])
            samp_labels = labels_arr[samp].tolist()
            scores_b = {
                name: compute_all_metrics(arr[samp].tolist(), samp_labels)
                for name, arr in score_arrays.items()
            }
            for name in boot_diffs:
                for met in EVAL_METRICS:
                    boot_diffs[name][met].append(scores_b[vrs_name][met] - scores_b[name][met])
            n_valid_boot += 1

    paired_ci: Dict[str, Dict[str, dict]] = {}
    for name, mets in boot_diffs.items():
        paired_ci[name] = {}
        for met, vals in mets.items():
            obs_diff = raw_metrics[vrs_name][met] - raw_metrics[name][met]
            if vals:
                lo, hi = np.percentile(vals, [2.5, 97.5])
                lo_f, hi_f = float(lo), float(hi)
                lo_r, hi_r = round(lo_f, 4), round(hi_f, 4)
                sig = bool(lo_r > 0.0 or hi_r < 0.0)
                paired_ci[name][met] = {
                    "observed_diff": round(obs_diff, 4),
                    "ci_95": [lo_r, hi_r],
                    "n_valid": len(vals),
                    "significant_95": sig,
                }
            else:
                paired_ci[name][met] = {
                    "observed_diff": round(obs_diff, 4),
                    "ci_95": None,
                    "n_valid": 0,
                    "significant_95": False,
                }

    report = {
        "dataset": str(csv_path),
        "n_eligible": n_total,
        "n_positives_90d_kev": n_pos,
        "n_negatives": n_neg,
        "positive_rate": round(n_pos / n_total, 6) if n_total else 0.0,
        "feature_coverage": coverage,
        "tie_summary": tie_stats,
        "methodology_notes": {
            "ranking_precision": "Unrounded float64 scores used for sorting; display rounded to 4 decimals.",
            "tie_handling": "Exact analytical expected metrics over uniform random permutations within tied score blocks.",
            "bootstrap": (
                f"Paired stratified bootstrap (n_boot={n_boot}, n_valid={n_valid_boot}, seed={seed}); "
                "resamples positive and negative CVEs separately with replacement using identical indices across methods; "
                "95% percentile CIs."
            ),
            "context_note": "No independent historical context; EPSS x Context omitted; VRS uses N=0.5, A=0.5 defaults.",
        },
        "metrics": rounded_metrics,
        "paired_stratified_bootstrap_vrs_minus_baseline": paired_ci,
    }

    if write_outputs:
        OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
        with open(OUT_JSON, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        lines = [
            "# TEOB Evaluation Results (`2026-07-01`, 90-day horizon)",
            "",
            f"- **Eligible CVEs:** {n_total}",
            f"- **Observed KEV additions (90d):** {n_pos} ({report['positive_rate']*100:.3f}%)",
            f"- **Negatives (not observed in KEV within horizon):** {n_neg}",
            f"- **CVSS available at cutoff:** {coverage['cvss_available']} (missing: {coverage['cvss_missing']})",
            f"- **EPSS available at cutoff:** {coverage['epss_available']} (missing: {coverage['epss_missing']})",
            f"- **Ranking & ties:** Unrounded float64 scores; exact analytical tie-aware expected metrics.",
            f"- **Bootstrap:** Paired stratified bootstrap (`n_boot={n_boot}`, `n_valid={n_valid_boot}`, `seed={seed}`), 95% percentile CIs.",
            f"- **Context handling:** {report['methodology_notes']['context_note']}",
            "",
            "## Tie-Aware Ranking Metrics",
            "",
            "| Method | NDCG@10 | P@10 | R@10 | R@50 | R@100 | Avg Precision | Top Tie Block |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for name, m in rounded_metrics.items():
            lines.append(
                f"| {name} | {m['ndcg@10']:.4f} | {m['precision@10']:.4f} | {m['recall@10']:.4f} | "
                f"{m['recall@50']:.4f} | {m['recall@100']:.4f} | {m['average_precision']:.4f} | "
                f"{tie_stats[name]['top_block_size']} |"
            )

        lines.extend(
            [
                "",
                "## Paired Stratified Bootstrap (VRS minus Baseline, 95% Percentile CI)",
                "",
                "| Baseline | Metric | Obs Diff | 95% CI | Sig (95%) |",
                "| --- | --- | ---: | --- | --- |",
            ]
        )
        for name, mets in paired_ci.items():
            for met in EVAL_METRICS:
                info = mets[met]
                ci_str = f"[{info['ci_95'][0]:.4f}, {info['ci_95'][1]:.4f}]" if info["ci_95"] else "N/A"
                lines.append(
                    f"| {name} | {met} | {info['observed_diff']:+.4f} | {ci_str} | {info['significant_95']} |"
                )

        with open(OUT_MD, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    return report


if __name__ == "__main__":
    rep = evaluate_teob()
    print(json.dumps(rep["metrics"], indent=2))
