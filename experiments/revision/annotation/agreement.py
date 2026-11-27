"""
Inter-Rater Agreement Calculator (Pairwise Cohen's Kappa & Fleiss' Kappa)
=========================================================================

Computes:
- Pairwise unweighted and quadratic-weighted Cohen's kappa
- Percent agreement and 4x4 confusion matrix (grades 0..3)
- Fleiss' kappa when >= 3 rater files are provided

Usage:
    python3 -m experiments.revision.annotation.agreement rater1.csv rater2.csv [--out out.json]
"""

import argparse
import csv
import json
from itertools import combinations
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np


GRADES = (0, 1, 2, 3)


def load_rater_file(path: Path) -> Dict[str, int]:
    ratings: Dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cid = row["cve_id"].strip()
            g = int(row["grade"])
            if g not in GRADES:
                raise ValueError(f"Invalid grade {g} for {cid} in {path}")
            ratings[cid] = g
    return ratings


def cohens_kappa(y1: Sequence[int], y2: Sequence[int], weighted: bool = False) -> float:
    n = len(y1)
    if n == 0 or len(y2) != n:
        return 0.0
    k = len(GRADES)
    conf = np.zeros((k, k), dtype=float)
    for a, b in zip(y1, y2):
        conf[a, b] += 1.0
    hist1 = conf.sum(axis=1)
    hist2 = conf.sum(axis=0)
    expected = np.outer(hist1, hist2) / float(n)
    if weighted:
        w = np.array([[((i - j) ** 2) / ((k - 1) ** 2) for j in range(k)] for i in range(k)], dtype=float)
        denom = float(np.sum(w * expected))
        if denom == 0.0:
            return 1.0 if list(y1) == list(y2) else 0.0
        return round(1.0 - float(np.sum(w * conf)) / denom, 4)
    po = float(np.trace(conf)) / float(n)
    pe = float(np.trace(expected)) / float(n)
    if pe >= 1.0:
        return 1.0 if po == 1.0 else 0.0
    return round((po - pe) / (1.0 - pe), 4)


def fleiss_kappa(matrix: np.ndarray) -> float:
    """Computes Fleiss' kappa for N subjects x k categories count matrix."""
    n_subj, _ = matrix.shape
    if n_subj == 0:
        return 0.0
    n_raters = float(matrix[0].sum())
    if n_raters <= 1:
        return 0.0
    p_j = matrix.sum(axis=0) / (n_subj * n_raters)
    p_e = float(np.sum(p_j ** 2))
    p_i = (np.sum(matrix ** 2, axis=1) - n_raters) / (n_raters * (n_raters - 1.0))
    p_bar = float(np.mean(p_i))
    if p_e >= 1.0:
        return 1.0 if p_bar == 1.0 else 0.0
    return round((p_bar - p_e) / (1.0 - p_e), 4)


def compute_agreement(
    rater_paths: List[Path],
    out_path: Optional[Path] = None,
    is_synthetic_dry_run: bool = False,
) -> Dict[str, object]:
    if len(rater_paths) < 2:
        raise ValueError("At least 2 rater files are required.")

    rater_maps = {p.stem: load_rater_file(p) for p in rater_paths}
    common_ids = sorted(set.intersection(*(set(m.keys()) for m in rater_maps.values())))
    if not common_ids:
        raise ValueError("No overlapping CVE IDs across rater files.")

    pairwise = {}
    for r1, r2 in combinations(rater_maps.keys(), 2):
        y1 = [rater_maps[r1][c] for c in common_ids]
        y2 = [rater_maps[r2][c] for c in common_ids]
        pct = round(sum(1 for a, b in zip(y1, y2) if a == b) / len(common_ids), 4)
        cm = [[0] * len(GRADES) for _ in GRADES]
        for a, b in zip(y1, y2):
            cm[a][b] += 1
        pairwise[f"{r1}_vs_{r2}"] = {
            "n_items": len(common_ids),
            "percent_agreement": pct,
            "cohens_kappa": cohens_kappa(y1, y2, weighted=False),
            "weighted_kappa": cohens_kappa(y1, y2, weighted=True),
            "confusion_matrix_0_to_3": cm,
        }

    fleiss = None
    if len(rater_maps) >= 3:
        mat = np.zeros((len(common_ids), len(GRADES)), dtype=float)
        for idx, cid in enumerate(common_ids):
            for m in rater_maps.values():
                mat[idx, m[cid]] += 1.0
        fleiss = fleiss_kappa(mat)

    result = {
        "n_raters": len(rater_maps),
        "n_common_items": len(common_ids),
        "is_synthetic_dry_run": is_synthetic_dry_run,
        "real_rater_data": "PENDING" if is_synthetic_dry_run else "AVAILABLE",
        "pairwise": pairwise,
        "fleiss_kappa": fleiss,
    }
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("raters", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--synthetic-dry-run", action="store_true")
    args = parser.parse_args()
    rep = compute_agreement(args.raters, out_path=args.out, is_synthetic_dry_run=args.synthetic_dry_run)
    print(json.dumps(rep, indent=2))
