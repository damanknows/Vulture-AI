"""
Independent Verification of CVSS-only vs KEV-first on Frozen TEOB
==================================================================

Recomputes CVSS-only and KEV-first point metrics, tie blocks (including
bottom missing-CVSS blocks), and paired stratified bootstrap differences
vs VRS directly from `data/benchmark/temporal/teob_2026-07-01_90d.csv`
using the frozen protocol (`n_boot=1000`, `seed=20261127`).

Outputs: `experiments/revision/verify_kevfirst.json`.

Usage:
    python3 -m experiments.revision.verify_kevfirst
"""

import json
from pathlib import Path

from experiments.evaluate_temporal import (
    TEOB_CSV,
    compute_all_metrics,
    compute_unrounded_scores,
    evaluate_teob,
    load_teob_records,
    summarize_ties,
    tie_blocks,
)


OUT_JSON = Path("experiments/revision/verify_kevfirst.json")


def verify_kevfirst(csv_path: Path = TEOB_CSV) -> dict:
    records, coverage = load_teob_records(csv_path)
    labels = [r["label"] for r in records]
    scores = compute_unrounded_scores(records)

    cvss_raw = compute_all_metrics(scores["CVSS-only"], labels)
    kev_raw = compute_all_metrics(scores["KEV-first"], labels)

    cvss_blocks = tie_blocks(scores["CVSS-only"], labels)
    kev_blocks = tie_blocks(scores["KEV-first"], labels)

    full_eval = evaluate_teob(
        csv_path=csv_path,
        n_boot=1000,
        seed=20261127,
        write_outputs=False,
    )

    result = {
        "dataset": str(csv_path),
        "n_eligible": len(records),
        "n_positives": sum(labels),
        "bootstrap_config": {"n_boot": 1000, "seed": 20261127},
        "unrounded_metrics": {
            "CVSS-only": cvss_raw,
            "KEV-first": kev_raw,
            "ap_abs_diff": abs(cvss_raw["average_precision"] - kev_raw["average_precision"]),
        },
        "rounded_4dp_metrics": {
            "CVSS-only": {k: round(v, 4) for k, v in cvss_raw.items()},
            "KEV-first": {k: round(v, 4) for k, v in kev_raw.items()},
        },
        "tie_blocks": {
            "CVSS-only": {
                "summary": summarize_ties(scores["CVSS-only"], labels),
                "top_block": {"size": cvss_blocks[0][0], "positives": cvss_blocks[0][1], "score": cvss_blocks[0][2]},
                "bottom_block": {"size": cvss_blocks[-1][0], "positives": cvss_blocks[-1][1], "score": str(cvss_blocks[-1][2])},
            },
            "KEV-first": {
                "summary": summarize_ties(scores["KEV-first"], labels),
                "top_block": {"size": kev_blocks[0][0], "positives": kev_blocks[0][1], "score": kev_blocks[0][2]},
                "bottom_block": {"size": kev_blocks[-1][0], "positives": kev_blocks[-1][1], "score": str(kev_blocks[-1][2])},
            },
        },
        "paired_bootstrap_vrs_minus_baseline": {
            "CVSS-only": full_eval["paired_stratified_bootstrap_vrs_minus_baseline"]["CVSS-only"],
            "KEV-first": full_eval["paired_stratified_bootstrap_vrs_minus_baseline"]["KEV-first"],
        },
    }
    OUT_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    res = verify_kevfirst()
    print(json.dumps(res, indent=2))
