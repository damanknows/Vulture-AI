"""
Compute Actionable Precision@10 (AP@10) and Recall@10 (AR@10) for All Exploratory Methods
=======================================================================================

Actionable = grade >= 2 (Act or Attend; 27 items in the 41-CVE benchmark).
Denominator is 10 for AP@10 and 27 for AR@10.
Saves results to `experiments/revision/baselines/exploratory_actionable.json`.

Usage:
    python3 -m experiments.revision.baselines.compute_actionable_summary
"""

import json
from pathlib import Path
from typing import Dict

from experiments.metrics import THRESHOLD_ACTIONABLE, precision_at_k, recall_at_k
from experiments.run_baselines import load_benchmark


METRICS_JSON = Path("experiments/results/metrics.json")
CONTEXT_JSON = Path("experiments/revision/baselines/results_context.json")
SSVC_JSON = Path("experiments/revision/baselines/results_ssvc.json")
OUT_JSON = Path("experiments/revision/baselines/exploratory_actionable.json")


def compute_actionable_summary(out_path: Path = OUT_JSON) -> Dict[str, object]:
    _, _, relevance_dict = load_benchmark("data/benchmark/cves.csv")
    n_actionable = sum(1 for v in relevance_dict.values() if v >= THRESHOLD_ACTIONABLE)
    assert THRESHOLD_ACTIONABLE == 2
    assert n_actionable == 27

    with open(METRICS_JSON, "r", encoding="utf-8") as f:
        m41 = json.load(f)
    with open(CONTEXT_JSON, "r", encoding="utf-8") as f:
        ctx = json.load(f)
    with open(SSVC_JSON, "r", encoding="utf-8") as f:
        ssvc = json.load(f)

    epss_ctx_order = ctx["EPSS×Context"] if "EPSS×Context" in ctx else ctx.get("epss_x_context", [])
    if not epss_ctx_order:
        raise KeyError(f"EPSS×Context ranking not found in {CONTEXT_JSON}; keys={list(ctx.keys())}")

    rows = {
        "SSVC tree": {
            "AP@10": ssvc["metrics"]["precision@10_actionable"],
            "AR@10": ssvc["metrics"]["recall@10_actionable"],
        },
        "CVSS-only": {
            "AP@10": m41["CVSS-only"]["precision10_actionable"],
            "AR@10": m41["CVSS-only"]["recall10_actionable"],
        },
        "EPSS-only": {
            "AP@10": m41["EPSS-only"]["precision10_actionable"],
            "AR@10": m41["EPSS-only"]["recall10_actionable"],
        },
        "KEV-first": {
            "AP@10": m41["KEV-first"]["precision10_actionable"],
            "AR@10": m41["KEV-first"]["recall10_actionable"],
        },
        "CVSS+EPSS+KEV": {
            "AP@10": m41["CVSS+EPSS+KEV"]["precision10_actionable"],
            "AR@10": m41["CVSS+EPSS+KEV"]["recall10_actionable"],
        },
        "EPSS×Context": {
            "AP@10": precision_at_k(epss_ctx_order, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE),
            "AR@10": recall_at_k(epss_ctx_order, relevance_dict, k=10, threshold=THRESHOLD_ACTIONABLE),
        },
        "VRS (vrs-v1)": {
            "AP@10": m41["VRS Proposed"]["precision10_actionable"],
            "AR@10": m41["VRS Proposed"]["recall10_actionable"],
        },
    }

    all_identical = len({(v["AP@10"], v["AR@10"]) for v in rows.values()}) == 1
    out = {
        "threshold": THRESHOLD_ACTIONABLE,
        "precision_denominator": 10,
        "recall_denominator": n_actionable,
        "all_identical": all_identical,
        "methods": rows,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    return out


if __name__ == "__main__":
    rep = compute_actionable_summary()
    print(json.dumps(rep, indent=2))
