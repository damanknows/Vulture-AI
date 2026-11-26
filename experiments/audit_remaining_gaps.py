"""
Programmatic Audit of Remaining Reviewer Gaps and Manuscript Consistency
========================================================================

1. Verifies which unmeasured reviewer gaps have available inputs vs NOT_AVAILABLE.
2. Audits key metrics in `revision/ICCI2026_revision/manuscript_revised.tex` against
   their JSON artifacts under `experiments/revision/` and `experiments/results/`.

Usage:
    python3 -m experiments.audit_remaining_gaps
"""

import csv
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List


EXPL_CSV = Path("experiments/revision/guardrail/explanation_evaluation.csv")
CVES_41_CSV = Path("data/benchmark/cves.csv")
TEOB_EVAL_JSON = Path("experiments/revision/teob_evaluation.json")
METRICS_41_JSON = Path("experiments/results/metrics.json")
GUARDRAIL_JSON = Path("experiments/revision/guardrail/metrics.json")
INTEGRITY_JSON = Path("experiments/revision/guardrail/score_integrity.json")
SENSITIVITY_JSON = Path("experiments/revision/sensitivity/stability_summary.json")
MANUSCRIPT_TEX = Path("revision/ICCI2026_revision/manuscript_revised.tex")
OUT_JSON = Path("experiments/revision/remaining_gaps_audit.json")


def _check_explanation_eval(csv_path: Path = EXPL_CSV) -> Dict[str, object]:
    if not csv_path.exists():
        return {"status": "NOT_AVAILABLE", "reason": f"Missing {csv_path}"}
    with open(csv_path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return {
            "status": "NOT_AVAILABLE",
            "n_rows": 0,
            "reason": "explanation_evaluation.csv contains header only (0 human or judge ratings).",
        }
    return {"status": "AVAILABLE", "n_rows": len(rows)}


def _check_41cve_ssvc_cvss4(csv_path: Path = CVES_41_CSV) -> Dict[str, object]:
    if not csv_path.exists():
        return {"status": "NOT_AVAILABLE", "reason": f"Missing {csv_path}"}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        cols = set(reader.fieldnames or [])
    needed = {"cvss_v4", "automatable", "mission_prevalence"}
    missing = sorted(needed - cols)
    if missing:
        return {
            "status": "NOT_AVAILABLE",
            "reason": f"cves.csv lacks required SSVC/CVSS v4.0 columns: {missing}",
        }
    return {"status": "AVAILABLE"}


def _check_cpe_ground_truth(data_dir: Path = Path("data")) -> Dict[str, object]:
    candidates = list(data_dir.rglob("*nmap*ground_truth*")) + list(data_dir.rglob("*cpe*labelled*"))
    if not candidates:
        return {
            "status": "NOT_AVAILABLE",
            "reason": "No labelled Nmap-XML-to-CVE ground-truth corpus exists in data/.",
        }
    return {"status": "AVAILABLE", "files": [str(c) for c in candidates]}


def _check_ollama(url: str = "http://localhost:11434/api/tags") -> Dict[str, object]:
    try:
        with urllib.request.urlopen(url, timeout=1.0) as resp:
            return {"status": "AVAILABLE", "http_status": resp.status}
    except (urllib.error.URLError, TimeoutError, OSError):
        return {
            "status": "NOT_AVAILABLE",
            "reason": "No live Ollama server reachable at localhost:11434 in this environment.",
        }


def audit_manuscript_numbers(tex_path: Path = MANUSCRIPT_TEX) -> Dict[str, object]:
    tex = tex_path.read_text(encoding="utf-8")
    with open(TEOB_EVAL_JSON, "r", encoding="utf-8") as f:
        teob = json.load(f)
    with open(METRICS_41_JSON, "r", encoding="utf-8") as f:
        m41 = json.load(f)
    with open(GUARDRAIL_JSON, "r", encoding="utf-8") as f:
        guard = json.load(f)
    with open(INTEGRITY_JSON, "r", encoding="utf-8") as f:
        integ = json.load(f)

    checks: List[Dict[str, object]] = []

    def check_token(label: str, val_str: str):
        found = val_str in tex
        checks.append({"label": label, "expected": val_str, "present_in_tex": found})

    # TEOB metrics (all <= 1.0)
    for method, mets in teob["metrics"].items():
        for k in ("ndcg@10", "precision@10", "recall@10", "recall@50", "recall@100", "average_precision"):
            val = mets[k]
            assert 0.0 <= val <= 1.0, f"Metric out of [0,1]: {method}.{k}={val}"
            check_token(f"teob.{method}.{k}", f"{val:.4f}")

    # 41-CVE metrics (all <= 1.0)
    vrs41 = m41["VRS Proposed"]
    assert 0.0 <= vrs41["ndcg10"] <= 1.0
    assert 0.0 <= vrs41["spearman"] <= 1.0
    check_token("41cve.vrs.ndcg10", f"{vrs41['ndcg10']:.4f}")
    check_token("41cve.vrs.spearman", f"{vrs41['spearman']:.4f}")

    # Weight sensitivity stability summary
    if SENSITIVITY_JSON.exists():
        with open(SENSITIVITY_JSON, "r", encoding="utf-8") as f:
            sens = json.load(f)["aggregate"]
        assert 0.0 <= sens["spearman_rho_min"] <= sens["spearman_rho_max"] <= 1.0
        assert 0.0 <= sens["kendall_tau_min"] <= sens["kendall_tau_max"] <= 1.0
        check_token("sensitivity.rho_min", f"{sens['spearman_rho_min']:.4f}")
        check_token("sensitivity.rho_max", f"{sens['spearman_rho_max']:.4f}")
        check_token("sensitivity.tau_min", f"{sens['kendall_tau_min']:.4f}")
        check_token("sensitivity.tau_max", f"{sens['kendall_tau_max']:.4f}")

    # Guardrail & Integrity
    cm = guard["confusion_matrix"]
    check_token("guardrail.TP", str(cm["TP"]))
    check_token("guardrail.FN", str(cm["FN"]))
    check_token("guardrail.FP", str(cm["FP"]))
    check_token("guardrail.TN", str(cm["TN"]))
    check_token("integrity.passed", f"{integ['n_passed']} / {integ['n_cases']}")

    # SSVC baseline on 41-CVE benchmark
    ssvc_json = Path("experiments/revision/baselines/results_ssvc.json")
    if ssvc_json.exists():
        with open(ssvc_json, "r", encoding="utf-8") as f:
            ssvc = json.load(f)
        for k in ("ndcg@10", "precision@10_act", "recall@10_act", "spearman"):
            val = ssvc["metrics"][k]
            assert 0.0 <= val <= 1.0
            check_token(f"ssvc.{k}", f"{val:.4f}")

    all_ok = all(c["present_in_tex"] for c in checks)
    return {"all_checked_metrics_match": all_ok, "n_checks": len(checks), "checks": checks}


def run_audit(out_path: Path = OUT_JSON) -> Dict[str, object]:
    gaps = {
        "explanation_quality": _check_explanation_eval(),
        "ssvc_and_cvss4_on_41cve": _check_41cve_ssvc_cvss4(),
        "cpe_nmap_matching_accuracy": _check_cpe_ground_truth(),
        "live_llm_guardrail": _check_ollama(),
    }
    manuscript_audit = audit_manuscript_numbers()
    report = {
        "remaining_gaps": gaps,
        "manuscript_consistency_audit": manuscript_audit,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report


if __name__ == "__main__":
    rep = run_audit()
    print(json.dumps({"gaps": rep["remaining_gaps"], "all_match": rep["manuscript_consistency_audit"]["all_checked_metrics_match"]}, indent=2))
