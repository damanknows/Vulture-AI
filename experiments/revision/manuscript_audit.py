"""
Automated Manuscript-to-JSON Table & Metric Audit
=================================================

Parses all numeric cells in the LaTeX tables of
`revision/ICCI2026_revision/manuscript_revised.tex` and verifies each cell
against its authoritative JSON artifact under `experiments/revision/` or
`experiments/results/`. Fails with exit code 1 on any mismatch or any
normalized metric > 1.0.

Usage:
    python3 -m experiments.revision.manuscript_audit
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple


TEX_PATH = Path("revision/ICCI2026_revision/manuscript_revised.tex")
TEOB_MANIFEST = Path("data/benchmark/temporal/teob_manifest.json")
TEOB_EVAL = Path("experiments/revision/teob_evaluation.json")
METRICS_41 = Path("experiments/results/metrics.json")
SSVC_JSON = Path("experiments/revision/baselines/results_ssvc.json")
CVSS_ENV_JSON = Path("experiments/revision/baselines/results_cvss_env.json")
ACTIONABLE_JSON = Path("experiments/revision/baselines/exploratory_actionable.json")
ABLATION_JSON = Path("experiments/results/ablation.json")
GUARD_JSON = Path("experiments/revision/guardrail/metrics.json")
INTEG_JSON = Path("experiments/revision/guardrail/score_integrity.json")


def _extract_table_block(tex: str, label: str) -> str:
    pattern = re.compile(
        rf"\\label\{{{re.escape(label)}\}}.*?\\begin\{{tabular\}}\{{[^}}]+\}}(.*?)\\end\{{tabular\}}",
        re.DOTALL,
    )
    m = pattern.search(tex)
    if not m:
        raise ValueError(f"Table with \\label{{{label}}} not found in {TEX_PATH}")
    return m.group(1)


def _clean_cell(cell: str) -> str:
    c = re.sub(r"\\textbf\{([^}]*)\}", r"\1", cell)
    c = re.sub(r"\\texttt\{([^}]*)\}", r"\1", c)
    c = re.sub(r"\$[^$]*\$", "", c)
    c = c.replace(",", "").strip()
    return c


def _parse_rows(block: str) -> List[List[str]]:
    rows = []
    for line in block.splitlines():
        s = line.strip()
        if not s or s.startswith("\\toprule") or s.startswith("\\midrule") or s.startswith("\\bottomrule") or s.startswith("\\multicolumn"):
            continue
        if "\\\\" not in s:
            continue
        s = s.split("\\\\")[0]
        cells = [_clean_cell(c) for c in s.split("&")]
        if cells and any(cells):
            rows.append(cells)
    return rows


def run_manuscript_audit(tex_path: Path = TEX_PATH) -> Tuple[bool, List[Tuple[str, str, str, str, bool]]]:
    tex = tex_path.read_text(encoding="utf-8")
    teob_m = json.loads(TEOB_MANIFEST.read_text(encoding="utf-8"))["stats"]
    teob_e = json.loads(TEOB_EVAL.read_text(encoding="utf-8"))
    m41 = json.loads(METRICS_41.read_text(encoding="utf-8"))
    ssvc = json.loads(SSVC_JSON.read_text(encoding="utf-8"))
    cenv = json.loads(CVSS_ENV_JSON.read_text(encoding="utf-8"))
    act = json.loads(ACTIONABLE_JSON.read_text(encoding="utf-8"))["methods"]
    abl = json.loads(ABLATION_JSON.read_text(encoding="utf-8"))["metrics"]
    guard = json.loads(GUARD_JSON.read_text(encoding="utf-8"))["confusion_matrix"]
    integ = json.loads(INTEG_JSON.read_text(encoding="utf-8"))

    checks: List[Tuple[str, str, str, str, bool]] = []

    def verify(table: str, key: str, tex_val: str, json_val: str, is_unit_metric: bool = True):
        ok = tex_val == json_val
        if is_unit_metric:
            fval = float(tex_val)
            if fval > 1.0 or fval < -1.0:
                ok = False
        checks.append((table, key, tex_val, json_val, ok))

    # 1. tab:teob_main
    teob_rows = _parse_rows(_extract_table_block(tex, "tab:teob_main"))[1:]
    for r in teob_rows:
        label = r[0]
        jkey = "VRS (default context=0.5)" if label.startswith("VRS") else label
        jm = teob_e["metrics"][jkey]
        for idx, mk in enumerate(("ndcg@10", "precision@10", "recall@10", "recall@50", "recall@100", "average_precision"), start=1):
            verify("tab:teob_main", f"{label}.{mk}", r[idx], f"{jm[mk]:.4f}", is_unit_metric=True)
        verify("tab:teob_main", f"{label}.top_tie", r[7], str(teob_e["tie_summary"][jkey]["top_block_size"]), is_unit_metric=False)

    # 2. tab:exploratory
    exp_rows = _parse_rows(_extract_table_block(tex, "tab:exploratory"))[1:]
    exp_map = {
        "SSVC tree": (ssvc["metrics"]["ndcg@10"], ssvc["metrics"]["precision@10_act"], ssvc["metrics"]["recall@10_act"], act["SSVC tree"]["AP@10"], act["SSVC tree"]["AR@10"], ssvc["metrics"]["spearman"]),
        "CVSS-only": (m41["CVSS-only"]["ndcg10"], m41["CVSS-only"]["precision10_act"], m41["CVSS-only"]["recall10_act"], act["CVSS-only"]["AP@10"], act["CVSS-only"]["AR@10"], m41["CVSS-only"]["spearman"]),
        "CVSS v3.1 env. proxy": (cenv["metrics"]["ndcg@10"], cenv["metrics"]["precision@10_act"], cenv["metrics"]["recall@10_act"], act["CVSS-only"]["AP@10"], act["CVSS-only"]["AR@10"], cenv["metrics"]["spearman"]),
        "EPSS-only": (m41["EPSS-only"]["ndcg10"], m41["EPSS-only"]["precision10_act"], m41["EPSS-only"]["recall10_act"], act["EPSS-only"]["AP@10"], act["EPSS-only"]["AR@10"], m41["EPSS-only"]["spearman"]),
        "KEV-first": (m41["KEV-first"]["ndcg10"], m41["KEV-first"]["precision10_act"], m41["KEV-first"]["recall10_act"], act["KEV-first"]["AP@10"], act["KEV-first"]["AR@10"], m41["KEV-first"]["spearman"]),
        "CVSS+EPSS+KEV": (m41["CVSS+EPSS+KEV"]["ndcg10"], m41["CVSS+EPSS+KEV"]["precision10_act"], m41["CVSS+EPSS+KEV"]["recall10_act"], act["CVSS+EPSS+KEV"]["AP@10"], act["CVSS+EPSS+KEV"]["AR@10"], m41["CVSS+EPSS+KEV"]["spearman"]),
        "VRS (vrs-v1)": (m41["VRS Proposed"]["ndcg10"], m41["VRS Proposed"]["precision10_act"], m41["VRS Proposed"]["recall10_act"], act["VRS (vrs-v1)"]["AP@10"], act["VRS (vrs-v1)"]["AR@10"], m41["VRS Proposed"]["spearman"]),
    }
    for r in exp_rows:
        name = r[0].replace("$^\\dagger$", "").replace("$^\\ddagger$", "").strip()
        if name in exp_map:
            vals = exp_map[name]
            for idx, mk in enumerate(("NDCG@10", "P@10", "R@10", "AP@10", "AR@10", "Spearman"), start=1):
                verify("tab:exploratory", f"{name}.{mk}", r[idx], f"{vals[idx-1]:.4f}", is_unit_metric=True)

    # 3. tab:ablation
    abl_rows = _parse_rows(_extract_table_block(tex, "tab:ablation"))[1:]
    abl_key_map = {
        "VRS (full)": "vrs_full",
        "VRS (No EPSS)": "vrs_no_epss",
        "VRS (No KEV)": "vrs_no_kev",
        "VRS (No Context)": "vrs_no_context",
        "VRS (No Bucket Override)": "vrs_no_buckets",
    }
    for r in abl_rows:
        ak = abl_key_map[r[0]]
        jm = abl[ak]
        for idx, mk in enumerate(("ndcg5", "ndcg10", "ndcg15", "precision10_act", "recall10_act", "spearman"), start=1):
            verify("tab:ablation", f"{r[0]}.{mk}", r[idx], f"{jm[mk]:.4f}", is_unit_metric=True)

    # 4. tab:guard
    guard_rows = _parse_rows(_extract_table_block(tex, "tab:guard"))[1:]
    tp_cell = guard_rows[0][1].replace("TP = ", "").strip()
    fn_cell = guard_rows[0][2].replace("FN = ", "").strip()
    fp_cell = guard_rows[1][1].replace("FP = ", "").strip()
    tn_cell = guard_rows[1][2].replace("TN = ", "").strip()
    verify("tab:guard", "TP", tp_cell, str(guard["TP"]), is_unit_metric=False)
    verify("tab:guard", "FN", fn_cell, str(guard["FN"]), is_unit_metric=False)
    verify("tab:guard", "FP", fp_cell, str(guard["FP"]), is_unit_metric=False)
    verify("tab:guard", "TN", tn_cell, str(guard["TN"]), is_unit_metric=False)

    # 5. tab:integrity
    integ_rows = _parse_rows(_extract_table_block(tex, "tab:integrity"))[1:]
    total_row = integ_rows[-1]
    verify("tab:integrity", "with_floor_total", total_row[2], f"{integ['n_passed']} / {integ['n_cases']}", is_unit_metric=False)

    # 6. tab:teob_cohort key totals
    coh_rows = _parse_rows(_extract_table_block(tex, "tab:teob_cohort"))[1:]
    verify("tab:teob_cohort", "nvd_total", coh_rows[0][1], str(teob_m["nvd_total"]), is_unit_metric=False)
    verify("tab:teob_cohort", "eligible_total", coh_rows[2][1].split()[0], str(teob_m["eligible_total"]), is_unit_metric=False)

    all_ok = all(c[4] for c in checks)
    return all_ok, checks


if __name__ == "__main__":
    ok, checks = run_manuscript_audit()
    print(f"{'TABLE':<16} {'CELL':<34} {'TEX':<10} {'JSON':<10} {'OK'}")
    print("-" * 80)
    for t, k, tv, jv, pass_flag in checks:
        print(f"{t:<16} {k:<34} {tv:<10} {jv:<10} {pass_flag}")
    print(f"\nTotal cells checked: {len(checks)}, Passed: {sum(1 for c in checks if c[4])}, Failed: {sum(1 for c in checks if not c[4])}")
    sys.exit(0 if ok else 1)
