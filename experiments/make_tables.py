"""
Vulture-AI Research Artifacts Generator (LaTeX Tables & Figures)
================================================================

Generates publication-quality LaTeX comparison tables and empirical ranking plots
strictly from actual executed experimental results.
"""

import json
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.metrics import (
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    spearman_correlation,
    THRESHOLD_ACT,
    THRESHOLD_ACTIONABLE
)


def generate_tex_table(headers, rows, filepath):
    tex = "\\begin{table}[h]\n\\centering\n\\begin{tabular}{" + "l" + "c" * (len(headers) - 1) + "}\n\\hline\n"
    tex += " & ".join(headers) + " \\\\\n\\hline\n"
    for row in rows:
        tex += " & ".join([f"{x:.4f}" if isinstance(x, float) else str(x) for x in row]) + " \\\\\n"
    tex += "\\hline\n\\end{tabular}\n\\end{table}"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(tex)


def make_tables():
    with open("experiments/results/baselines.json", "r", encoding="utf-8") as f:
        base = json.load(f)

    abl = {}
    if os.path.exists("experiments/results/ablation.json"):
        with open("experiments/results/ablation.json", "r", encoding="utf-8") as f:
            abl = json.load(f)

    ref = base["reference"]
    rel_dict = base["relevance_dict"]

    # 1. Main Baseline Comparison Table
    models = [
        ("cvss_only", "CVSS-only"),
        ("epss_only", "EPSS-only"),
        ("kev_first", "KEV-first"),
        ("combo_baseline", "CVSS+EPSS+KEV"),
        ("vrs_v1", "VRS (Proposed)")
    ]
    headers = ["Model", "NDCG@10", "P@10 (Act)", "R@10 (Act)", "P@10 (Action)", "R@10 (Action)", "Spearman"]
    rows = []

    for key, label in models:
        pred = base.get(key, [])
        n10 = ndcg_at_k(pred, rel_dict, k=10)
        p10_act = precision_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACT)
        r10_act = recall_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACT)
        p10_action = precision_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACTIONABLE)
        r10_action = recall_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACTIONABLE)
        sp = spearman_correlation(pred, ref)
        label_clean = label.replace("_", "\\_")
        rows.append([label_clean, n10, p10_act, r10_act, p10_action, r10_action, sp])

    os.makedirs("experiments/results/tables", exist_ok=True)
    generate_tex_table(headers, rows, "experiments/results/tables/main_comparison.tex")

    # 2. Ablation Comparison Table
    if abl:
        abl_models = [
            ("vrs_full", "VRS (Full Model)"),
            ("vrs_no_epss", "VRS (No EPSS)"),
            ("vrs_no_kev", "VRS (No KEV Weight)"),
            ("vrs_no_context", "VRS (No Context / Tech-only)"),
            ("vrs_no_buckets", "VRS (No Bucket Override)")
        ]
        abl_headers = ["Variant", "NDCG@10", "P@10 (Act)", "R@10 (Act)", "P@10 (Action)", "R@10 (Action)", "Spearman"]
        abl_rows = []
        for key, label in abl_models:
            pred = abl.get(key, [])
            if pred:
                n10 = ndcg_at_k(pred, rel_dict, k=10)
                p10_act = precision_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACT)
                r10_act = recall_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACT)
                p10_action = precision_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACTIONABLE)
                r10_action = recall_at_k(pred, rel_dict, k=10, threshold=THRESHOLD_ACTIONABLE)
                sp = spearman_correlation(pred, ref)
                abl_rows.append([label.replace("_", "\\_"), n10, p10_act, r10_act, p10_action, r10_action, sp])
        generate_tex_table(abl_headers, abl_rows, "experiments/results/tables/ablation.tex")

    # 3. Empirical Ranking Scatter Figure
    os.makedirs("experiments/results/figures", exist_ok=True)
    fig_path = "experiments/results/figures/ranking_comparison.png"

    ref_indices = list(range(1, len(ref) + 1))
    cvss_ranks = [base["cvss_only"].index(cve) + 1 for cve in ref]
    epss_ranks = [base["epss_only"].index(cve) + 1 for cve in ref]
    vrs_ranks = [base["vrs_v1"].index(cve) + 1 for cve in ref]

    plt.figure(figsize=(9, 5), dpi=300)
    plt.plot(ref_indices, ref_indices, 'k--', label="Ideal Reference Rank (1:1)", alpha=0.5)
    plt.scatter(ref_indices, cvss_ranks, color='#e63946', label=f"CVSS-only (Sp={spearman_correlation(base['cvss_only'], ref):.3f})", alpha=0.7, s=35)
    plt.scatter(ref_indices, epss_ranks, color='#457b9d', label=f"EPSS-only (Sp={spearman_correlation(base['epss_only'], ref):.3f})", alpha=0.7, s=35)
    plt.scatter(ref_indices, vrs_ranks, color='#2a9d8f', label=f"VRS Proposed (Sp={spearman_correlation(base['vrs_v1'], ref):.3f})", alpha=0.9, marker='^', s=45)

    plt.title("Empirical Ranking Comparison vs. Reference Priority (N=41)", fontsize=12, fontweight='bold')
    plt.xlabel("Reference Priority (1 = Highest Urgency)", fontsize=10)
    plt.ylabel("Assigned Method Rank (1 = Highest Urgency)", fontsize=10)
    plt.gca().invert_yaxis()
    plt.gca().invert_xaxis()
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(loc="lower left", fontsize=9)
    plt.tight_layout()
    plt.savefig(fig_path)
    plt.close()
    print(f"Generated tables and empirical ranking figure: {fig_path}")


if __name__ == "__main__":
    make_tables()
