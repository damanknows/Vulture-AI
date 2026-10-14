#!/usr/bin/env python3
"""
experiments/make_figures.py

Generates publication-quality figures for the IEEE ICCI 2026 manuscript.
Strictly uses verified experimental results from:
- experiments/results/baselines.json (41-record curated benchmark)
- experiments/results/expanded_500_results.json (500-record expanded corpus)

Outputs:
- experiments/results/figures/ranking_and_recall.pdf (vector)
- experiments/results/figures/ranking_and_recall.png (high-dpi raster)
"""

import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def generate_ranking_and_recall_figure():
    baselines_path = os.path.join(PROJECT_ROOT, "experiments", "results", "baselines.json")
    results_500_path = os.path.join(PROJECT_ROOT, "experiments", "results", "expanded_500_results.json")
    figures_dir = os.path.join(PROJECT_ROOT, "experiments", "results", "figures")
    os.makedirs(figures_dir, exist_ok=True)

    with open(baselines_path, "r", encoding="utf-8") as f:
        base = json.load(f)

    with open(results_500_path, "r", encoding="utf-8") as f:
        res500 = json.load(f)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.0), dpi=300)

    # -------------------------------------------------------------
    # Panel (a): Curated Benchmark Ranking Scatter (N=41)
    # -------------------------------------------------------------
    ref = base["reference"]
    ref_indices = list(range(1, len(ref) + 1))
    cvss_ranks = [base["cvss_only"].index(cve) + 1 for cve in ref]
    epss_ranks = [base["epss_only"].index(cve) + 1 for cve in ref]
    vrs_ranks = [base["vrs_v1"].index(cve) + 1 for cve in ref]

    ax1.plot(ref_indices, ref_indices, 'k--', label="Ideal Reference Rank (1:1)", alpha=0.45, linewidth=1.2)
    ax1.scatter(ref_indices, cvss_ranks, color='#d62728', label="CVSS-only (rho=0.736)", alpha=0.75, s=28, marker='o')
    ax1.scatter(ref_indices, epss_ranks, color='#1f77b4', label="EPSS-only (rho=0.824)", alpha=0.75, s=28, marker='s')
    ax1.scatter(ref_indices, vrs_ranks, color='#2ca02c', label="VRS Proposed (rho=0.949)", alpha=0.90, s=42, marker='^')

    ax1.set_title("(a) Rank Alignment vs. SSVC Priority (N=41)", fontsize=10, fontweight='bold', pad=8)
    ax1.set_xlabel("Author-Curated SSVC Priority Rank (1 = Highest)", fontsize=9)
    ax1.set_ylabel("Assigned Method Rank (1 = Highest)", fontsize=9)
    ax1.invert_yaxis()
    ax1.invert_xaxis()
    ax1.grid(True, linestyle=':', alpha=0.55)
    ax1.legend(loc="lower left", fontsize=8, framealpha=0.9)

    # -------------------------------------------------------------
    # Panel (b): Retrospective Recall@K on Expanded Backlog (N=500)
    # -------------------------------------------------------------
    cutoffs = res500["evaluated_cutoffs"]  # [5, 10, 15, 20, 25, 30]
    multi = res500["multi_cutoff_metrics"]

    cvss_r = [multi["CVSS-only"][f"R@{k}"] for k in cutoffs]
    epss_r = [multi["EPSS-only"][f"R@{k}"] for k in cutoffs]
    kev_first_r = [multi["KEV-first"][f"R@{k}"] for k in cutoffs]
    combo_r = [multi["Combined Baseline"][f"R@{k}"] for k in cutoffs]
    vrs_r = [multi["VRS Proposed (vrs-v1)"][f"R@{k}"] for k in cutoffs]

    # Theoretical ceiling given 25 total positives: min(k/25, 1.0)
    ceiling_r = [min(k / 25.0, 1.0) for k in cutoffs]

    ax2.plot(cutoffs, ceiling_r, 'k--', label="Theoretical Recall Ceiling (K/25)", alpha=0.45, linewidth=1.2)
    ax2.plot(cutoffs, cvss_r, 'o-', color='#d62728', label="CVSS-only (R@25=0.44)", linewidth=1.8, markersize=5)
    ax2.plot(cutoffs, epss_r, 's-', color='#1f77b4', label="EPSS-only (R@25=0.88)", linewidth=1.8, markersize=5)
    ax2.plot(cutoffs, kev_first_r, 'd--', color='#ff7f0e', label="KEV-first (R@25=1.00)*", linewidth=1.6, markersize=5, alpha=0.8)
    ax2.plot(cutoffs, combo_r, 'x--', color='#9467bd', label="Combined Baseline (R@25=1.00)*", linewidth=1.6, markersize=6, alpha=0.8)
    ax2.plot(cutoffs, vrs_r, '^-', color='#2ca02c', label="VRS Proposed (R@25=1.00)*", linewidth=2.0, markersize=6)

    ax2.set_title("(b) Retrospective Recall@K on Backlog (N=500, KEV=25)", fontsize=10, fontweight='bold', pad=8)
    ax2.set_xlabel("Triage Budget / Top-K Cutoff (K)", fontsize=9)
    ax2.set_ylabel("Recall Against CISA KEV Membership", fontsize=9)
    ax2.set_ylim(-0.02, 1.05)
    ax2.set_xticks(cutoffs)
    ax2.grid(True, linestyle=':', alpha=0.55)
    ax2.legend(loc="lower right", fontsize=7.5, framealpha=0.9)

    plt.tight_layout()

    pdf_out = os.path.join(figures_dir, "ranking_and_recall.pdf")
    png_out = os.path.join(figures_dir, "ranking_and_recall.png")
    plt.savefig(pdf_out, bbox_inches="tight")
    plt.savefig(png_out, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"Generated figures:\n  {pdf_out}\n  {png_out}")

if __name__ == "__main__":
    generate_ranking_and_recall_figure()
