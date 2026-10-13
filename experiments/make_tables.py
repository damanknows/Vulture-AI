import json
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.metrics import ndcg_at_k, precision_at_k, recall_at_k, spearman_correlation

def generate_tex_table(headers, rows, filepath):
    tex = "\\begin{table}[h]\n\\centering\n\\begin{tabular}{" + "c" * len(headers) + "}\n\\hline\n"
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
    
    # Main Comparison Table
    models = [
        ("cvss_only", "CVSS-only"),
        ("epss_only", "EPSS-only"),
        ("kev_first", "KEV-first"),
        ("combo_baseline", "CVSS+EPSS+KEV"),
        ("vrs_v1", "Vulture-AI (VRS)")
    ]
    headers = ["Model", "NDCG@10", "P@10", "R@10", "Spearman"]
    rows = []
    
    for key, label in models:
        pred = base.get(key, [])
        n10 = ndcg_at_k(pred, rel_dict, k=10)
        p10 = precision_at_k(pred, rel_dict, k=10, threshold=3)
        r10 = recall_at_k(pred, rel_dict, k=10, threshold=3)
        sp = spearman_correlation(pred, ref)
        label_clean = label.replace("_", "\\_")
        rows.append([label_clean, n10, p10, r10, sp])
        
    os.makedirs("experiments/results/tables", exist_ok=True)
    generate_tex_table(headers, rows, "experiments/results/tables/main_comparison.tex")
    
    # Ablation Table
    if abl:
        abl_models = [
            ("vrs_full", "VRS (Full)"),
            ("vrs_no_epss", "VRS (No EPSS)"),
            ("vrs_no_kev", "VRS (No KEV)"),
            ("vrs_no_context", "VRS (No Context)")
        ]
        abl_headers = ["Variant", "NDCG@10", "P@10", "R@10", "Spearman"]
        abl_rows = []
        for key, label in abl_models:
            pred = abl.get(key, [])
            if pred:
                n10 = ndcg_at_k(pred, rel_dict, k=10)
                p10 = precision_at_k(pred, rel_dict, k=10, threshold=3)
                r10 = recall_at_k(pred, rel_dict, k=10, threshold=3)
                sp = spearman_correlation(pred, ref)
                abl_rows.append([label.replace("_", "\\_"), n10, p10, r10, sp])
        generate_tex_table(abl_headers, abl_rows, "experiments/results/tables/ablation.tex")
        
    # Generate real, empirical ranking comparison figure
    os.makedirs("experiments/results/figures", exist_ok=True)
    fig_path = "experiments/results/figures/ranking_comparison.png"
    
    ref_indices = list(range(1, len(ref) + 1))
    cvss_ranks = [base["cvss_only"].index(cve) + 1 for cve in ref]
    epss_ranks = [base["epss_only"].index(cve) + 1 for cve in ref]
    vrs_ranks = [base["vrs_v1"].index(cve) + 1 for cve in ref]
    
    plt.figure(figsize=(9, 5), dpi=300)
    plt.plot(ref_indices, ref_indices, 'k--', label="Ideal Reference Rank", alpha=0.5)
    plt.scatter(ref_indices, cvss_ranks, color='#e63946', label=f"CVSS-only (Sp={spearman_correlation(base['cvss_only'], ref):.3f})", alpha=0.7, s=35)
    plt.scatter(ref_indices, epss_ranks, color='#457b9d', label=f"EPSS-only (Sp={spearman_correlation(base['epss_only'], ref):.3f})", alpha=0.7, s=35)
    plt.scatter(ref_indices, vrs_ranks, color='#2a9d8f', label=f"VRS (Sp={spearman_correlation(base['vrs_v1'], ref):.3f})", alpha=0.9, marker='^', s=45)
    
    plt.title("Empirical Ranking Comparison vs. Reference Priority", fontsize=12, fontweight='bold')
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
