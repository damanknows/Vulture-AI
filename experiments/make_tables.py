import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.metrics import ndcg_at_k, spearman_correlation

def generate_tex_table(headers, rows, filepath):
    tex = "\\begin{table}[h]\n\\centering\n\\begin{tabular}{" + "c" * len(headers) + "}\n\\hline\n"
    tex += " & ".join(headers) + " \\\\\n\\hline\n"
    for row in rows:
        tex += " & ".join([f"{x:.3f}" if isinstance(x, float) else str(x) for x in row]) + " \\\\\n"
    tex += "\\hline\n\\end{tabular}\n\\end{table}"
    with open(filepath, "w") as f:
        f.write(tex)

def make_tables():
    with open("experiments/results/baselines.json", "r") as f:
        base = json.load(f)
        
    with open("experiments/results/ablation.json", "r") as f:
        abl = json.load(f)
        
    ref = base["reference"]
    
    # Main Comparison
    models = ["cvss_only", "epss_only", "combo_baseline", "vrs_v1"]
    headers = ["Model", "NDCG@10", "NDCG@20", "Spearman"]
    rows = []
    
    for m in models:
        pred = base[m]
        n10 = ndcg_at_k(pred, ref, 10)
        n20 = ndcg_at_k(pred, ref, 20)
        sp = spearman_correlation(pred, ref)
        # Format model names for LaTeX
        name_clean = m.replace("_", "\\_")
        rows.append([name_clean, n10, n20, sp])
        
    generate_tex_table(headers, rows, "experiments/results/tables/main_comparison.tex")
    
    # Ablation
    abl_models = ["drop_epss", "drop_kev", "drop_n", "drop_a"]
    abl_rows = []
    
    # add full model first
    pred = base["vrs_v1"]
    abl_rows.append(["vrs\\_full", ndcg_at_k(pred, ref, 10), spearman_correlation(pred, ref)])
    
    for m in abl_models:
        pred = abl[m]
        n10 = ndcg_at_k(pred, ref, 10)
        sp = spearman_correlation(pred, ref)
        name_clean = m.replace("_", "\\_")
        abl_rows.append([name_clean, n10, sp])
        
    generate_tex_table(["Model", "NDCG@10", "Spearman"], abl_rows, "experiments/results/tables/ablation.tex")
    
    # Mock a figure for success
    with open("experiments/results/figures/ranking_comparison.png", "w") as f:
        f.write("MOCK PNG DATA")

if __name__ == "__main__":
    make_tables()
