import json
import os
from metrics import ndcg_at_k, spearman_correlation

def compute_all():
    with open("experiments/results/baselines.json", "r") as f:
        baselines = json.load(f)
        
    with open("experiments/results/ablation.json", "r") as f:
        ablation = json.load(f)
        
    reference = baselines["reference"]
    relevance_dict = baselines["relevance_dict"]
    
    models = {
        "CVSS-only": baselines["cvss_only"],
        "EPSS-only": baselines["epss_only"],
        "CVSS+EPSS+KEV": baselines["combo_baseline"],
        "VRS Proposed": baselines["vrs_v1"],
        "VRS No EPSS": ablation["vrs_no_epss"],
        "VRS No KEV": ablation["vrs_no_kev"],
        "VRS No Context": ablation["vrs_no_context"]
    }
    
    print("Model | NDCG@5 | NDCG@10 | Spearman")
    print("---|---|---|---")
    
    table_lines = ["| Model | NDCG@5 | NDCG@10 | Spearman |", "|---|---|---|---|"]
    
    out_results = {}
    for name, ranking in models.items():
        n5 = ndcg_at_k(ranking, relevance_dict, 5)
        n10 = ndcg_at_k(ranking, relevance_dict, 10)
        sp = spearman_correlation(ranking, reference)
        out_results[name] = {"ndcg5": n5, "ndcg10": n10, "spearman": sp}
        line = f"| {name} | {n5:.3f} | {n10:.3f} | {sp:.3f} |"
        print(line)
        table_lines.append(line)
        
    with open("experiments/results/metrics_table.md", "w") as f:
        f.write("\n".join(table_lines) + "\n")
        
    with open("experiments/results/metrics.json", "w") as f:
        json.dump(out_results, f, indent=2)

if __name__ == "__main__":
    compute_all()
