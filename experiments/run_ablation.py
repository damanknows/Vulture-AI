import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import rank_findings, DEFAULT_WEIGHTS
from experiments.run_baselines import load_benchmark

def normalize_weights(w):
    total = sum(w.values())
    return {k: v / total for k, v in w.items()}

def run_ablation():
    findings, ref_ranking = load_benchmark("data/benchmark/cves.csv")
    
    ablations = {
        "drop_epss": "w_E",
        "drop_kev": "w_K",
        "drop_n": "w_N",
        "drop_a": "w_A"
    }
    
    results = {"reference": ref_ranking}
    
    for name, drop_key in ablations.items():
        w = dict(DEFAULT_WEIGHTS)
        w[drop_key] = 0.0
        w = normalize_weights(w)
        
        ranked_data = rank_findings(findings, weights=w)
        results[name] = [r["primary_cve"] for r in ranked_data]
        
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/ablation.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_ablation()
