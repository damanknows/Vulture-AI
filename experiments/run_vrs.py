import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import rank_findings
from experiments.run_baselines import load_benchmark

def run_vrs():
    findings, ref_ranking = load_benchmark("data/benchmark/cves.csv")
    
    config_path = "experiments/configs/vrs_v1.json"
    with open(config_path, "r") as f:
        weights = json.load(f)
        
    vrs_ranked_data = rank_findings(findings, weights=weights)
    vrs_ranking = [r["primary_cve"] for r in vrs_ranked_data]
    
    results = {
        "reference": ref_ranking,
        "vrs_v1_custom_config": vrs_ranking
    }
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/vrs.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_vrs()
