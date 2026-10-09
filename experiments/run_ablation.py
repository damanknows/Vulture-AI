import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import rank_findings
from run_baselines import load_benchmark

def run_ablation():
    findings, ref_ranking, _ = load_benchmark("data/benchmark/cves.csv")
    
    # 1. Full VRS
    full_weights = {"w_C": 0.25, "w_E": 0.20, "w_K": 0.20, "w_N": 0.20, "w_A": 0.15}
    full_ranked = rank_findings(findings, weights=full_weights)
    full_ranking = [r["primary_cve"] for r in full_ranked]
    
    # 2. No EPSS (Distribute w_E evenly)
    no_epss_w = {"w_C": 0.30, "w_E": 0.00, "w_K": 0.25, "w_N": 0.25, "w_A": 0.20}
    no_epss_ranked = rank_findings(findings, weights=no_epss_w)
    no_epss_ranking = [r["primary_cve"] for r in no_epss_ranked]
    
    # 3. No KEV
    no_kev_w = {"w_C": 0.30, "w_E": 0.25, "w_K": 0.00, "w_N": 0.25, "w_A": 0.20}
    no_kev_ranked = rank_findings(findings, weights=no_kev_w)
    no_kev_ranking = [r["primary_cve"] for r in no_kev_ranked]
    
    # 4. No Exposure/Criticality (Only vulnerability metrics)
    no_context_w = {"w_C": 0.40, "w_E": 0.30, "w_K": 0.30, "w_N": 0.00, "w_A": 0.00}
    no_context_ranked = rank_findings(findings, weights=no_context_w)
    no_context_ranking = [r["primary_cve"] for r in no_context_ranked]
    
    results = {
        "vrs_full": full_ranking,
        "vrs_no_epss": no_epss_ranking,
        "vrs_no_kev": no_kev_ranking,
        "vrs_no_context": no_context_ranking
    }
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/ablation.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("Saved ablation rankings to experiments/results/ablation.json")

if __name__ == "__main__":
    run_ablation()
