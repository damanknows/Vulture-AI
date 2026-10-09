import csv
import json
import os
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import compute_cvss_only, compute_epss_only, compute_cvss_epss_kev, rank_findings, compute_vrs

def load_benchmark(filepath):
    findings = []
    reference = []
    relevance_dict = {}
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            finding = {
                "finding": {
                    "network_exposure": float(row["exposure"]),
                    "asset_criticality": float(row["asset_criticality"])
                },
                "cve_matches": [
                    {
                        "cve_id": row["cve_id"],
                        "cvss_score": float(row["cvss"]) if row["cvss"] else None,
                        "epss_probability": float(row["epss"]) if row["epss"] else None,
                        "kev_listed": int(row["kev"]) == 1
                    }
                ]
            }
            findings.append(finding)
            reference.append((row["cve_id"], int(row["reference_priority"])))
            
            tier_match = re.search(r'Tier (\d)', row.get("label_source", ""))
            tier = int(tier_match.group(1)) if tier_match else 4
            relevance = max(0, 4 - tier)
            relevance_dict[row["cve_id"]] = relevance
            
    reference.sort(key=lambda x: x[1])
    ref_ranking = [x[0] for x in reference]
    return findings, ref_ranking, relevance_dict

def run_baselines():
    findings, ref_ranking, relevance_dict = load_benchmark("data/benchmark/cves.csv")
    
    # 1. CVSS only (Descending CVSS, tie-break Ascending CVE)
    cvss_ranked = sorted(findings, key=lambda f: (
        -compute_cvss_only(f) if compute_cvss_only(f) is not None else float('inf'), 
        f["cve_matches"][0]["cve_id"]
    ))
    cvss_ranking = [f["cve_matches"][0]["cve_id"] for f in cvss_ranked]
    
    # 2. EPSS only
    epss_ranked = sorted(findings, key=lambda f: (
        -compute_epss_only(f) if compute_epss_only(f) is not None else float('inf'), 
        f["cve_matches"][0]["cve_id"]
    ))
    epss_ranking = [f["cve_matches"][0]["cve_id"] for f in epss_ranked]
    
    # 3. CVSS + EPSS + KEV (Baseline Combo)
    combo_ranked = sorted(findings, key=lambda f: (
        -compute_cvss_epss_kev(f) if compute_cvss_epss_kev(f) is not None else float('inf'), 
        f["cve_matches"][0]["cve_id"]
    ))
    combo_ranking = [f["cve_matches"][0]["cve_id"] for f in combo_ranked]
    
    # 4. VRS (vrs-v1) Default
    vrs_ranked_data = rank_findings(findings)
    vrs_ranking = [r["primary_cve"] for r in vrs_ranked_data]
    
    results = {
        "reference": ref_ranking,
        "relevance_dict": relevance_dict,
        "cvss_only": cvss_ranking,
        "epss_only": epss_ranking,
        "combo_baseline": combo_ranking,
        "vrs_v1": vrs_ranking
    }
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/baselines.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("Saved baseline rankings to experiments/results/baselines.json")

if __name__ == "__main__":
    run_baselines()
