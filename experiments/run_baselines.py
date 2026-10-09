import csv
import json
import os
import sys

# Add parent directory to path to import risk_engine
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import compute_cvss_only, compute_epss_only, compute_cvss_epss_kev, rank_findings, compute_vrs

def load_benchmark(filepath):
    findings = []
    reference = []
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
                        "intel": {
                            "data": {
                                "metrics": {
                                    "cvssMetricV31": [{"cvssData": {"baseScore": float(row["cvss"])}}]
                                }
                            }
                        }
                    }
                ],
                "epss_scores": {row["cve_id"]: float(row["epss"])},
                "kev_matches": [row["cve_id"]] if int(row["kev"]) == 1 else []
            }
            findings.append(finding)
            reference.append((row["cve_id"], int(row["reference_priority"])))
            
    reference.sort(key=lambda x: x[1])
    ref_ranking = [x[0] for x in reference]
    return findings, ref_ranking

def run_baselines():
    findings, ref_ranking = load_benchmark("data/benchmark/cves.csv")
    
    # 1. CVSS only
    cvss_ranked = sorted(findings, key=lambda f: -compute_cvss_only(f))
    cvss_ranking = [f["cve_matches"][0]["cve_id"] for f in cvss_ranked]
    
    # 2. EPSS only
    epss_ranked = sorted(findings, key=lambda f: -compute_epss_only(f))
    epss_ranking = [f["cve_matches"][0]["cve_id"] for f in epss_ranked]
    
    # 3. CVSS + EPSS + KEV (Baseline Combo)
    combo_ranked = sorted(findings, key=lambda f: -compute_cvss_epss_kev(f))
    combo_ranking = [f["cve_matches"][0]["cve_id"] for f in combo_ranked]
    
    # 4. VRS (vrs-v1) Default
    vrs_ranked_data = rank_findings(findings)
    vrs_ranking = [r["primary_cve"] for r in vrs_ranked_data]
    
    results = {
        "reference": ref_ranking,
        "cvss_only": cvss_ranking,
        "epss_only": epss_ranking,
        "combo_baseline": combo_ranking,
        "vrs_v1": vrs_ranking
    }
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/baselines.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_baselines()
