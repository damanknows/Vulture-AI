import csv
import json
import os
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk_engine import (
    compute_cvss_only,
    compute_epss_only,
    compute_kev_first,
    compute_cvss_epss_kev,
    rank_findings,
    compute_vrs
)

LABEL_TO_RELEVANCE = {
    "Act": 3,
    "Attend": 2,
    "Track": 1,
    "Defer": 0
}

def load_benchmark(filepath="data/benchmark/cves.csv"):
    findings = []
    reference = []
    relevance_dict = {}
    
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row["cve_id"].strip()
            
            # Missing value handling
            cvss_val = float(row["cvss"]) if row.get("cvss") and row["cvss"].strip() else None
            epss_val = float(row["epss"]) if row.get("epss") and row["epss"].strip() else None
            kev_val = int(row["kev"]) if row.get("kev") and row["kev"].strip() else 0
            
            exp_val = float(row["exposure"]) if row.get("exposure") and row["exposure"].strip() else None
            crit_val = float(row["asset_criticality"]) if row.get("asset_criticality") and row["asset_criticality"].strip() else None
            
            finding = {
                "finding": {
                    "target": "benchmark_host",
                    "port": 443,
                    "service": "https",
                    "network_exposure": exp_val,
                    "asset_criticality": crit_val
                },
                "cve_matches": [
                    {
                        "cve_id": cve_id,
                        "cvss_score": cvss_val,
                        "epss_probability": epss_val,
                        "kev_listed": kev_val == 1
                    }
                ]
            }
            findings.append(finding)
            
            ref_pri = int(row["reference_priority"]) if row.get("reference_priority") else 999
            reference.append((cve_id, ref_pri))
            
            # Map independent label to relevance grade (3=Act, 2=Attend, 1=Track, 0=Defer)
            raw_label = row.get("independent_label", "").strip()
            if raw_label in LABEL_TO_RELEVANCE:
                rel = LABEL_TO_RELEVANCE[raw_label]
            else:
                tier_m = re.search(r'Tier (\d)', row.get("label_source", ""))
                tier = int(tier_m.group(1)) if tier_m else 4
                rel = max(0, 4 - tier)
                
            relevance_dict[cve_id] = rel
            
    reference.sort(key=lambda x: (x[1], x[0]))
    ref_ranking = [x[0] for x in reference]
    return findings, ref_ranking, relevance_dict

def run_baselines(benchmark_path="data/benchmark/cves.csv"):
    findings, ref_ranking, relevance_dict = load_benchmark(benchmark_path)
    
    # 1. CVSS-only (Descending score, deterministic tie-break: ascending CVE ID)
    cvss_ranked = sorted(findings, key=lambda f: (
        -compute_cvss_only(f) if compute_cvss_only(f) is not None else float('inf'),
        f["cve_matches"][0]["cve_id"]
    ))
    cvss_ranking = [f["cve_matches"][0]["cve_id"] for f in cvss_ranked]
    
    # 2. EPSS-only (Descending score, deterministic tie-break: ascending CVE ID)
    epss_ranked = sorted(findings, key=lambda f: (
        -compute_epss_only(f) if compute_epss_only(f) is not None else float('inf'),
        f["cve_matches"][0]["cve_id"]
    ))
    epss_ranking = [f["cve_matches"][0]["cve_id"] for f in epss_ranked]
    
    # 3. KEV-first baseline (KEV=1 first, then CVSS descending, deterministic tie-break)
    kev_ranked = sorted(findings, key=lambda f: (
        -compute_kev_first(f),
        f["cve_matches"][0]["cve_id"]
    ))
    kev_ranking = [f["cve_matches"][0]["cve_id"] for f in kev_ranked]
    
    # 4. CVSS + EPSS + KEV combo baseline
    combo_ranked = sorted(findings, key=lambda f: (
        -compute_cvss_epss_kev(f) if compute_cvss_epss_kev(f) is not None else float('inf'),
        f["cve_matches"][0]["cve_id"]
    ))
    combo_ranking = [f["cve_matches"][0]["cve_id"] for f in combo_ranked]
    
    # 5. Vulture-AI Proposed (vrs-v1)
    vrs_ranked_data = rank_findings(findings)
    vrs_ranking = [r["primary_cve"] for r in vrs_ranked_data]
    
    # Record per-record scoring breakdown
    per_record = {}
    for r in vrs_ranked_data:
        cid = r["primary_cve"]
        f_match = r["finding_data"]["cve_matches"][0]
        score_info = r["score_data"]
        per_record[cid] = {
            "cvss": f_match.get("cvss_score"),
            "epss": f_match.get("epss_probability"),
            "kev": f_match.get("kev_listed"),
            "vrs_score": score_info.get("vrs"),
            "vrs_bucket": score_info.get("bucket"),
            "components": score_info.get("components"),
            "missing_data": score_info.get("missing_data"),
            "reference_priority": ref_ranking.index(cid) + 1 if cid in ref_ranking else None,
            "relevance_grade": relevance_dict.get(cid, 0)
        }
        
    results = {
        "benchmark_file": benchmark_path,
        "sample_count": len(findings),
        "reference": ref_ranking,
        "relevance_dict": relevance_dict,
        "cvss_only": cvss_ranking,
        "epss_only": epss_ranking,
        "kev_first": kev_ranking,
        "combo_baseline": combo_ranking,
        "vrs_v1": vrs_ranking,
        "per_record": per_record
    }
    
    os.makedirs("experiments/results", exist_ok=True)
    with open("experiments/results/baselines.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"Computed rankings for {len(findings)} records.")
    print("Saved baseline outputs to experiments/results/baselines.json")
    return results

if __name__ == "__main__":
    run_baselines()
