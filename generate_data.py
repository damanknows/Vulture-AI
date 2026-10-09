import json
import random
random.seed(42)
import csv
import os

# Generate 40 synthetic but realistic CVEs representing different risk profiles.
# Reference priority is based on a strict expert rubric:
# Tier 1 (Priority 1-10): KEV=1, EPSS > 0.5 (Actively exploited)
# Tier 2 (Priority 11-20): KEV=1, EPSS <= 0.5 OR KEV=0, EPSS > 0.8, Critical CVSS
# Tier 3 (Priority 21-30): KEV=0, High/Med CVSS, Exposure > 0.5
# Tier 4 (Priority 31-40): Low CVSS, Low Exposure, Low EPSS

def generate_benchmark():
    cves = []
    
    # Tier 1
    for i in range(1, 11):
        cves.append({
            "cve_id": f"CVE-2024-100{i:02d}",
            "cvss": round(random.uniform(7.0, 10.0), 1),
            "epss": round(random.uniform(0.6, 0.99), 3),
            "kev": 1,
            "exposure": round(random.uniform(0.7, 1.0), 2),
            "asset_criticality": round(random.uniform(0.5, 1.0), 2),
            "reference_priority": i,
            "source_timestamp": "2026-10-09",
            "label_source": "Expert Rubric (Tier 1)"
        })
        
    # Tier 2
    for i in range(11, 21):
        is_kev = random.choice([0, 1])
        epss = round(random.uniform(0.1, 0.5), 3) if is_kev else round(random.uniform(0.81, 0.95), 3)
        cves.append({
            "cve_id": f"CVE-2023-200{i:02d}",
            "cvss": round(random.uniform(7.0, 10.0), 1),
            "epss": epss,
            "kev": is_kev,
            "exposure": round(random.uniform(0.4, 0.9), 2),
            "asset_criticality": round(random.uniform(0.3, 0.8), 2),
            "reference_priority": i,
            "source_timestamp": "2026-10-09",
            "label_source": "Expert Rubric (Tier 2)"
        })
        
    # Tier 3
    for i in range(21, 31):
        cves.append({
            "cve_id": f"CVE-2022-300{i:02d}",
            "cvss": round(random.uniform(4.0, 7.0), 1),
            "epss": round(random.uniform(0.01, 0.1), 3),
            "kev": 0,
            "exposure": round(random.uniform(0.5, 1.0), 2),
            "asset_criticality": round(random.uniform(0.1, 0.5), 2),
            "reference_priority": i,
            "source_timestamp": "2026-10-09",
            "label_source": "Expert Rubric (Tier 3)"
        })
        
    # Tier 4
    for i in range(31, 41):
        cves.append({
            "cve_id": f"CVE-2021-400{i:02d}",
            "cvss": round(random.uniform(1.0, 4.0), 1),
            "epss": round(random.uniform(0.001, 0.01), 3),
            "kev": 0,
            "exposure": round(random.uniform(0.0, 0.4), 2),
            "asset_criticality": round(random.uniform(0.0, 0.3), 2),
            "reference_priority": i,
            "source_timestamp": "2026-10-09",
            "label_source": "Expert Rubric (Tier 4)"
        })
        
    with open("data/benchmark/cves.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cves[0].keys())
        writer.writeheader()
        for row in cves:
            writer.writerow(row)

if __name__ == "__main__":
    generate_benchmark()
