"""
Vulture-AI Benchmark Provenance Manifest Generator
==================================================

Generates comprehensive JSON manifest documenting dataset provenance:
- Dataset identity (name, version, timestamp)
- Record composition (real vs synthetic)
- Feature provenance (source, timestamp, version)
- Label origin and methodology
- Missing data inventory
- Data lineage and generation steps

Manifest is immutable after creation; enables reproducibility auditing.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List
import csv


MANIFEST_SCHEMA_VERSION = "1.0"


def generate_benchmark_manifest(
    csv_path: str,
    dataset_name: str = "Vulture-AI Curated Reference Benchmark",
    snapshot_date: str = "2026-10-14T00:00:00Z",
    real_cve_count: int = 39,
    synthetic_cve_count: int = 2,
    cvss_source: str = "NIST NVD v2.0 API",
    cvss_snapshot_date: str = "2026-10-14T00:00:00Z",
    epss_source: str = "FIRST.org EPSS API",
    epss_snapshot_date: str = "2026-10-14T00:00:00Z",
    kev_source: str = "CISA Known Exploited Vulnerabilities Catalog",
    kev_version: str = "2026.10.13",
    kev_release_date: str = "2026-10-13T19:10:43.6568Z",
    label_origin: str = "Author-curated SSVC reference rubric (not independently validated)",
    context_origin: str = "Archetypal profiles (not organization-specific)",
) -> Dict[str, Any]:
    """
    Generates comprehensive provenance manifest for benchmark dataset.
    
    Args:
        csv_path: Path to benchmark CSV file
        dataset_name: Human-readable dataset identifier
        snapshot_date: ISO-8601 timestamp when benchmark frozen
        real_cve_count: Number of real public CVEs in dataset
        synthetic_cve_count: Number of synthetic edge-case CVEs
        cvss_source: Source of CVSS scores
        cvss_snapshot_date: When CVSS data was collected
        epss_source: Source of EPSS probabilities
        epss_snapshot_date: When EPSS data was collected
        kev_source: Source of KEV catalog
        kev_version: KEV catalog version
        kev_release_date: KEV catalog release timestamp
        label_origin: Description of how labels were created
        context_origin: Description of how N (exposure) and A (criticality) were assigned
    
    Returns:
        Dictionary containing complete provenance manifest
    """
    
    # Read CSV to inventory records
    records = []
    real_cves = []
    synthetic_cves = []
    missing_cvss = []
    missing_epss = []
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)
            cve_id = row["cve_id"].strip()
            
            # Classify: synthetic if ID ends in 99xxx
            if cve_id.endswith("99991") or cve_id.endswith("99992"):
                synthetic_cves.append(cve_id)
                if not row["cvss"].strip():
                    missing_cvss.append(cve_id)
                if not row["epss"].strip():
                    missing_epss.append(cve_id)
            else:
                real_cves.append(cve_id)
    
    # Count labels
    label_distribution = {}
    for row in records:
        label = row["independent_label"].strip()
        label_distribution[label] = label_distribution.get(label, 0) + 1
    
    # Count KEV
    kev_count = sum(1 for row in records if row["kev"].strip() == "1")
    
    manifest = {
        "metadata": {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "dataset_name": dataset_name,
            "dataset_version": "v1.0-original",
            "generation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "benchmark_snapshot_date": snapshot_date,
        },
        
        "population": {
            "total_records": len(records),
            "real_cve_count": len(real_cves),
            "synthetic_cve_count": len(synthetic_cves),
            "real_cve_ids": sorted(real_cves),
            "synthetic_cve_ids": sorted(synthetic_cves),
        },
        
        "feature_provenance": {
            "cvss": {
                "source": cvss_source,
                "version": "v3.1",
                "snapshot_date": cvss_snapshot_date,
                "metric": "Base Score",
                "range": [0.0, 10.0],
                "completeness": f"{len([r for r in records if r['cvss'].strip()])}/{len(records)}",
            },
            "epss": {
                "source": epss_source,
                "snapshot_date": epss_snapshot_date,
                "metric": "30-day exploitation probability",
                "range": [0.0, 1.0],
                "completeness": f"{len([r for r in records if r['epss'].strip()])}/{len(records)}",
                "note": "Rolling 30-day forecast; subject to drift",
            },
            "kev": {
                "source": kev_source,
                "version": kev_version,
                "release_date": kev_release_date,
                "metric": "Binary KEV catalog membership",
                "kev_listed_count": kev_count,
                "kev_unlisted_count": len(records) - kev_count,
            },
            "exposure": {
                "source": context_origin,
                "metric": "Network exposure (N): [0.0, 1.0]",
                "values": {
                    "1.0": "Internet-facing perimeter",
                    "0.7": "DMZ or partner network",
                    "0.3": "Internal subnet",
                    "0.0": "Air-gapped / isolated"
                },
                "note": "Archetypal profiles, not organization-specific",
            },
            "asset_criticality": {
                "source": context_origin,
                "metric": "Asset criticality (A): [0.0, 1.0]",
                "values": {
                    "1.0": "Tier 1 critical (domain controller, payment gateway, DNS)",
                    "0.7": "Tier 2 high-value (production database, VPN)",
                    "0.3": "Tier 3 moderate (internal workstations, dev hosts)",
                    "0.0": "Tier 4 low-value (test environments)",
                },
                "note": "Archetypal profiles, not organization-specific",
            },
        },
        
        "label_provenance": {
            "origin": label_origin,
            "methodology": "Manual application of CISA SSVC decision rubric v2.0",
            "reference": "Spring et al. (2020) Prioritizing Vulnerability Response: A Stakeholder-Specific Vulnerability Categorization (SSVC)",
            "note": "Author-curated heuristic judgments; NOT independently validated breach ground truth",
            "distribution": label_distribution,
        },
        
        "missing_data_inventory": {
            "missing_cvss": {
                "count": len(missing_cvss),
                "cve_ids": missing_cvss,
                "handling_policy": "Records with missing CVSS are assigned VRS=None, bucket='unavailable'",
            },
            "missing_epss": {
                "count": len(missing_epss),
                "cve_ids": missing_epss,
                "handling_policy": "Records with missing EPSS default to EPSS=0.0 with uncertainty flag",
            },
        },
        
        "data_lineage": {
            "steps": [
                "1. 39 real CVEs sourced from NVD (CVSS), FIRST (EPSS), CISA (KEV)",
                "2. 2 synthetic edge-case records created: CVE-2024-99991 (missing CVSS), CVE-2024-99992 (missing EPSS)",
                "3. Labels assigned via SSVC rubric traversal by authors",
                "4. Environment context (N, A) assigned via archetypal profiles",
                "5. Benchmark frozen at snapshot_date",
                "6. Manifest generated for reproducibility auditing",
            ]
        },
        
        "critical_disclaimers": [
            "Labels are AUTHOR-CURATED using SSVC rubric, NOT independently validated breach ground truth.",
            "Construct circularity: Reference labels use same features (KEV, EPSS, N) evaluated by VRS.",
            "High VRS performance reflects CONSTRUCT ALIGNMENT with SSVC rubric, not independent prediction.",
            "Environment context (N, A) are archetypal profiles, NOT organization-specific telemetry.",
            "EPSS is rolling 30-day forecast; subject to drift; exact values dependent on query date.",
            "KEV membership indicates unobserved in federal civilian reporting, NOT confirmed non-exploitation.",
            "Synthetic edge-case CVEs (CVE-2024-99991, CVE-2024-99992) are non-existent; for testing only.",
            "Independent analyst validation remains PENDING (future Experiment 2.1).",
        ],
    }
    
    return manifest


def save_manifest(manifest: Dict[str, Any], output_path: str) -> None:
    """Save manifest to JSON file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest saved to: {output_path}")


def load_manifest(manifest_path: str) -> Dict[str, Any]:
    """Load and parse manifest from JSON file."""
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_manifest(manifest: Dict[str, Any]) -> bool:
    """Validate manifest schema and content."""
    required_keys = ["metadata", "population", "feature_provenance", "label_provenance", 
                     "missing_data_inventory", "data_lineage", "critical_disclaimers"]
    
    for key in required_keys:
        if key not in manifest:
            raise ValueError(f"Missing required manifest key: {key}")
    
    # Validate population counts
    total = manifest["population"]["total_records"]
    real = manifest["population"]["real_cve_count"]
    synthetic = manifest["population"]["synthetic_cve_count"]
    
    if real + synthetic != total:
        raise ValueError(f"Population mismatch: {real} + {synthetic} != {total}")
    
    return True


if __name__ == "__main__":
    # Generate and save manifest for original benchmark
    csv_path = "data/benchmark/cves.csv"
    manifest_path = "data/benchmark/versions/cves_v1_manifest.json"
    
    manifest = generate_benchmark_manifest(csv_path)
    save_manifest(manifest, manifest_path)
    
    # Validate
    validate_manifest(manifest)
    print(f"Manifest validation passed.")
    print(f"Population: {manifest['population']['total_records']} total "
          f"({manifest['population']['real_cve_count']} real, "
          f"{manifest['population']['synthetic_cve_count']} synthetic)")
    print(f"Labels: {manifest['label_provenance']['distribution']}")
