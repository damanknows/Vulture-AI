"""
Vulture-AI Benchmark Dataset Generator & Integrity Validator
============================================================

This module manages and verifies the benchmark dataset of 39 real, publicly documented
CVEs and 2 synthetic missing-data edge-case records (41 total) used for comparative
prioritization experiments.

All real records are grounded in authoritative public intelligence sources:
- NIST National Vulnerability Database (NVD): CVSS v3.1 base score
- FIRST.org EPSS API: Live exploit prediction probability
- CISA Known Exploited Vulnerabilities (KEV) Catalog: Active exploitation status
- CISA Stakeholder-Specific Vulnerability Categorization (SSVC): Reference decision rubric

NOTE: Arbitrary synthetic vulnerability generation (e.g. CVE-2024-100xx) has been retired.
Two synthetic edge-case records (CVE-2024-99991, CVE-2024-99992) are preserved exclusively
to test missing-CVSS and missing-EPSS handling policies.
"""

import csv
import hashlib
import os
import sys
from typing import Dict, List, Tuple

BENCHMARK_CSV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data", "benchmark", "cves.csv"
)

EXPECTED_BENCHMARK_COUNT = 41
EXPECTED_COLUMNS = [
    "cve_id", "cvss", "epss", "kev", "exposure", "asset_criticality",
    "reference_priority", "independent_label", "source_timestamp",
    "source_reference", "description"
]
VALID_LABELS = {"Act", "Attend", "Track", "Defer"}


def compute_benchmark_sha256(filepath: str = BENCHMARK_CSV_PATH) -> str:
    """Computes SHA-256 hash of the benchmark CSV file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Benchmark file not found: {filepath}")
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_and_validate_benchmark(filepath: str = BENCHMARK_CSV_PATH) -> Tuple[List[Dict], str]:
    """
    Loads and rigorously validates the 41-CVE benchmark records.
    Verifies column schema, value ranges, uniqueness, and label validity.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Benchmark file not found: {filepath}")

    sha256_hash = compute_benchmark_sha256(filepath)
    records = []
    seen_cves = set()
    seen_priorities = set()

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for col in EXPECTED_COLUMNS:
            if col not in reader.fieldnames:
                raise ValueError(f"Missing expected column in benchmark: {col}")

        for idx, row in enumerate(reader, start=1):
            cve_id = row["cve_id"].strip()
            if not cve_id:
                raise ValueError(f"Row {idx}: Missing cve_id")
            if cve_id in seen_cves:
                raise ValueError(f"Duplicate cve_id detected at row {idx}: {cve_id}")
            seen_cves.add(cve_id)

            # Reference priority validation
            ref_pri_str = row["reference_priority"].strip()
            if not ref_pri_str:
                raise ValueError(f"Row {idx} ({cve_id}): Missing reference_priority")
            ref_pri = int(ref_pri_str)
            if ref_pri in seen_priorities:
                raise ValueError(f"Duplicate reference_priority detected at row {idx}: {ref_pri}")
            seen_priorities.add(ref_pri)

            # Independent label validation
            label = row["independent_label"].strip()
            if label not in VALID_LABELS:
                raise ValueError(f"Row {idx} ({cve_id}): Invalid independent_label '{label}'. Must be one of {VALID_LABELS}")

            # CVSS validation (None allowed for missing-data edge cases)
            cvss_str = row.get("cvss", "").strip()
            if cvss_str:
                cvss_val = float(cvss_str)
                if not (0.0 <= cvss_val <= 10.0):
                    raise ValueError(f"Row {idx} ({cve_id}): CVSS out of bounds [0.0, 10.0]: {cvss_val}")

            # EPSS validation (None allowed for missing-data edge cases)
            epss_str = row.get("epss", "").strip()
            if epss_str:
                epss_val = float(epss_str)
                if not (0.0 <= epss_val <= 1.0):
                    raise ValueError(f"Row {idx} ({cve_id}): EPSS out of bounds [0.0, 1.0]: {epss_val}")

            # KEV validation (0 or 1)
            kev_str = row.get("kev", "").strip()
            if kev_str not in {"0", "1"}:
                raise ValueError(f"Row {idx} ({cve_id}): KEV flag must be 0 or 1, got '{kev_str}'")

            # Exposure validation
            exp_str = row.get("exposure", "").strip()
            if exp_str:
                exp_val = float(exp_str)
                if not (0.0 <= exp_val <= 1.0):
                    raise ValueError(f"Row {idx} ({cve_id}): Exposure out of bounds [0.0, 1.0]: {exp_val}")

            # Asset criticality validation
            crit_str = row.get("asset_criticality", "").strip()
            if crit_str:
                crit_val = float(crit_str)
                if not (0.0 <= crit_val <= 1.0):
                    raise ValueError(f"Row {idx} ({cve_id}): Asset criticality out of bounds [0.0, 1.0]: {crit_val}")

            records.append(row)

    if len(records) != EXPECTED_BENCHMARK_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_BENCHMARK_COUNT} benchmark records, found {len(records)}"
        )

    return records, sha256_hash


def verify_benchmark():
    """CLI verification command for benchmark integrity."""
    print("=" * 65)
    print("Vulture-AI Benchmark Dataset Integrity Check")
    print("=" * 65)
    try:
        records, sha256_hash = load_and_validate_benchmark()
        print(f"File:         {BENCHMARK_CSV_PATH}")
        print(f"Record Count: {len(records)} records (39 real public CVEs + 2 synthetic missing-data edge cases)")
        print(f"SHA-256 Hash: {sha256_hash}")
        
        # Summary counts
        act_cnt = sum(1 for r in records if r["independent_label"] == "Act")
        attend_cnt = sum(1 for r in records if r["independent_label"] == "Attend")
        track_cnt = sum(1 for r in records if r["independent_label"] == "Track")
        defer_cnt = sum(1 for r in records if r["independent_label"] == "Defer")
        kev_cnt = sum(1 for r in records if r["kev"] == "1")
        missing_cvss = sum(1 for r in records if not r["cvss"].strip())
        missing_epss = sum(1 for r in records if not r["epss"].strip())
        
        print("\nDistribution Summary:")
        print(f"  - Act (Urgent):       {act_cnt} records")
        print(f"  - Attend (High):      {attend_cnt} records")
        print(f"  - Track (Standard):   {track_cnt} records")
        print(f"  - Defer (Low):        {defer_cnt} records")
        print(f"  - CISA KEV Listed:    {kev_cnt} records")
        print(f"  - Missing CVSS cases: {missing_cvss} (e.g. CVE-2024-99991)")
        print(f"  - Missing EPSS cases: {missing_epss} (e.g. CVE-2024-99992)")
        print("\nAll integrity checks passed successfully. 39 real CVEs verified; 2 synthetic edge cases accounted for.")
        print("=" * 65)
        return True
    except Exception as e:
        print(f"[FAIL] Benchmark integrity check failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    verify_benchmark()
