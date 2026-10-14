"""
Unit Tests for 500-CVE Expanded Benchmark and Evaluation Artifacts
===================================================================

Validates:
1. Preservation of original 41-record benchmark and checksum.
2. Structural integrity of cves_500.csv: exactly 500 unique real CVEs, 0 synthetic records.
3. Preservation of all 39 original real CVE records.
4. Numerical bounds on CVSS, EPSS, KEV, and asset criticality.
5. Scientific boundary on SSVC labels: exactly 39 labeled, 461 explicitly unlabeled.
6. Enriched dataset field semantics and concordance with CISA KEV catalog.
7. Manifest SHA-256 and metadata consistency.
8. Retrospective evaluation metric reproducibility.
"""

import os
import csv
import json
import re
import pytest

from experiments.enrich_benchmark_kev import compute_sha256

ORIGINAL_BENCHMARK_PATH = os.path.join("data", "benchmark", "cves.csv")
EXPECTED_ORIGINAL_SHA256 = "27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e"

BENCHMARK_500_PATH = os.path.join("data", "benchmark", "cves_500.csv")
ENRICHED_500_PATH = os.path.join("data", "benchmark", "cves_500_enriched.csv")
MANIFEST_500_PATH = os.path.join("data", "benchmark", "cves_500_manifest.json")
RESULTS_500_PATH = os.path.join("experiments", "results", "expanded_500_results.json")
TABLE_500_PATH = os.path.join("experiments", "results", "expanded_500_table.md")

SYNTHETIC_IDS = {"CVE-2024-99991", "CVE-2024-99992"}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def test_original_benchmark_preserved():
    """Ensure the original 41-record benchmark is completely intact."""
    assert os.path.exists(ORIGINAL_BENCHMARK_PATH), "Original benchmark missing"
    assert compute_sha256(ORIGINAL_BENCHMARK_PATH) == EXPECTED_ORIGINAL_SHA256, (
        "Original benchmark SHA-256 altered!"
    )
    with open(ORIGINAL_BENCHMARK_PATH, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 41, f"Expected 41 records, found {len(reader)}"


def test_benchmark_500_structure_and_uniqueness():
    """Verify cves_500.csv contains exactly 500 unique, valid real CVEs."""
    assert os.path.exists(BENCHMARK_500_PATH), f"Missing {BENCHMARK_500_PATH}"
    with open(BENCHMARK_500_PATH, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 500, f"Expected 500 records, got {len(reader)}"

        cve_ids = [row["cve_id"] for row in reader]
        assert len(set(cve_ids)) == 500, "Duplicate CVE IDs found in cves_500.csv"

        for cid in cve_ids:
            assert CVE_PATTERN.match(cid), f"Malformed CVE ID: {cid}"
            assert cid not in SYNTHETIC_IDS, f"Synthetic ID leaked into benchmark: {cid}"


def test_preservation_of_all_original_real_cves():
    """Verify that all 39 real CVEs from original benchmark are preserved in 500 corpus."""
    with open(ORIGINAL_BENCHMARK_PATH, "r", encoding="utf-8") as f:
        orig_reader = list(csv.DictReader(f))
        orig_real = {r["cve_id"] for r in orig_reader if r["cve_id"] not in SYNTHETIC_IDS}
        assert len(orig_real) == 39

    with open(BENCHMARK_500_PATH, "r", encoding="utf-8") as f:
        bench_500 = {r["cve_id"] for r in csv.DictReader(f)}

    missing_real = orig_real - bench_500
    assert not missing_real, f"Original real CVEs missing from 500 benchmark: {missing_real}"


def test_feature_ranges_and_validity():
    """Verify CVSS, EPSS, KEV, exposure, and asset criticality are within legitimate bounds."""
    with open(BENCHMARK_500_PATH, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    for row in reader:
        cid = row["cve_id"]
        cvss = float(row["cvss"])
        assert 0.0 <= cvss <= 10.0, f"CVSS out of bounds for {cid}: {cvss}"

        epss = float(row["epss"])
        assert 0.0 <= epss <= 1.0, f"EPSS out of bounds for {cid}: {epss}"

        kev = int(row["kev"])
        assert kev in (0, 1), f"KEV status must be 0 or 1 for {cid}: {kev}"

        exp = float(row["exposure"])
        assert 0.0 <= exp <= 1.0, f"Exposure out of bounds for {cid}: {exp}"

        crit = float(row["asset_criticality"])
        assert 0.0 <= crit <= 1.0, f"Asset criticality out of bounds for {cid}: {crit}"


def test_label_boundary_integrity():
    """Verify strictly 39 records have author-curated reference labels; 461 must be explicitly unlabeled."""
    with open(BENCHMARK_500_PATH, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    labeled = [r for r in reader if r.get("independent_label") and r["independent_label"] != "unlabeled"]
    unlabeled = [r for r in reader if r.get("independent_label") == "unlabeled"]

    assert len(labeled) == 39, f"Expected exactly 39 SSVC labeled records, got {len(labeled)}"
    assert len(unlabeled) == 461, f"Expected exactly 461 unlabeled records, got {len(unlabeled)}"


def test_enriched_500_integrity_and_kev_concordance():
    """Verify cves_500_enriched.csv matches base CSV and validates KEV semantics."""
    assert os.path.exists(ENRICHED_500_PATH), f"Missing {ENRICHED_500_PATH}"
    with open(ENRICHED_500_PATH, "r", encoding="utf-8") as f:
        enriched_rows = list(csv.DictReader(f))

    assert len(enriched_rows) == 500

    kev_listed_count = 0
    date_regex = re.compile(r"^\d{4}-\d{2}-\d{2}$")

    for row in enriched_rows:
        cid = row["cve_id"]
        is_listed = row["cisa_kev_listed"].strip().lower() == "true"

        if is_listed:
            kev_listed_count += 1
            assert date_regex.match(row["cisa_kev_date_added"]), (
                f"Invalid date_added for {cid}: {row['cisa_kev_date_added']}"
            )
            assert row["cisa_kev_source_url"].startswith("http"), (
                f"Invalid source_url for {cid}: {row['cisa_kev_source_url']}"
            )
        else:
            assert row["cisa_kev_date_added"] == ""

        # For newly sampled records (unlabeled), kev strictly mirrors cisa_kev_listed
        if row.get("independent_label") == "unlabeled":
            expected_kev = 1 if is_listed else 0
            assert int(row["kev"]) == expected_kev, f"Mismatch in kev for new CVE {cid}"

    assert kev_listed_count == 25, f"Expected 25 KEV listed CVEs in 500 corpus, got {kev_listed_count}"


def test_manifest_consistency():
    """Verify manifest records match actual disk hashes and metadata."""
    assert os.path.exists(MANIFEST_500_PATH), f"Missing {MANIFEST_500_PATH}"
    with open(MANIFEST_500_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Check disk hashes match manifest
    actual_base_hash = compute_sha256(BENCHMARK_500_PATH)
    actual_enriched_hash = compute_sha256(ENRICHED_500_PATH)
    actual_orig_hash = compute_sha256(ORIGINAL_BENCHMARK_PATH)

    assert manifest["artifacts"]["base_csv"]["sha256"] == actual_base_hash
    assert manifest["artifacts"]["enriched_csv"]["sha256"] == actual_enriched_hash
    assert manifest["artifacts"]["original_benchmark_preserved"]["sha256"] == actual_orig_hash

    pop = manifest["population_summary"]
    assert pop["total_records"] == 500
    assert pop["unique_cve_ids_count"] == 500
    assert pop["synthetic_records_count"] == 0
    assert pop["preserved_original_real_cves"] == 39
    assert pop["newly_sampled_real_cves"] == 461
    assert pop["cisa_kev_listed_count"] == 25
    assert pop["ssvc_labeled_count"] == 39
    assert pop["unlabeled_count"] == 461


def test_results_and_table_integrity():
    """Verify experiment outputs exist and match expected research metrics."""
    assert os.path.exists(RESULTS_500_PATH), f"Missing {RESULTS_500_PATH}"
    assert os.path.exists(TABLE_500_PATH), f"Missing {TABLE_500_PATH}"

    with open(RESULTS_500_PATH, "r", encoding="utf-8") as f:
        res = json.load(f)

    metrics = res["multi_cutoff_metrics"]
    assert "CVSS-only" in metrics
    assert "EPSS-only" in metrics
    assert "VRS Proposed (vrs-v1)" in metrics

    # CVSS achieves 11/25 = 0.44 recall at depth 25
    assert metrics["CVSS-only"]["hits@25"] == 11
    assert abs(metrics["CVSS-only"]["R@25"] - 0.4400) < 1e-4

    # EPSS achieves 22/25 = 0.88 recall at depth 25
    assert metrics["EPSS-only"]["hits@25"] == 22
    assert abs(metrics["EPSS-only"]["R@25"] - 0.8800) < 1e-4

    # VRS achieves 25/25 = 1.0 recall at depth 25
    assert metrics["VRS Proposed (vrs-v1)"]["hits@25"] == 25
    assert abs(metrics["VRS Proposed (vrs-v1)"]["R@25"] - 1.0000) < 1e-4
