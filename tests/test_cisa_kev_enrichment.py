"""
Unit Tests for CISA KEV Benchmark Enrichment and Telemetry Integrity
=====================================================================

Validates:
1. Exact matching of real CVEs against CISA KEV catalog.
2. Proper handling of unlisted CVEs (unknown/not-listed != confirmed non-exploitation).
3. Explicit marking and exclusion of synthetic records (CVE-2024-99991, CVE-2024-99992).
4. Rejection of duplicate CVE identifiers.
5. Handling of missing values in enrichment columns and legacy missing-data edge cases.
6. Ranking integrity: duplicate detection, synthetic ID rejection, population consistency.
7. Short and empty ranking rejection for precision@k and recall@k.
8. Catalog metadata validation and corrupted/stale catalog handling.
9. Correct semantic mapping of notes, vulnerabilityName, and genuine source URLs.
10. Separation and denominator consistency of precision@k and recall@k.
11. Provenance metadata and checksum verification across files.
12. Retrospective report concordance.
"""

import os
import csv
import json
import re
import pytest
from experiments.enrich_benchmark_kev import (
    compute_sha256,
    extract_source_url,
    load_kev_catalog,
    validate_ranking,
    validate_consistent_populations,
    calculate_precision_at_k,
    calculate_recall_at_k,
    BENCHMARK_PATH,
    ENRICHED_PATH,
    PROVENANCE_PATH,
    KEV_CATALOG_PATH,
    RETROSPECTIVE_TABLE_PATH,
    EXPECTED_BENCHMARK_SHA256,
    SYNTHETIC_IDS,
)


def load_enriched_csv():
    assert os.path.exists(ENRICHED_PATH), f"Enriched benchmark not found at {ENRICHED_PATH}"
    with open(ENRICHED_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader), reader.fieldnames


# =============================================================================
# 1. Benchmark & Enriched Dataset Integrity Tests
# =============================================================================

def test_source_benchmark_checksum_unaltered():
    """Ensure original benchmark CSV was not modified."""
    assert os.path.exists(BENCHMARK_PATH), f"Benchmark source missing: {BENCHMARK_PATH}"
    actual_sha256 = compute_sha256(BENCHMARK_PATH)
    assert actual_sha256 == EXPECTED_BENCHMARK_SHA256, (
        f"Original benchmark checksum altered! Expected {EXPECTED_BENCHMARK_SHA256}, got {actual_sha256}"
    )


def test_enriched_benchmark_structure_and_row_count():
    """Verify enriched CSV has exactly 41 rows and includes all required fields."""
    rows, fieldnames = load_enriched_csv()
    assert len(rows) == 41, f"Expected 41 records, found {len(rows)}"

    required_fields = [
        "cve_id",
        "cvss",
        "epss",
        "kev",
        "exposure",
        "asset_criticality",
        "reference_priority",
        "independent_label",
        "is_synthetic",
        "cisa_kev_listed",
        "cisa_kev_status",
        "cisa_kev_date_added",
        "cisa_kev_due_date",
        "cisa_kev_required_action",
        "cisa_kev_source_url",
        "cisa_kev_vulnerability_name",
        "cisa_kev_notes",
    ]
    for rf in required_fields:
        assert rf in fieldnames, f"Missing required column in enriched CSV: {rf}"


def test_enriched_benchmark_no_duplicate_cve_ids():
    """Verify zero duplicate CVE IDs in the enriched benchmark."""
    rows, _ = load_enriched_csv()
    cve_ids = [r["cve_id"].strip() for r in rows]
    duplicates = [cid for cid in cve_ids if cve_ids.count(cid) > 1]
    assert len(cve_ids) == len(set(cve_ids)), f"Duplicate CVE IDs found: {set(duplicates)}"


def test_exact_kev_matching_known_positives():
    """Verify exact matching of verified KEV entries against known ground-truth details."""
    rows, _ = load_enriched_csv()
    row_map = {r["cve_id"].strip(): r for r in rows}

    # Log4Shell (CVE-2021-44228)
    log4j = row_map.get("CVE-2021-44228")
    assert log4j is not None
    assert log4j["is_synthetic"] == "False"
    assert log4j["cisa_kev_listed"] == "True"
    assert log4j["cisa_kev_status"] == "listed"
    assert log4j["cisa_kev_date_added"] == "2021-12-10"
    assert log4j["cisa_kev_due_date"] == "2021-12-24"
    assert "Apply updates" in log4j["cisa_kev_required_action"]
    assert log4j["cisa_kev_vulnerability_name"] == "Apache Log4j2 Remote Code Execution Vulnerability"

    # MOVEit (CVE-2023-34362)
    moveit = row_map.get("CVE-2023-34362")
    assert moveit is not None
    assert moveit["cisa_kev_listed"] == "True"
    assert moveit["cisa_kev_date_added"] == "2023-06-02"
    assert moveit["cisa_kev_due_date"] == "2023-06-23"
    assert moveit["cisa_kev_vulnerability_name"] == "Progress MOVEit Transfer SQL Injection Vulnerability"

    # ScreenConnect (CVE-2024-1709)
    screenconnect = row_map.get("CVE-2024-1709")
    assert screenconnect is not None
    assert screenconnect["cisa_kev_listed"] == "True"
    assert screenconnect["cisa_kev_date_added"] == "2024-02-22"
    assert screenconnect["cisa_kev_due_date"] == "2024-02-29"

    # Cisco IOS XE (CVE-2023-20198)
    cisco = row_map.get("CVE-2023-20198")
    assert cisco is not None
    assert cisco["cisa_kev_listed"] == "True"
    assert cisco["cisa_kev_date_added"] == "2023-10-16"


# =============================================================================
# 2. Field Semantics & Mapping Tests
# =============================================================================

def test_correct_mapping_of_notes_vulnname_and_source_url():
    """
    Verify field semantics:
    - cisa_kev_source_url must be a genuine, validated HTTP/HTTPS URL (no prose sentences).
    - cisa_kev_vulnerability_name contains the official vulnerability name.
    - cisa_kev_notes preserves raw vendor and remediation notes.
    """
    rows, _ = load_enriched_csv()
    for r in rows:
        cid = r["cve_id"].strip()
        status = r["cisa_kev_status"]

        if status == "listed":
            url = r["cisa_kev_source_url"]
            # Genuine URL check
            assert url.startswith(("http://", "https://")), f"{cid}: Invalid source URL '{url}'"
            assert ";" not in url, f"{cid}: Raw unparsed semicolon in source URL: '{url}'"
            assert " " not in url, f"{cid}: Whitespace in source URL: '{url}'"
            assert not url.startswith("This CVE"), f"{cid}: Notes prose leaked into source URL"

            # Vulnerability Name check
            vuln_name = r["cisa_kev_vulnerability_name"]
            assert len(vuln_name) > 0, f"{cid}: Missing vulnerability name"
            assert not vuln_name.startswith("http"), f"{cid}: URL placed in vulnerability name"

            # Notes check
            raw_notes = r["cisa_kev_notes"]
            assert len(raw_notes) > 0, f"{cid}: Missing raw notes"


def test_extract_source_url_helper():
    """Unit test for extract_source_url logic across various note formats."""
    # Case 1: Single direct URL
    url1 = extract_source_url("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "CVE-2021-44228")
    assert url1 == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"

    # Case 2: Semicolon-delimited list of URLs
    notes2 = "https://example.com/advisory1; https://nvd.nist.gov/vuln/detail/CVE-2024-1709"
    url2 = extract_source_url(notes2, "CVE-2024-1709")
    assert url2 == "https://example.com/advisory1"

    # Case 3: Embedded URL with prose containing CISA advisory
    notes3 = "This CVE has a CISA AA located here: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a. Please see AA for IOCs."
    url3 = extract_source_url(notes3, "CVE-2023-34362")
    assert url3 == "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"

    # Case 4: Empty or non-URL string
    assert extract_source_url("", "CVE-TEST") == ""
    assert extract_source_url("No URL available for this record.", "CVE-TEST") == ""


# =============================================================================
# 3. Unlisted and Synthetic Records Handling Tests
# =============================================================================

def test_unlisted_cve_handling_not_negative_ground_truth():
    """
    Verify that CVEs not present in CISA KEV are designated as 'not_listed_or_unknown',
    and NOT marked as confirmed non-exploitation or negative ground truth.
    """
    rows, _ = load_enriched_csv()
    row_map = {r["cve_id"].strip(): r for r in rows}

    # CVE-2024-3094 (XZ backdoor - supply chain incident, not in CISA KEV)
    xz = row_map.get("CVE-2024-3094")
    assert xz is not None
    assert xz["is_synthetic"] == "False"
    assert xz["cisa_kev_listed"] == "False"
    assert xz["cisa_kev_status"] == "not_listed_or_unknown"
    assert xz["cisa_kev_status"] != "not_exploited"
    assert "NOT confirmed non-exploitation" in xz["cisa_kev_notes"]
    assert xz["cisa_kev_source_url"] == ""

    # OpenSSH timing oracle (CVE-2018-15473)
    ssh = row_map.get("CVE-2018-15473")
    assert ssh is not None
    assert ssh["cisa_kev_listed"] == "False"
    assert ssh["cisa_kev_status"] == "not_listed_or_unknown"
    assert "NOT confirmed non-exploitation" in ssh["cisa_kev_notes"]


def test_synthetic_records_marked_and_excluded():
    """Verify synthetic edge cases are explicitly flagged and excluded from real KEV outcomes."""
    rows, _ = load_enriched_csv()
    row_map = {r["cve_id"].strip(): r for r in rows}

    for syn_id in SYNTHETIC_IDS:
        rec = row_map.get(syn_id)
        assert rec is not None, f"Synthetic ID {syn_id} not found in enriched CSV"
        assert rec["is_synthetic"] == "True"
        assert rec["cisa_kev_status"] == "synthetic_excluded"
        assert rec["cisa_kev_listed"] == "N/A (synthetic)"
        assert "SYNTHETIC" in rec["cisa_kev_notes"]
        assert rec["cisa_kev_vulnerability_name"] == "SYNTHETIC TEST CASE"
        assert rec["cisa_kev_source_url"] == ""
        assert rec["cisa_kev_date_added"] == ""
        assert rec["cisa_kev_due_date"] == ""


def test_missing_values_handled_gracefully():
    """Verify missing values in both base and enriched columns do not cause issues."""
    rows, _ = load_enriched_csv()
    row_map = {r["cve_id"].strip(): r for r in rows}

    # CVE-2024-99991: missing CVSS
    rec1 = row_map["CVE-2024-99991"]
    assert rec1["cvss"] == ""

    # CVE-2024-99992: missing EPSS
    rec2 = row_map["CVE-2024-99992"]
    assert rec2["epss"] == ""

    # Unlisted CVEs must have empty date_added, due_date, required_action, source_url
    for r in rows:
        if r["cisa_kev_status"] == "not_listed_or_unknown":
            assert r["cisa_kev_date_added"] == ""
            assert r["cisa_kev_due_date"] == ""
            assert r["cisa_kev_required_action"] == ""
            assert r["cisa_kev_source_url"] == ""
        elif r["cisa_kev_status"] == "listed":
            assert re.match(r"^\d{4}-\d{2}-\d{2}$", r["cisa_kev_date_added"])
            assert re.match(r"^\d{4}-\d{2}-\d{2}$", r["cisa_kev_due_date"])
            assert len(r["cisa_kev_required_action"]) > 0


# =============================================================================
# 4. Ranking Integrity & Validation Tests
# =============================================================================

def test_duplicate_ids_in_ranking_raises_error():
    """Ensure validate_ranking detects and rejects rankings with duplicate identifiers."""
    eligible = {"CVE-2021-44228", "CVE-2023-34362"}
    dup_ranking = ["CVE-2021-44228", "CVE-2021-44228"]
    with pytest.raises(ValueError, match="Duplicate IDs detected"):
        validate_ranking(dup_ranking, eligible, ranking_name="test_duplicates")


def test_short_and_empty_rankings_handled():
    """Ensure validate_ranking, precision@k, and recall@k reject empty or short rankings."""
    eligible = {"CVE-2021-44228", "CVE-2023-34362"}

    # 1. Empty ranking in validate_ranking
    with pytest.raises(ValueError, match="is empty"):
        validate_ranking([], eligible, ranking_name="test_empty")

    # 2. Short ranking in calculate_precision_at_k
    short_ranking = ["CVE-2021-44228", "CVE-2023-34362", "CVE-2024-1709"]
    positive_set = {"CVE-2021-44228"}
    with pytest.raises(ValueError, match="less than k=5"):
        calculate_precision_at_k(short_ranking, positive_set, k=5)

    # 3. Short ranking in calculate_recall_at_k
    with pytest.raises(ValueError, match="less than k=5"):
        calculate_recall_at_k(short_ranking, positive_set, total_positives=1, k=5)

    # 4. Invalid cutoff k <= 0
    with pytest.raises(ValueError, match="Cutoff k must be positive"):
        calculate_precision_at_k(short_ranking, positive_set, k=0)


def test_synthetic_ids_appearing_in_eligible_ranking_raises_error():
    """Ensure validate_ranking rejects rankings containing synthetic test cases."""
    eligible = {"CVE-2021-44228", "CVE-2023-34362"}
    ranking_with_synthetic = ["CVE-2021-44228", "CVE-2024-99991"]
    with pytest.raises(ValueError, match="Synthetic IDs detected"):
        validate_ranking(ranking_with_synthetic, eligible, ranking_name="test_synthetic")


def test_ranking_methods_using_inconsistent_populations_raises_error():
    """Ensure validate_consistent_populations detects population mismatches between methods."""
    eligible = {"CVE-2021-44228", "CVE-2023-34362"}
    valid_rk1 = ["CVE-2021-44228", "CVE-2023-34362"]
    valid_rk2 = ["CVE-2023-34362", "CVE-2021-44228"]
    mismatched_rk = ["CVE-2021-44228", "CVE-2024-1709"]

    # Valid consistent dictionary
    validate_consistent_populations({"m1": valid_rk1, "m2": valid_rk2}, eligible)

    # Inconsistent dictionary
    with pytest.raises(ValueError, match="Population mismatch"):
        validate_consistent_populations({"m1": valid_rk1, "m2": mismatched_rk}, eligible)


def test_catalog_metadata_validation(tmp_path):
    """Ensure load_kev_catalog detects corrupted JSON and missing required top-level metadata."""
    # 1. Non-existent file
    with pytest.raises(FileNotFoundError):
        load_kev_catalog(str(tmp_path / "nonexistent.json"))

    # 2. Corrupted JSON
    corrupted_file = tmp_path / "corrupted.json"
    corrupted_file.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupted or invalid JSON"):
        load_kev_catalog(str(corrupted_file))

    # 3. Missing required top-level key
    missing_key_file = tmp_path / "missing_key.json"
    missing_key_file.write_text(
        json.dumps({"title": "CISA KEV", "catalogVersion": "1.0", "vulnerabilities": []}),
        encoding="utf-8"
    )
    with pytest.raises(KeyError, match="missing required top-level metadata"):
        load_kev_catalog(str(missing_key_file))


def test_consistency_of_precision_and_recall_denominators():
    """
    Verify mathematical separation and denominator consistency between Precision and Recall.
    Precision@k denominator must be k.
    Recall@k denominator must be total_positives (N_KEV_eligible = 25).
    """
    ranking = [f"CVE-{i}" for i in range(1, 16)]  # 15 items
    positives = {f"CVE-{i}" for i in range(1, 11)}  # 10 positive items
    total_positives = 25  # Denominator for recall

    # At k = 5: hits = 5
    p5 = calculate_precision_at_k(ranking, positives, 5)
    r5 = calculate_recall_at_k(ranking, positives, total_positives, 5)
    assert p5 == 5 / 5.0 == 1.0
    assert r5 == 5 / 25.0 == 0.20

    # At k = 10: hits = 10
    p10 = calculate_precision_at_k(ranking, positives, 10)
    r10 = calculate_recall_at_k(ranking, positives, total_positives, 10)
    assert p10 == 10 / 10.0 == 1.0
    assert r10 == 10 / 25.0 == 0.40

    # At k = 15: hits = 10 (items 11-15 are negative)
    p15 = calculate_precision_at_k(ranking, positives, 15)
    r15 = calculate_recall_at_k(ranking, positives, total_positives, 15)
    assert p15 == 10 / 15.0  # 0.6667
    assert r15 == 10 / 25.0 == 0.40

    # Confirm Precision and Recall are mathematically distinct
    assert p15 != r15


# =============================================================================
# 5. Provenance & Retrospective Report Tests
# =============================================================================

def test_provenance_json_integrity():
    """Verify provenance metadata, catalog SHA-256, runtime timestamps, and matching statistics."""
    assert os.path.exists(PROVENANCE_PATH), f"Provenance file missing: {PROVENANCE_PATH}"
    with open(PROVENANCE_PATH, "r", encoding="utf-8") as f:
        prov = json.load(f)

    # 1. Processing timestamp (runtime UTC)
    assert "processing_timestamp_utc" in prov["metadata"]
    assert "T" in prov["metadata"]["processing_timestamp_utc"]

    # 2. Local cache timestamp and source mode
    feed = prov["cisa_kev_feed"]
    assert feed["source_mode"] == "cached_local_file"
    assert "local_cache_modified_utc" in feed
    assert feed["official_feed_url"].startswith("https://")

    # 3. Benchmark source
    assert prov["benchmark_source"]["record_count"] == 41
    assert prov["benchmark_source"]["identifier_column"] == "cve_id"
    assert prov["benchmark_source"]["sha256_checksum"] == EXPECTED_BENCHMARK_SHA256

    # 4. Enriched benchmark
    assert prov["enriched_benchmark"]["record_count"] == 41
    actual_enriched_sha = compute_sha256(ENRICHED_PATH)
    assert prov["enriched_benchmark"]["sha256_checksum"] == actual_enriched_sha
    assert "field_semantics" in prov["enriched_benchmark"]
    assert "cisa_kev_source_url" in prov["enriched_benchmark"]["field_semantics"]
    assert "cisa_kev_vulnerability_name" in prov["enriched_benchmark"]["field_semantics"]

    # 5. KEV Feed catalog
    assert os.path.exists(KEV_CATALOG_PATH), f"Local KEV cache missing: {KEV_CATALOG_PATH}"
    actual_catalog_sha = compute_sha256(KEV_CATALOG_PATH)
    assert prov["cisa_kev_feed"]["sha256_checksum"] == actual_catalog_sha
    assert prov["cisa_kev_feed"]["catalog_vulnerabilities_count"] == 1741
    assert prov["cisa_kev_feed"]["catalog_version"] == "2026.10.13"

    # 6. Matching counts
    stats = prov["matching_statistics"]
    assert stats["total_benchmark_records"] == 41
    assert stats["real_cve_records"] == 39
    assert stats["synthetic_records_count"] == 2
    assert stats["real_matched_in_cisa_kev"] == 25
    assert stats["real_unmatched_in_cisa_kev"] == 14
    assert stats["real_matched_in_cisa_kev"] + stats["real_unmatched_in_cisa_kev"] == 39
    assert len(stats["matched_cve_ids"]) == 25
    assert len(stats["unmatched_cve_ids"]) == 14
    assert len(stats["synthetic_cve_ids"]) == 2

    # 7. Disclaimers present
    disclaimers = prov["scientific_disclaimers"]
    assert "retrospective concordance study" in disclaimers["retrospective_nature"]
    assert "information_overlap_disclosure" in disclaimers
    assert "MUST NOT be interpreted as confirmed non-exploitation" in disclaimers["catalog_absence_interpretation"]
    assert "MUST NOT be interpreted as the date of first weaponization" in disclaimers["catalog_date_interpretation"]
    assert "strictly to test missing-data" in disclaimers["synthetic_records_policy"]


def test_retrospective_comparison_file():
    """Verify retrospective summary markdown file is generated and contains top-15 precision and recall."""
    assert os.path.exists(RETROSPECTIVE_TABLE_PATH), f"Missing retrospective table at {RETROSPECTIVE_TABLE_PATH}"
    with open(RETROSPECTIVE_TABLE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Derived metadata and checksum
    assert "Catalog SHA-256" in content
    assert "136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28" in content
    assert "Processing Timestamp (UTC)" in content

    # Metrics
    assert "Top-15 Retrospective Precision" in content
    assert "15/15 (100.0%)" in content
    assert "Top-15 Retrospective Recall" in content
    assert "15/25 (60.0%)" in content

    # Disclaimers
    assert "Retrospective Association vs. Temporal Prediction" in content
    assert "Information Overlap / Feature Leakage Disclosure" in content
    assert "Catalog Absence != Confirmed Non-Exploitation" in content
    assert "Catalog Date != First Exploitation Date" in content
    assert "Sample Size & Curated Benchmark Limitations ($N=41$)" in content
