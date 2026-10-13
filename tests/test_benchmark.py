"""
Unit Tests for Vulture-AI Benchmark Dataset Integrity
======================================================

Tests benchmark dataset constraints:
- Zero duplicate CVE identifiers
- Valid score ranges (CVSS [0, 10], EPSS [0, 1], exposure [0, 1], criticality [0, 1])
- CISA KEV binary flags ({0, 1})
- Missing-data edge cases (CVE-2024-99991 and CVE-2024-99992)
- Rejection of invalid inputs and duplicates
"""

import os
import pytest
from generate_data import (
    load_and_validate_benchmark,
    compute_benchmark_sha256,
    BENCHMARK_CSV_PATH,
    EXPECTED_BENCHMARK_COUNT,
)
from experiments.run_baselines import load_benchmark
from risk_engine import compute_vrs


def test_benchmark_file_exists():
    assert os.path.exists(BENCHMARK_CSV_PATH), f"Benchmark CSV not found at {BENCHMARK_CSV_PATH}"


def test_benchmark_validation_and_record_count():
    records, sha256_hash = load_and_validate_benchmark(BENCHMARK_CSV_PATH)
    assert len(records) == EXPECTED_BENCHMARK_COUNT == 41
    assert isinstance(sha256_hash, str)
    assert len(sha256_hash) == 64


def test_benchmark_no_duplicate_cve_ids():
    records, _ = load_and_validate_benchmark(BENCHMARK_CSV_PATH)
    cve_ids = [r["cve_id"] for r in records]
    assert len(cve_ids) == len(set(cve_ids)), "Duplicate CVE IDs found in benchmark!"


def test_benchmark_score_ranges():
    records, _ = load_and_validate_benchmark(BENCHMARK_CSV_PATH)
    for r in records:
        cve = r["cve_id"]
        # CVSS check
        cvss_str = r.get("cvss", "").strip()
        if cvss_str:
            cvss = float(cvss_str)
            assert 0.0 <= cvss <= 10.0, f"{cve}: CVSS out of bounds: {cvss}"

        # EPSS check
        epss_str = r.get("epss", "").strip()
        if epss_str:
            epss = float(epss_str)
            assert 0.0 <= epss <= 1.0, f"{cve}: EPSS out of bounds: {epss}"

        # KEV check
        assert r["kev"].strip() in {"0", "1"}, f"{cve}: Invalid KEV: {r['kev']}"

        # Exposure and Criticality
        exp = float(r["exposure"].strip())
        assert 0.0 <= exp <= 1.0, f"{cve}: Exposure out of bounds: {exp}"
        crit = float(r["asset_criticality"].strip())
        assert 0.0 <= crit <= 1.0, f"{cve}: Asset criticality out of bounds: {crit}"


def test_missing_data_edge_cases_handled():
    findings, ref_ranking, relevance_dict = load_benchmark(BENCHMARK_CSV_PATH)

    # 1. CVE-2024-99991: Missing CVSS
    f_missing_cvss = next((f for f in findings if f["cve_matches"][0]["cve_id"] == "CVE-2024-99991"), None)
    assert f_missing_cvss is not None, "CVE-2024-99991 not found in findings"
    assert f_missing_cvss["cve_matches"][0]["cvss_score"] is None
    res_cvss = compute_vrs(f_missing_cvss)
    assert res_cvss["vrs"] is None, "Missing CVSS should result in vrs=None"
    assert res_cvss["bucket"] == "unavailable", "Missing CVSS should result in bucket='unavailable'"

    # 2. CVE-2024-99992: Missing EPSS
    f_missing_epss = next((f for f in findings if f["cve_matches"][0]["cve_id"] == "CVE-2024-99992"), None)
    assert f_missing_epss is not None, "CVE-2024-99992 not found in findings"
    assert f_missing_epss["cve_matches"][0]["epss_probability"] is None
    res_epss = compute_vrs(f_missing_epss)
    assert res_epss["vrs"] is not None, "Missing EPSS should default to 0.0 and compute a VRS score"
    assert any("EPSS" in u for u in res_epss.get("uncertainties", []))


def test_validator_rejects_duplicate_cve(tmp_path):
    bad_csv = tmp_path / "bad.csv"
    bad_csv.write_text(
        "cve_id,cvss,epss,kev,exposure,asset_criticality,reference_priority,independent_label,source_timestamp,source_reference,description\n"
        "CVE-2021-44228,10.0,0.99,1,1.0,1.0,1,Act,2026-10-14T00:00:00Z,ref,Log4Shell\n"
        "CVE-2021-44228,9.8,0.95,1,1.0,1.0,2,Act,2026-10-14T00:00:00Z,ref,Duplicate Log4Shell\n"
    )
    with pytest.raises(ValueError, match="Duplicate cve_id detected"):
        load_and_validate_benchmark(str(bad_csv))


def test_validator_rejects_out_of_bounds_cvss(tmp_path):
    bad_csv = tmp_path / "bad_cvss.csv"
    bad_csv.write_text(
        "cve_id,cvss,epss,kev,exposure,asset_criticality,reference_priority,independent_label,source_timestamp,source_reference,description\n"
        "CVE-2021-44228,11.5,0.99,1,1.0,1.0,1,Act,2026-10-14T00:00:00Z,ref,Log4Shell\n"
    )
    with pytest.raises(ValueError, match="CVSS out of bounds"):
        load_and_validate_benchmark(str(bad_csv))
