"""
Automated Temporal-Leakage, CVSS-Reconstruction, and Tie-Aware Metric Tests for TEOB
====================================================================================
"""

import csv
import json
import math
from datetime import date, timedelta
from pathlib import Path

import pytest

from experiments.build_temporal_benchmark import (
    CUTOFF_DATE,
    HORIZON_DAYS,
    OUT_CSV,
    build_temporal_benchmark,
    compute_cvss_v3_base_from_vector,
    resolve_cvss_as_of_cutoff,
)
from experiments.evaluate_temporal import (
    compute_unrounded_scores,
    evaluate_teob,
    tie_aware_average_precision,
    tie_aware_ndcg_at_k,
    tie_aware_precision_at_k,
    tie_aware_recall_at_k,
)


def _make_v31_metric(mtype: str, source: str, vector: str, score: float) -> dict:
    return {
        "type": mtype,
        "source": source,
        "cvssData": {"vectorString": f"CVSS:3.1/{vector}", "baseScore": score},
    }


def _write_mini_caches(
    tmp_path: Path,
    vulns: list,
    history: dict,
    epss_data: dict,
    kev_vulns: list,
    kev_released: str = "2026-10-13T19:10:43.6568Z",
    nvd_retrieved: str = "2026-11-26T21:32:00Z",
    hist_retrieved: str = "2026-11-26T21:51:46Z",
):
    nvd_p = tmp_path / "nvd.json"
    hist_p = tmp_path / "hist.json"
    epss_p = tmp_path / "epss.json"
    kev_p = tmp_path / "kev.json"
    out_csv = tmp_path / "teob.csv"
    out_man = tmp_path / "manifest.json"

    nvd_p.write_text(json.dumps({"retrieved_utc": nvd_retrieved, "vulnerabilities": vulns}), encoding="utf-8")
    hist_p.write_text(json.dumps({"retrieved_utc": hist_retrieved, "cvss_changes": history}), encoding="utf-8")
    epss_p.write_text(json.dumps({"date": "2026-07-01", "data": epss_data}), encoding="utf-8")
    kev_p.write_text(
        json.dumps({"catalogVersion": "2026.10.13", "dateReleased": kev_released, "vulnerabilities": kev_vulns}),
        encoding="utf-8",
    )
    return nvd_p, hist_p, epss_p, kev_p, out_csv, out_man


def test_cvss_vector_reconstruction_matches_known_vector():
    assert compute_cvss_v3_base_from_vector("NIST AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert compute_cvss_v3_base_from_vector("NIST AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 7.8


def test_cvss_primary_vs_secondary_preserves_pre_cutoff_secondary():
    # Secondary (CNA) existed at publication; Primary (NVD) was Added after cutoff.
    cve_obj = {
        "lastModified": "2026-07-13T19:02:39.860",
        "metrics": {
            "cvssMetricV31": [
                _make_v31_metric("Secondary", "cna@vendor.com", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
                _make_v31_metric("Primary", "nvd@nist.gov", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ]
        },
    }
    history = [
        {
            "created": "2026-07-13T19:02:39.860",
            "eventName": "Initial Analysis",
            "action": "Added",
            "type": "CVSS V3.1",
            "oldValue": "",
            "newValue": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ]
    score, status, vec, src = resolve_cvss_as_of_cutoff(cve_obj, history, cutoff_date="2026-07-01")
    assert score == 9.1
    assert status == "reconstructed_from_cvehistory"
    assert vec == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    assert src.startswith("Secondary:")


def test_cvss_changes_before_at_and_after_cutoff():
    vec_pre = "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # 7.8
    vec_post = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8

    # Before cutoff (< 2026-07-01T00:00:00Z)
    cve_pre = {
        "lastModified": "2026-06-30T23:59:59.000",
        "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec_pre, 7.8)]},
    }
    s_pre, st_pre, _, _ = resolve_cvss_as_of_cutoff(cve_pre, [], cutoff_date="2026-07-01")
    assert s_pre == 7.8
    assert st_pre == "unchanged_since_cutoff"

    # Exactly at cutoff (2026-07-01T00:00:00Z) -> must be undone
    cve_at = {
        "lastModified": "2026-07-01T00:00:00.000",
        "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec_post, 9.8)]},
    }
    hist_at = [
        {"created": "2026-07-01T00:00:00.000", "eventName": "Initial Analysis", "action": "Added", "type": "CVSS V3.1", "oldValue": "", "newValue": vec_post}
    ]
    s_at, st_at, _, _ = resolve_cvss_as_of_cutoff(cve_at, hist_at, cutoff_date="2026-07-01")
    assert s_at is None
    assert st_at == "added_after_cutoff_excluded"

    # After cutoff via NVD Added + Removed pair
    cve_pair = {
        "lastModified": "2026-07-07T23:16:55.650",
        "metrics": {"cvssMetricV31": [_make_v31_metric("Secondary", "cna@x", vec_post, 9.8)]},
    }
    hist_pair = [
        {"created": "2026-07-07T23:16:55.650", "eventName": "CVE Modified", "action": "Added", "type": "CVSS V3.1", "oldValue": "", "newValue": vec_post},
        {"created": "2026-07-07T23:16:55.650", "eventName": "CVE Modified", "action": "Removed", "type": "CVSS V3.1", "oldValue": vec_pre, "newValue": ""},
    ]
    s_pair, st_pair, _, _ = resolve_cvss_as_of_cutoff(cve_pair, hist_pair, cutoff_date="2026-07-01")
    assert s_pair == 7.8
    assert st_pair == "reconstructed_from_cvehistory"


def test_timezone_boundary_and_midnight_cutoff():
    vec = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    # 2026-07-01T02:00:00+05:30 == 2026-06-30T20:30:00Z (strictly pre-cutoff)
    cve_ist = {
        "lastModified": "2026-07-01T02:00:00+05:30",
        "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec, 9.8)]},
    }
    s_ist, st_ist, _, _ = resolve_cvss_as_of_cutoff(cve_ist, [], cutoff_date="2026-07-01")
    assert s_ist == 9.8
    assert st_ist == "unchanged_since_cutoff"

    # 2026-07-01T02:16:49Z is post-cutoff -> must be excluded if Added then
    cve_utc = {
        "lastModified": "2026-07-01T02:16:49.000",
        "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec, 9.8)]},
    }
    hist_utc = [
        {"created": "2026-07-01T02:16:49.000", "eventName": "Initial Analysis", "action": "Added", "type": "CVSS V3.1", "oldValue": "", "newValue": vec}
    ]
    s_utc, st_utc, _, _ = resolve_cvss_as_of_cutoff(cve_utc, hist_utc, cutoff_date="2026-07-01")
    assert s_utc is None
    assert st_utc == "added_after_cutoff_excluded"


def test_builder_cohort_boundaries_duplicates_missing_features_and_horizon(tmp_path: Path):
    vec = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vulns = [
        # Eligible, KEV at start of window (2026-07-02) -> positive
        {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Analyzed", "published": "2026-06-30T23:59:59.000", "lastModified": "2026-06-30T23:59:59.000", "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec, 9.8)]}}},
        # Duplicate CVE-2026-0001 -> must be deduplicated
        {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Analyzed", "published": "2026-06-30T23:59:59.000", "lastModified": "2026-06-30T23:59:59.000", "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec, 9.8)]}}},
        # Eligible, KEV at end of window (2026-09-29) -> positive, missing CVSS, wrong EPSS date ignored
        {"cve": {"id": "CVE-2026-0002", "vulnStatus": "Deferred", "published": "2026-06-15T12:00:00.000", "lastModified": "2026-06-15T12:00:00.000", "metrics": {}}},
        # Eligible, KEV after window (2026-09-30) -> negative
        {"cve": {"id": "CVE-2026-0003", "vulnStatus": "Analyzed", "published": "2026-06-10T00:00:00.000", "lastModified": "2026-06-10T00:00:00.000", "metrics": {"cvssMetricV31": [_make_v31_metric("Primary", "nvd@nist.gov", vec, 9.8)]}}},
        # Excluded: KEV exactly at cutoff (2026-07-01)
        {"cve": {"id": "CVE-2026-0004", "vulnStatus": "Analyzed", "published": "2026-06-05T00:00:00.000", "lastModified": "2026-06-05T00:00:00.000", "metrics": {}}},
        # Excluded: Published at cutoff midnight (2026-07-01T00:00:00)
        {"cve": {"id": "CVE-2026-0005", "vulnStatus": "Analyzed", "published": "2026-07-01T00:00:00.000", "lastModified": "2026-07-01T00:00:00.000", "metrics": {}}},
        # Excluded: Rejected
        {"cve": {"id": "CVE-2026-0006", "vulnStatus": "Rejected", "published": "2026-06-05T00:00:00.000", "lastModified": "2026-06-05T00:00:00.000", "metrics": {}}},
    ]
    epss_data = {
        "CVE-2026-0001": {"epss": 0.01234, "percentile": 0.5, "date": "2026-07-01"},
        "CVE-2026-0002": {"epss": 0.99999, "percentile": 0.99, "date": "2026-08-01"},  # wrong date -> must not leak
    }
    kev_vulns = [
        {"cveID": "CVE-2026-0001", "dateAdded": "2026-07-02"},
        {"cveID": "CVE-2026-0002", "dateAdded": "2026-09-29"},
        {"cveID": "CVE-2026-0003", "dateAdded": "2026-09-30"},
        {"cveID": "CVE-2026-0004", "dateAdded": "2026-07-01"},
    ]
    nvd_p, hist_p, epss_p, kev_p, out_csv, out_man = _write_mini_caches(tmp_path, vulns, {}, epss_data, kev_vulns)
    manifest = build_temporal_benchmark(nvd_p, hist_p, epss_p, kev_p, out_csv, out_man)
    st = manifest["stats"]
    assert st["excluded_duplicate"] == 1
    assert st["excluded_rejected"] == 1
    assert st["excluded_post_cutoff_published"] == 1
    assert st["excluded_kev_at_cutoff"] == 1
    assert st["eligible_total"] == 3
    assert st["positives_within_horizon"] == 2
    assert st["negatives_not_observed"] == 1
    assert st["epss_available"] == 1
    assert st["epss_missing"] == 2

    rows = {r["cve_id"]: r for r in csv.DictReader(out_csv.open("r", encoding="utf-8"))}
    assert rows["CVE-2026-0001"]["future_kev_within_horizon"] == "1"
    assert rows["CVE-2026-0002"]["future_kev_within_horizon"] == "1"
    assert rows["CVE-2026-0002"]["cvss_as_of_cutoff"] == ""
    assert rows["CVE-2026-0002"]["epss_as_of_cutoff"] == ""
    assert rows["CVE-2026-0003"]["future_kev_within_horizon"] == "0"


def test_incomplete_observation_window_raises(tmp_path: Path):
    nvd_p, hist_p, epss_p, kev_p, out_csv, out_man = _write_mini_caches(
        tmp_path, [], {}, {}, [], kev_released="2026-09-15T00:00:00Z"
    )
    with pytest.raises(ValueError, match="precedes horizon end"):
        build_temporal_benchmark(nvd_p, hist_p, epss_p, kev_p, out_csv, out_man)


def test_tie_aware_metrics_hand_verified_and_fewer_than_k():
    # Hand-calculated example: 4 items, all tied in pairs:
    # Block 1: score=10.0, size=2, positives=1 -> exp rel 0.5 at ranks 1 and 2
    # Block 2: score=5.0,  size=2, positives=1 -> exp rel 0.5 at ranks 3 and 4
    scores = [10.0, 10.0, 5.0, 5.0]
    labels = [1, 0, 0, 1]

    # Precision@10 with N=4 < 10 -> denom = min(10, 4) = 4 -> 2 / 4 = 0.5
    assert tie_aware_precision_at_k(scores, labels, k=10) == pytest.approx(0.5)

    # Recall@10 = 2 / 2 = 1.0; Recall@2 = (0.5 + 0.5) / 2 = 0.5
    assert tie_aware_recall_at_k(scores, labels, k=10) == pytest.approx(1.0)
    assert tie_aware_recall_at_k(scores, labels, k=2) == pytest.approx(0.5)

    # NDCG@10 with 2 positives: IDCG = 1/log2(2) + 1/log2(3)
    idcg = 1.0 / math.log2(2) + 1.0 / math.log2(3)
    dcg = 0.5 * (1.0 / math.log2(2) + 1.0 / math.log2(3) + 1.0 / math.log2(4) + 1.0 / math.log2(5))
    assert tie_aware_ndcg_at_k(scores, labels, k=10) == pytest.approx(dcg / idcg)

    # AP: Block 1 avg prec = 0.5*(1/1 + 1/2) = 0.75; Block 2 avg prec = 0.5*(2/3 + 2/4) = 7/12
    expected_ap = (0.75 + 7.0 / 12.0) / 2.0
    assert tie_aware_average_precision(scores, labels) == pytest.approx(expected_ap)


def test_unrounded_epss_precision_and_no_label_leakage():
    records_a = [
        {"cve_id": "CVE-2026-0001", "cvss": 9.8, "epss": 0.00199, "kev": False, "label": 0},
        {"cve_id": "CVE-2026-0002", "cvss": 9.8, "epss": 0.00201, "kev": False, "label": 1},
    ]
    scores_a = compute_unrounded_scores(records_a)
    assert scores_a["EPSS-only"][1] > scores_a["EPSS-only"][0]
    assert scores_a["VRS (default context=0.5)"][1] > scores_a["VRS (default context=0.5)"][0]

    # Flipping future labels must never change any method's input scores
    records_b = [dict(r, label=1 - r["label"]) for r in records_a]
    scores_b = compute_unrounded_scores(records_b)
    assert scores_a == scores_b


def test_empty_and_no_positive_and_bootstrap_reproducibility(tmp_path: Path):
    # Empty CSV
    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("cve_id,cvss_as_of_cutoff,epss_as_of_cutoff,kev_at_cutoff,future_kev_within_horizon\n", encoding="utf-8")
    rep_empty = evaluate_teob(empty_csv, n_boot=50, seed=42, write_outputs=False)
    assert rep_empty["n_eligible"] == 0
    assert rep_empty["metrics"]["VRS (default context=0.5)"]["ndcg@10"] == 0.0

    # No-positive-label CSV
    nopos_csv = tmp_path / "nopos.csv"
    nopos_csv.write_text(
        "cve_id,cvss_as_of_cutoff,epss_as_of_cutoff,kev_at_cutoff,future_kev_within_horizon\n"
        "CVE-2026-1,9.8,0.01,0,0\n"
        "CVE-2026-2,7.5,0.02,0,0\n",
        encoding="utf-8",
    )
    rep_nopos = evaluate_teob(nopos_csv, n_boot=50, seed=42, write_outputs=False)
    assert rep_nopos["n_positives_90d_kev"] == 0
    assert rep_nopos["metrics"]["VRS (default context=0.5)"]["average_precision"] == 0.0
    assert rep_nopos["paired_stratified_bootstrap_vrs_minus_baseline"]["CVSS-only"]["ndcg@10"]["n_valid"] == 0

    # Bootstrap reproducibility with fixed seed
    small_csv = tmp_path / "small.csv"
    small_csv.write_text(
        "cve_id,cvss_as_of_cutoff,epss_as_of_cutoff,kev_at_cutoff,future_kev_within_horizon\n"
        "CVE-2026-1,9.8,0.05,0,1\n"
        "CVE-2026-2,9.8,0.01,0,0\n"
        "CVE-2026-3,8.0,0.02,0,1\n"
        "CVE-2026-4,7.0,0.005,0,0\n",
        encoding="utf-8",
    )
    r1 = evaluate_teob(small_csv, n_boot=100, seed=12345, write_outputs=False)
    r2 = evaluate_teob(small_csv, n_boot=100, seed=12345, write_outputs=False)
    assert r1 == r2


@pytest.mark.skipif(not OUT_CSV.exists(), reason="TEOB dataset CSV not yet built")
def test_teob_csv_has_no_temporal_leakage_or_invalid_labels():
    horizon_end = (date.fromisoformat(CUTOFF_DATE) + timedelta(days=HORIZON_DAYS)).isoformat()
    with open(OUT_CSV, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) > 0
    seen_ids = set()
    for r in rows:
        cid = r["cve_id"]
        assert cid not in seen_ids
        seen_ids.add(cid)

        assert r["cutoff_date"] == CUTOFF_DATE
        assert r["published_date"] < CUTOFF_DATE
        assert int(r["kev_at_cutoff"]) == 0
        assert int(r["observation_horizon_days"]) == HORIZON_DAYS

        if r["cvss_status_at_cutoff"] in ("added_after_cutoff_excluded", "missing_in_nvd", "unreconstructable_post_cutoff_change"):
            assert r["cvss_as_of_cutoff"] == ""

        if r["future_kev_within_horizon"] == "1":
            da = r["future_kev_addition_date"]
            assert CUTOFF_DATE < da <= horizon_end
            assert r["outcome_label"] == "observed_kev_addition"
        else:
            assert r["future_kev_within_horizon"] == "0"
            assert r["future_kev_addition_date"] == ""
            assert r["outcome_label"] == "not observed in KEV during the horizon"
