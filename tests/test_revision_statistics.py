"""
Tests for Phase 3 statistical validation (experiments/revision_statistics.py).

Covers deterministic bootstrap, CI calculation, paired resampling, metric edge
cases, empty and single-record datasets, missing labels, ceiling metrics,
small-sample warnings, and reproducibility.
"""

import csv
import math
import os
import sys

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "experiments"))

import revision_statistics as rs  # noqa: E402
from experiments.metrics import ndcg_at_k, precision_at_k, recall_at_k, spearman_correlation  # noqa: E402


BENCH = os.path.join(ROOT, "data", "benchmark", "cves.csv")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _toy(ranking, grades):
    """Build a _Ranking over a toy population. grades: dict cve -> int."""
    cves = list(grades.keys())
    idx = {c: i for i, c in enumerate(cves)}
    return rs._Ranking("toy", ranking, idx), cves, idx


def _ref_pos_and_grades(cves, grades, reference):
    idx = {c: i for i, c in enumerate(cves)}
    ref_pos = np.empty(len(cves), dtype=np.int64)
    for p, c in enumerate(reference):
        ref_pos[idx[c]] = p
    g = np.array([grades[c] for c in cves], dtype=np.int64)
    return ref_pos, g


# ---------------------------------------------------------------------------
# Deterministic bootstrap with fixed seeds
# ---------------------------------------------------------------------------

def test_make_indices_same_seed_is_identical():
    a = rs.make_indices(41, 50, seed=7, strategy="plain")
    b = rs.make_indices(41, 50, seed=7, strategy="plain")
    assert np.array_equal(a, b)


def test_make_indices_different_seed_differs():
    a = rs.make_indices(41, 50, seed=7, strategy="plain")
    b = rs.make_indices(41, 50, seed=8, strategy="plain")
    assert not np.array_equal(a, b)


def test_make_indices_shape_and_range():
    m = rs.make_indices(41, 200, seed=1, strategy="plain")
    assert m.shape == (200, 41)
    assert m.min() >= 0 and m.max() < 41


def test_stratified_preserves_grade_counts():
    grades = np.array([3, 3, 2, 1, 0, 0, 0])
    m = rs.make_indices(7, 100, seed=3, strategy="stratified", grades=grades)
    assert m.shape == (100, 7)
    for row in m:
        drawn = grades[row]
        for g in (0, 1, 2, 3):
            assert int(np.sum(drawn == g)) == int(np.sum(grades == g))


def test_bootstrap_full_run_is_deterministic():
    r1 = rs.run_analysis(n_iter=40, seed=11, write=False, verify_phase2=True)
    r2 = rs.run_analysis(n_iter=40, seed=11, write=False, verify_phase2=True)
    assert r1["observed_metrics"] == r2["observed_metrics"]
    assert r1["warnings"] == r2["warnings"]
    assert r1["strategy_meta"] == r2["strategy_meta"]


def test_iteration_bounds_enforced():
    with pytest.raises(ValueError):
        rs.make_indices(41, 0, seed=1, strategy="plain")
    with pytest.raises(ValueError):
        rs.make_indices(41, rs.MAX_ITERATIONS + 1, seed=1, strategy="plain")
    with pytest.raises(ValueError):
        rs.run_analysis(n_iter=rs.MAX_ITERATIONS + 1, write=False)


def test_default_and_max_iterations_match_spec():
    assert rs.DEFAULT_ITERATIONS == 2000
    assert rs.MAX_ITERATIONS == 5000


# ---------------------------------------------------------------------------
# Confidence interval calculations
# ---------------------------------------------------------------------------

def test_percentile_ci_known_values():
    vals = np.arange(101, dtype=float)  # 0..100
    lo, hi = rs._pct_ci(vals, level=0.95)
    assert lo == pytest.approx(2.5)
    assert hi == pytest.approx(97.5)


def test_percentile_ci_ignores_nan():
    vals = np.array([np.nan, 0.0, 1.0, 2.0, np.nan])
    lo, hi = rs._pct_ci(vals)
    assert lo == pytest.approx(0.05)
    assert hi == pytest.approx(1.95)


def test_percentile_ci_all_nan_returns_nan():
    lo, hi = rs._pct_ci(np.array([np.nan, np.nan]))
    assert math.isnan(lo) and math.isnan(hi)


def test_summarize_mean_sd_ci():
    vals = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
    s = rs.summarize(vals, observed=3.0, ceiling=None)
    assert s["bootstrap_mean"] == pytest.approx(3.0)
    assert s["bootstrap_sd"] == pytest.approx(np.std(vals, ddof=1))
    assert s["ci_low"] == pytest.approx(np.percentile(vals, 2.5))
    assert s["ci_high"] == pytest.approx(np.percentile(vals, 97.5))
    assert s["n_iterations"] == 5
    assert s["n_valid"] == 5
    assert s["degenerate"] is False


def test_summarize_constant_is_degenerate():
    s = rs.summarize(np.ones(20), observed=1.0, ceiling=1.0)
    assert s["degenerate"] is True
    assert s["fraction_at_ceiling"] == pytest.approx(1.0)


def test_summarize_all_nan_is_degenerate_not_crash():
    s = rs.summarize(np.full(10, np.nan), observed=float("nan"), ceiling=1.0)
    assert s["n_valid"] == 0
    assert s["degenerate"] is True
    assert math.isnan(s["bootstrap_mean"])


def test_summarize_single_iteration():
    s = rs.summarize(np.array([0.5]), observed=0.5, ceiling=None)
    assert s["n_valid"] == 1
    assert math.isnan(s["bootstrap_sd"])
    assert s["degenerate"] is False


# ---------------------------------------------------------------------------
# Metric edge cases
# ---------------------------------------------------------------------------

def test_spearman_identity_is_one():
    grades = {"A": 3, "B": 2, "C": 1}
    rk, cves, _ = _toy(["A", "B", "C"], grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ["A", "B", "C"])
    assert rs._spearman(
        rs._sample_view(np.arange(3), rk, ref_pos, g)[1],
        rs._sample_view(np.arange(3), rk, ref_pos, g)[2],
    ) == pytest.approx(1.0)


def test_spearman_reversed_is_minus_one():
    grades = {"A": 3, "B": 2, "C": 1}
    rk, cves, _ = _toy(["C", "B", "A"], grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ["A", "B", "C"])
    _, pr, rr, _ = rs._sample_view(np.arange(3), rk, ref_pos, g)
    assert rs._spearman(pr, rr) == pytest.approx(-1.0)


def test_spearman_single_record_is_nan():
    assert math.isnan(rs._spearman(np.array([0]), np.array([0])))


def test_spearman_matches_metrics_py_on_identity():
    rk_list = ["CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E"]
    grades = {c: 1 for c in rk_list}
    rk, cves, _ = _toy(rk_list[::-1], grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, rk_list)
    _, pr, rr, _ = rs._sample_view(np.arange(5), rk, ref_pos, g)
    expected = spearman_correlation(rk_list[::-1], rk_list)
    assert rs._spearman(pr, rr) == pytest.approx(expected, abs=1e-4)


def test_ndcg_perfect_is_one():
    g = np.array([3, 2, 1, 0])
    assert rs._ndcg_at_k(g, g) == pytest.approx(1.0)


def test_ndcg_no_relevant_items_is_nan():
    g = np.zeros(5, dtype=int)
    assert math.isnan(rs._ndcg_at_k(g, g))


def test_ndcg_matches_metrics_py():
    grades = {f"C{i}": g for i, g in enumerate([3, 0, 2, 1, 3, 0, 0, 2, 1, 0, 3, 2])}
    ranking = list(grades)
    rel = dict(grades)
    rk, cves, _ = _toy(ranking, grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, sorted(cves))
    _, _, _, gs = rs._sample_view(np.arange(len(cves)), rk, ref_pos, g)
    mine = rs._ndcg_at_k(gs, g)
    assert mine == pytest.approx(ndcg_at_k(ranking, rel, 10), abs=1e-4)


def test_precision_fixed_denominator_k():
    g_sorted = np.array([3, 3])  # only 2 items in top-10 list
    assert rs._precision_at_k(g_sorted, tau=3, k=10) == pytest.approx(0.2)


def test_recall_no_relevant_is_nan():
    g = np.array([0, 1, 1])
    assert math.isnan(rs._recall_at_k(g[:3], g, tau=3))


def test_recall_matches_metrics_py_actionable():
    grades = {"A": 3, "B": 2, "C": 2, "D": 0}
    ranking = ["A", "C", "B", "D"]
    rk, cves, _ = _toy(ranking, grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ranking)
    _, _, _, gs = rs._sample_view(np.arange(4), rk, ref_pos, g)
    mine = rs._recall_at_k(gs, g, tau=2, k=10)
    expected = recall_at_k(ranking, grades, k=10, threshold=2)
    assert mine == pytest.approx(expected, abs=1e-4)
    # Precision: hits in top-10 with grade>=2 over fixed K=10 (here 2 hits: A, C, B are >=2 -> 3 hits)
    assert rs._precision_at_k(gs, tau=2, k=10) == pytest.approx(
        precision_at_k(ranking, grades, k=10, threshold=2), abs=1e-4
    )


# ---------------------------------------------------------------------------
# Paired resampling
# ---------------------------------------------------------------------------

def test_paired_samples_share_indices_across_models():
    """The same index vector must produce both models' metrics on the same records."""
    grades = {"A": 3, "B": 0, "C": 2}
    r1, cves, _ = _toy(["A", "B", "C"], grades)
    r2, _, _ = _toy(["C", "B", "A"], grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ["A", "B", "C"])
    idx = np.array([2, 2, 0])  # duplicate draw
    _, p1, rr1, _ = rs._sample_view(idx, r1, ref_pos, g)
    _, p2, rr2, _ = rs._sample_view(idx, r2, ref_pos, g)
    assert np.array_equal(rr1, rr2)  # reference rank of each draw is shared
    assert sorted(p1.tolist()) == sorted(p2.tolist()) == [0, 1, 2]


def test_duplicate_draws_are_distinct_items():
    grades = {"A": 3, "B": 0}
    rk, cves, _ = _toy(["A", "B"], grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ["A", "B"])
    idx = np.array([0, 0, 1])
    order, pred_rank, ref_rank, gs = rs._sample_view(idx, rk, ref_pos, g)
    assert len(set(pred_rank.tolist())) == 3  # three distinct positions
    assert gs.tolist() == [3, 3, 0]


def test_paired_difference_is_zero_for_identical_rankings():
    grades = {"A": 3, "B": 2, "C": 1, "D": 0}
    ranking = ["A", "B", "C", "D"]
    r1, cves, _ = _toy(ranking, grades)
    r2, _, _ = _toy(ranking, grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ranking)
    idx = rs.make_indices(4, 20, seed=5, strategy="plain")
    for row in idx:
        a = rs.metrics_for_sample(row, r1, ref_pos, g)
        b = rs.metrics_for_sample(row, r2, ref_pos, g)
        for k in a:
            if math.isnan(a[k]):
                assert math.isnan(b[k]), k
            else:
                assert a[k] == b[k], k


def test_ranking_similarity_identical_is_one():
    grades = {"A": 3, "B": 2, "C": 1, "D": 0}
    ranking = ["A", "B", "C", "D"]
    r1, cves, _ = _toy(ranking, grades)
    r2, _, _ = _toy(ranking, grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ranking)
    sim = rs.ranking_similarity(np.arange(4), r1, r2, ref_pos, g)
    assert sim["spearman_vs_model"] == pytest.approx(1.0)
    assert sim["kendall_tau_vs_model"] == pytest.approx(1.0)


def test_ranking_similarity_is_not_performance():
    """Similarity between two rankings must not depend on the reference grades."""
    ranking_a = ["A", "B", "C", "D"]
    ranking_b = ["D", "C", "B", "A"]
    grades1 = {"A": 3, "B": 2, "C": 1, "D": 0}
    grades2 = {"A": 0, "B": 1, "C": 2, "D": 3}
    r1, cves, _ = _toy(ranking_a, grades1)
    r2, _, _ = _toy(ranking_b, grades1)
    ref_pos, g = _ref_pos_and_grades(cves, grades1, ranking_a)
    sim = rs.ranking_similarity(np.arange(4), r1, r2, ref_pos, g)
    assert sim["spearman_vs_model"] == pytest.approx(-1.0)


# ---------------------------------------------------------------------------
# Empty datasets, single-record datasets, missing labels
# ---------------------------------------------------------------------------

def test_empty_dataset_resample_raises():
    with pytest.raises(ValueError, match="empty"):
        rs.make_indices(0, 10, seed=1, strategy="plain")


def test_empty_ranking_rejected():
    with pytest.raises(ValueError):
        rs._Ranking("x", [], {})


def test_single_record_dataset_is_degenerate_but_runs():
    grades = {"A": 3}
    rk, cves, _ = _toy(["A"], grades)
    ref_pos, g = _ref_pos_and_grades(cves, grades, ["A"])
    m = rs.metrics_for_sample(np.array([0]), rk, ref_pos, g)
    assert m["ndcg@10"] == pytest.approx(1.0)
    assert m["precision@10_act"] == pytest.approx(0.1)
    assert m["recall@10_act"] == pytest.approx(1.0)
    assert math.isnan(m["spearman"])


def test_ranking_population_mismatch_rejected():
    with pytest.raises(ValueError, match="population"):
        rs._Ranking("x", ["A", "B"], {"A": 0, "C": 1})


def test_duplicate_identifiers_in_ranking_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        rs._Ranking("x", ["A", "A"], {"A": 0, "B": 1})


def test_missing_label_raises(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text(
        "cve_id,cvss,epss,kev,exposure,asset_criticality,reference_priority,independent_label,description\n"
        "CVE-1,5.0,0.1,0,0.5,0.5,1,,x\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="independent_label"):
        rs.load_labels(str(p))


def test_invalid_label_raises(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text(
        "cve_id,cvss,epss,kev,exposure,asset_criticality,reference_priority,independent_label,description\n"
        "CVE-1,5.0,0.1,0,0.5,0.5,1,Urgent,x\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid independent_label"):
        rs.load_labels(str(p))


def test_duplicate_cve_in_labels_raises(tmp_path):
    p = tmp_path / "dup.csv"
    p.write_text(
        "cve_id,cvss,epss,kev,exposure,asset_criticality,reference_priority,independent_label,description\n"
        "CVE-1,5.0,0.1,0,0.5,0.5,1,Act,x\n"
        "CVE-1,5.0,0.1,0,0.5,0.5,2,Act,x\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate"):
        rs.load_labels(str(p))


def test_load_labels_real_benchmark_counts():
    cves, grades, synthetic, _ = rs.load_labels(BENCH)
    assert len(cves) == 41
    assert sum(synthetic.values()) == 2
    assert {c for c, s in synthetic.items() if s} == set(rs.SYNTHETIC_IDS)


# ---------------------------------------------------------------------------
# Ceiling metrics and warnings
# ---------------------------------------------------------------------------

def test_ceiling_fraction_reported():
    vals = np.array([1.0, 1.0, 0.5, 1.0])
    s = rs.summarize(vals, observed=1.0, ceiling=1.0)
    assert s["fraction_at_ceiling"] == pytest.approx(0.75)


def test_warning_small_sample_and_ceiling():
    r = rs.run_analysis(n_iter=30, seed=2, write=False, verify_phase2=True)
    text = " | ".join(r["warnings"])
    assert "SMALL SAMPLE" in text
    assert "CEILING" in text
    assert "NO SIGNIFICANCE CLAIMS" in text
    assert "AUTHOR-CURATED" in text
    assert "SYNTHETIC RECORDS" in text


def test_warning_iterations_below_default():
    r = rs.run_analysis(n_iter=30, seed=2, write=False, verify_phase2=True)
    assert any(w.startswith("ITERATIONS:") for w in r["warnings"])


def test_no_significance_claims_in_report_text(tmp_path):
    rs.run_analysis(n_iter=30, seed=2, write=True, out_dir=str(tmp_path), verify_phase2=True)
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "no p-value" in md.lower() or "No p-values" in md
    # the word "significant" may only appear in negated contexts
    for line in md.splitlines():
        low = line.lower()
        if "significant" in low:
            assert "no significance" in low or "not significant" in low or "not " in low, line


def test_paired_interpretation_never_claims_significance():
    text = rs.interpret_difference(0.2, 0.05, 0.4, degenerate=False, n_valid=50, n_iter=50)
    assert "no p-value" in text
    assert "significant" not in text.lower()


def test_interpret_degenerate_comparison():
    text = rs.interpret_difference(0.0, 0.0, 0.0, degenerate=True, n_valid=50, n_iter=50)
    assert "Degenerate" in text


def test_interpret_interval_including_zero():
    text = rs.interpret_difference(0.01, -0.02, 0.05, degenerate=False, n_valid=50, n_iter=50)
    assert "includes 0" in text


# ---------------------------------------------------------------------------
# Actionable metric verification
# ---------------------------------------------------------------------------

def test_actionable_verification_matches_metrics_py():
    r = rs.run_analysis(n_iter=20, seed=3, write=False, verify_phase2=True)
    av = r["actionable_verification"]
    assert av["all_match_metrics_py"] is True
    assert av["relevant_population_size"] == 27  # Act(15) + Attend(12) on the benchmark
    assert av["discriminative"] is False  # documented finding


# ---------------------------------------------------------------------------
# Input integrity and Phase 2 agreement
# ---------------------------------------------------------------------------

def test_rebuilt_rankings_match_phase2():
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        findings, _, _ = rs.load_benchmark(BENCH)
        rankings = rs.build_rankings(findings)
        report = rs.verify_against_phase2(rankings)
        assert all(report.values())
        assert set(report) == set(rs.ORIGINAL_MODELS + rs.CONTEXT_MODELS)
    finally:
        os.chdir(cwd)


def test_benchmark_hash_guard(tmp_path):
    fake = tmp_path / "cves.csv"
    fake.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        rs.run_analysis(benchmark_path=str(fake), n_iter=5, write=False)


# ---------------------------------------------------------------------------
# Reproducibility of written outputs
# ---------------------------------------------------------------------------

def test_outputs_written_and_reproducible(tmp_path):
    out1 = tmp_path / "a"
    out2 = tmp_path / "b"
    rs.run_analysis(n_iter=25, seed=4, out_dir=str(out1), write=True, verify_phase2=True)
    rs.run_analysis(n_iter=25, seed=4, out_dir=str(out2), write=True, verify_phase2=True)
    for name in ("bootstrap_results.csv", "paired_comparisons.csv", "ranking_stability.csv", "statistical_report.json", "report.md"):
        assert (out1 / name).read_bytes() == (out2 / name).read_bytes(), name


def test_paired_csv_schema(tmp_path):
    rs.run_analysis(n_iter=10, seed=4, out_dir=str(tmp_path), write=True, verify_phase2=True)
    with open(tmp_path / "paired_comparisons.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows, "no paired rows written"
    required = {"baseline", "vrs", "observed_difference", "ci_low", "ci_high", "n_iterations", "interpretation"}
    assert required <= set(rows[0].keys())
    assert all(r["vrs"] == "VRS Proposed" for r in rows)
    assert {r["baseline"] for r in rows} == set(rs.ORIGINAL_MODELS + rs.CONTEXT_MODELS) - {"VRS Proposed"}


def test_stability_separates_similarity_from_performance(tmp_path):
    rs.run_analysis(n_iter=10, seed=4, out_dir=str(tmp_path), write=True, verify_phase2=True)
    with open(tmp_path / "ranking_stability.csv", encoding="utf-8") as f:
        types = {r["comparison_type"] for r in csv.DictReader(f)}
    assert types == {"ranking_similarity", "performance_vs_reference_labels"}


def test_outputs_do_not_touch_protected_artifacts(tmp_path):
    protected = [
        os.path.join(ROOT, "experiments", "results", "metrics.json"),
        os.path.join(ROOT, "experiments", "revision", "metrics.json"),
        BENCH,
    ]
    before = {p: open(p, "rb").read() for p in protected}
    rs.run_analysis(n_iter=5, seed=1, out_dir=str(tmp_path), write=True, verify_phase2=True)
    for p in protected:
        assert open(p, "rb").read() == before[p], p
