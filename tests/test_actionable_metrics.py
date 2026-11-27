"""Unit tests for Actionable Precision@10 (denom 10) and Recall@10 (denom 27, threshold 2)."""

from pathlib import Path

from experiments.metrics import THRESHOLD_ACTIONABLE, precision_at_k, recall_at_k
from experiments.revision.baselines.compute_actionable_summary import compute_actionable_summary
from experiments.run_baselines import load_benchmark


def test_actionable_denominators_and_threshold():
    _, ref_ranking, relevance_dict = load_benchmark("data/benchmark/cves.csv")
    assert THRESHOLD_ACTIONABLE == 2
    n_actionable = sum(1 for v in relevance_dict.values() if v >= 2)
    assert n_actionable == 27

    p10 = precision_at_k(ref_ranking, relevance_dict, k=10, threshold=2)
    r10 = recall_at_k(ref_ranking, relevance_dict, k=10, threshold=2)
    assert p10 == 1.0  # 10 / 10
    assert r10 == round(10 / 27, 4)  # 0.3704


def test_compute_actionable_summary_bounded(tmp_path: Path):
    out = tmp_path / "actionable.json"
    rep = compute_actionable_summary(out_path=out)
    assert rep["threshold"] == 2
    assert rep["precision_denominator"] == 10
    assert rep["recall_denominator"] == 27
    for m, vals in rep["methods"].items():
        assert 0.0 <= vals["AP@10"] <= 1.0
        assert 0.0 <= vals["AR@10"] <= 1.0
