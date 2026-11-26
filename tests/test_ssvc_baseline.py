"""Unit tests for vendored SSVC decision-tree baseline."""

from pathlib import Path

from experiments.revision.baselines.ssvc_baseline import (
    evaluate_ssvc_tree,
    run_ssvc_baseline,
)


def test_ssvc_tree_known_leaves():
    assert evaluate_ssvc_tree("active", "yes", "total", "essential", "minimal") == "Act"
    assert evaluate_ssvc_tree("none", "no", "partial", "negligible", "minimal") == "Track"
    assert evaluate_ssvc_tree("poc", "yes", "total", "support", "minimal") == "Attend"


def test_run_ssvc_baseline_idempotent_and_bounded(tmp_path: Path):
    out = tmp_path / "results_ssvc.json"
    r1 = run_ssvc_baseline(out_path=out)
    r2 = run_ssvc_baseline(out_path=out)
    assert r1["metrics"] == r2["metrics"]
    assert r1["n_records"] == 41
    for k, v in r1["metrics"].items():
        assert 0.0 <= v <= 1.0, f"{k} out of range: {v}"
    sens = r1["assumption_sensitivity_2x2"]
    assert len(sens["combinations"]) == 4
    assert 0.0 <= sens["spearman_min"] <= sens["spearman_max"] <= 1.0
