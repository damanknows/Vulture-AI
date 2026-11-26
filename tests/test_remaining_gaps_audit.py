"""Unit tests for weight sensitivity summary and remaining gaps audit."""

import json
from pathlib import Path

from experiments.audit_remaining_gaps import run_audit
from experiments.summarize_weight_sensitivity import summarize_sensitivity


def test_summarize_sensitivity_idempotent_and_bounded(tmp_path: Path):
    out = tmp_path / "stability.json"
    r1 = summarize_sensitivity(out_path=out)
    r2 = summarize_sensitivity(out_path=out)
    assert r1 == r2
    assert r1["n_perturbations"] == 5
    agg = r1["aggregate"]
    assert 0.0 <= agg["spearman_rho_min"] <= agg["spearman_rho_max"] <= 1.0
    assert 0.0 <= agg["kendall_tau_min"] <= agg["kendall_tau_max"] <= 1.0
    assert agg["top10_overlap_min"] == 10


def test_remaining_gaps_audit_runs_headless_and_matches_tex(tmp_path: Path):
    out = tmp_path / "gaps.json"
    rep = run_audit(out_path=out)
    assert rep["remaining_gaps"]["explanation_quality"]["status"] == "NOT_AVAILABLE"
    assert rep["remaining_gaps"]["cpe_nmap_matching_accuracy"]["status"] == "NOT_AVAILABLE"
    assert rep["remaining_gaps"]["ssvc_and_cvss4_on_41cve"]["status"] == "NOT_AVAILABLE"
    assert rep["manuscript_consistency_audit"]["all_checked_metrics_match"] is True
