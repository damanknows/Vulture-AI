"""Unit tests for full-rank weight sensitivity and ablation metrics."""

import json
import math
from pathlib import Path

from experiments.revision.sensitivity.full_rank_sensitivity import (
    CONFIGS_PATH,
    run_full_rank_sensitivity,
)
from experiments.run_ablation import run_ablation
from experiments.run_baselines import load_benchmark
from risk_engine import DEFAULT_WEIGHTS, rank_findings


def test_all_configurations_sum_to_one():
    with open(CONFIGS_PATH, "r", encoding="utf-8") as f:
        configs = json.load(f)
    assert len(configs) == 6
    for name, w in configs.items():
        assert math.isclose(sum(w.values()), 1.0, abs_tol=1e-6), f"{name} sum != 1.0"


def test_full_rank_sensitivity_reproduces_default_and_bounds(tmp_path: Path):
    out = tmp_path / "full_rank.json"
    res = run_full_rank_sensitivity(out_path=out)
    findings, _, _ = load_benchmark("data/benchmark/cves.csv")
    expected_default = [r["primary_cve"] for r in rank_findings(findings, weights=DEFAULT_WEIGHTS)]
    assert res["orderings"]["original"] == expected_default
    assert res["per_configuration"]["original"]["spearman_rho"] == 1.0
    assert res["per_configuration"]["original"]["kendall_tau"] == 1.0
    assert res["per_configuration"]["original"]["max_rank_shift"] == 0
    for name, info in res["per_configuration"].items():
        assert 0.0 <= info["spearman_rho"] <= 1.0
        assert 0.0 <= info["kendall_tau"] <= 1.0


def test_ablation_metrics_bounded_and_complete():
    res = run_ablation()
    assert "metrics" in res
    for variant, mets in res["metrics"].items():
        for k, v in mets.items():
            assert 0.0 <= v <= 1.0, f"{variant}.{k}={v} exceeds 1.0"
