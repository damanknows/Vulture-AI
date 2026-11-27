"""Unit tests for CVSS v3.1 environmental/threat proxy baseline."""

from pathlib import Path

from experiments.revision.baselines.cvss_env_baseline import (
    compute_cvss_v31_env_proxy,
    run_cvss_env_baseline,
)


def test_cvss_env_proxy_handles_missing_and_bounds():
    f_none = {"finding": {"network_exposure": 1.0, "asset_criticality": 1.0}, "cve_matches": [{"cve_id": "X", "cvss_score": None}]}
    assert compute_cvss_v31_env_proxy(f_none) is None
    f_max = {"finding": {"network_exposure": 1.0, "asset_criticality": 1.0}, "cve_matches": [{"cve_id": "Y", "cvss_score": 10.0, "epss_probability": 0.9, "kev_listed": True}]}
    assert compute_cvss_v31_env_proxy(f_max) == 10.0


def test_run_cvss_env_baseline_idempotent_and_bounded(tmp_path: Path):
    out = tmp_path / "results_cvss_env.json"
    r1 = run_cvss_env_baseline(out_path=out)
    r2 = run_cvss_env_baseline(out_path=out)
    assert r1["metrics"] == r2["metrics"]
    assert r1["cvss_v4_vectors_available"] is False
    for k, v in r1["metrics"].items():
        assert 0.0 <= v <= 1.0, f"{k}={v} out of [0, 1]"
