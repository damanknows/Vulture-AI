"""Unit tests for scanner-to-CPE matching evaluation."""

from pathlib import Path

from experiments.revision.cpe.matching_eval import evaluate_cpe_matching


def test_cpe_matching_eval_idempotent_and_bounded(tmp_path: Path):
    out = tmp_path / "cpe.json"
    r1 = evaluate_cpe_matching(out_path=out)
    r2 = evaluate_cpe_matching(out_path=out)
    assert r1 == r2
    assert 30 <= r1["n_banners"] <= 50
    for k, v in r1["metrics"].items():
        assert 0.0 <= v <= 1.0, f"{k}={v} out of [0, 1]"
    cm = r1["confusion_matrix"]
    assert cm["TP"] + cm["FP"] + cm["FN"] + cm["TN"] == r1["n_banners"]
