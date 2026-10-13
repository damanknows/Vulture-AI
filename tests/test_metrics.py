import pytest
from experiments.metrics import ndcg_at_k, precision_at_k, recall_at_k, spearman_correlation

def test_spearman_perfect():
    pred = ["A", "B", "C"]
    ref = ["A", "B", "C"]
    assert abs(spearman_correlation(pred, ref) - 1.0) < 1e-4

def test_spearman_inverse():
    pred = ["A", "B", "C"]
    ref = ["C", "B", "A"]
    assert abs(spearman_correlation(pred, ref) - (-1.0)) < 1e-4

def test_ndcg_perfect():
    rel_dict = {"A": 3, "B": 2, "C": 1}
    pred = ["A", "B", "C"]
    assert abs(ndcg_at_k(pred, rel_dict, 3) - 1.0) < 1e-4

def test_ndcg_imperfect():
    rel_dict = {"A": 3, "B": 1, "C": 0}
    pred = ["B", "A", "C"]
    val = ndcg_at_k(pred, rel_dict, 2)
    expected_dcg = 1.0 + (7.0 / 1.5849625)
    expected_idcg = 7.0 + (1.0 / 1.5849625)
    assert abs(val - round(expected_dcg / expected_idcg, 4)) < 1e-3

def test_precision_at_k():
    rel_dict = {"A": 3, "B": 3, "C": 2, "D": 1, "E": 0}
    pred = ["A", "D", "B", "E", "C"]
    # Top 3 items: A (3), D (1), B (3) -> 2 items with rel >= 3
    assert precision_at_k(pred, rel_dict, k=3, threshold=3) == round(2 / 3, 4)
    # Threshold >= 2: A(3), D(1), B(3) -> 2 items
    assert precision_at_k(pred, rel_dict, k=3, threshold=2) == round(2 / 3, 4)
    # Top 5 items with threshold >= 2: A(3), B(3), C(2) -> 3 items
    assert precision_at_k(pred, rel_dict, k=5, threshold=2) == 0.6000

def test_recall_at_k():
    rel_dict = {"A": 3, "B": 3, "C": 3, "D": 2, "E": 0}
    pred = ["A", "D", "B", "E", "C"]
    # Total items with rel >= 3: A, B, C (3 items)
    # Top 2: A, D -> hits = 1
    assert recall_at_k(pred, rel_dict, k=2, threshold=3) == round(1 / 3, 4)
    # Top 3: A, D, B -> hits = 2
    assert recall_at_k(pred, rel_dict, k=3, threshold=3) == round(2 / 3, 4)
    # Top 5: A, D, B, E, C -> hits = 3
    assert recall_at_k(pred, rel_dict, k=5, threshold=3) == 1.0000

def test_metrics_empty_and_zero():
    rel_dict = {"A": 1, "B": 0}
    assert precision_at_k([], rel_dict, k=5, threshold=3) == 0.0
    assert recall_at_k([], rel_dict, k=5, threshold=3) == 0.0
    assert recall_at_k(["A", "B"], rel_dict, k=2, threshold=3) == 0.0  # Total relevant = 0

def test_deterministic_tie_breaking():
    from risk_engine import rank_findings
    f1 = {
        "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
        "cve_matches": [{"cve_id": "CVE-2021-0002", "cvss_score": 7.0, "epss_probability": 0.2, "kev_listed": False}]
    }
    f2 = {
        "finding": {"network_exposure": 0.5, "asset_criticality": 0.5},
        "cve_matches": [{"cve_id": "CVE-2021-0001", "cvss_score": 7.0, "epss_probability": 0.2, "kev_listed": False}]
    }
    ranked = rank_findings([f1, f2])
    # Both have identical VRS scores; deterministic tie-breaking must sort CVE-2021-0001 before CVE-2021-0002
    assert ranked[0]["primary_cve"] == "CVE-2021-0001"
    assert ranked[1]["primary_cve"] == "CVE-2021-0002"
