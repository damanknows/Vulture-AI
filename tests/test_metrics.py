import math
import pytest
from experiments.metrics import (
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    spearman_correlation,
    validate_ranking_population,
    THRESHOLD_ACT,
    THRESHOLD_ACTIONABLE,
)


def test_spearman_perfect():
    pred = ["A", "B", "C"]
    ref = ["A", "B", "C"]
    assert abs(spearman_correlation(pred, ref) - 1.0) < 1e-4


def test_spearman_inverse():
    pred = ["A", "B", "C"]
    ref = ["C", "B", "A"]
    assert abs(spearman_correlation(pred, ref) - (-1.0)) < 1e-4


def test_spearman_duplicate_predicted_raises():
    pred = ["A", "A", "B"]
    ref = ["A", "B", "C"]
    with pytest.raises(ValueError, match="Duplicate identifiers detected in predicted ranking"):
        spearman_correlation(pred, ref)


def test_spearman_duplicate_reference_raises():
    pred = ["A", "B", "C"]
    ref = ["A", "B", "B"]
    with pytest.raises(ValueError, match="Duplicate identifiers detected in reference ranking"):
        spearman_correlation(pred, ref)


def test_spearman_mismatched_population_raises():
    pred = ["A", "B", "C"]
    ref = ["A", "B", "D"]
    with pytest.raises(ValueError, match="Ranking populations mismatch"):
        spearman_correlation(pred, ref)


def test_spearman_constant_array_zero_variance():
    # When all scores are identical, correlation is mathematically undefined (zero variance)
    # The metric safely returns 0.0
    pred_constant = {"A": 5.0, "B": 5.0, "C": 5.0}
    ref_varying = {"A": 1.0, "B": 2.0, "C": 3.0}
    assert spearman_correlation(pred_constant, ref_varying) == 0.0

    ref_constant = {"A": 7.0, "B": 7.0, "C": 7.0}
    assert spearman_correlation(pred_constant, ref_constant) == 0.0


def test_spearman_with_ties_manual_calculation():
    # Hand-calculated example:
    # Items: A, B, C, D
    # pred scores: A=10, B=10, C=5, D=1  -> ranks: D=1, C=2, A&B tied for ranks 3 & 4 (mid-rank = 3.5)
    # ref scores:  A=4,  B=3,  C=2, D=1  -> ranks: D=1, C=2, B=3, A=4
    # Pearson of ranks: cov=4.5, var_x=4.5, var_y=5.0 -> rho = 4.5 / sqrt(22.5) ≈ 0.94868
    pred = {"A": 10.0, "B": 10.0, "C": 5.0, "D": 1.0}
    ref = {"A": 4.0, "B": 3.0, "C": 2.0, "D": 1.0}
    expected = round(4.5 / math.sqrt(22.5), 4)
    assert spearman_correlation(pred, ref) == expected


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


def test_ndcg_manual_hand_calculated():
    # Hand-calculated example:
    # rel: A=3, B=2, C=1, D=0
    # pred: ['B', 'A', 'D', 'C']
    # k=3: top-3 are B (rel=2), A (rel=3), D (rel=0)
    # DCG@3 = (3/1) + (7/1.5849625) + 0 ≈ 7.416508
    # IDCG@3 = (7/1) + (3/1.5849625) + (1/2) ≈ 9.392789
    # NDCG@3 = 7.416508 / 9.392789 ≈ 0.7896
    rel = {"A": 3, "B": 2, "C": 1, "D": 0}
    pred = ["B", "A", "D", "C"]
    assert ndcg_at_k(pred, rel, k=3) == 0.7896


def test_ndcg_duplicates_raises():
    rel = {"A": 3, "B": 2}
    with pytest.raises(ValueError, match="Duplicate items found in predicted ranking"):
        ndcg_at_k(["A", "A", "B"], rel, k=3)


def test_precision_at_k():
    rel_dict = {"A": 3, "B": 3, "C": 2, "D": 1, "E": 0}
    pred = ["A", "D", "B", "E", "C"]
    # Top 3 items: A (3), D (1), B (3) -> 2 items with rel >= 3
    assert precision_at_k(pred, rel_dict, k=3, threshold=3) == round(2 / 3, 4)
    # Threshold >= 2: A(3), D(1), B(3) -> 2 items
    assert precision_at_k(pred, rel_dict, k=3, threshold=2) == round(2 / 3, 4)
    # Top 5 items with threshold >= 2: A(3), B(3), C(2) -> 3 items
    assert precision_at_k(pred, rel_dict, k=5, threshold=2) == 0.6000


def test_precision_recall_manual_thresholds():
    # Hand-calculated example:
    # rel: A=3, B=3, C=2, D=1, E=0
    # Total with rel >= 3: 2 (A, B)
    # Total with rel >= 2: 3 (A, B, C)
    # pred: ['C', 'A', 'E', 'B', 'D']
    # top 3: ['C' (2), 'A' (3), 'E' (0)]
    rel = {"A": 3, "B": 3, "C": 2, "D": 1, "E": 0}
    pred = ["C", "A", "E", "B", "D"]
    assert precision_at_k(pred, rel, k=3, threshold=THRESHOLD_ACT) == round(1 / 3, 4)
    assert recall_at_k(pred, rel, k=3, threshold=THRESHOLD_ACT) == round(1 / 2, 4)
    assert precision_at_k(pred, rel, k=3, threshold=THRESHOLD_ACTIONABLE) == round(2 / 3, 4)
    assert recall_at_k(pred, rel, k=3, threshold=THRESHOLD_ACTIONABLE) == round(2 / 3, 4)


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
    assert ndcg_at_k([], rel_dict, k=5) == 0.0
    assert spearman_correlation([], []) == 0.0


def test_metrics_invalid_k():
    rel_dict = {"A": 3, "B": 2}
    pred = ["A", "B"]
    assert ndcg_at_k(pred, rel_dict, k=0) == 0.0
    assert ndcg_at_k(pred, rel_dict, k=-1) == 0.0
    assert precision_at_k(pred, rel_dict, k=0) == 0.0
    assert precision_at_k(pred, rel_dict, k=-5) == 0.0
    assert recall_at_k(pred, rel_dict, k=0) == 0.0
    assert recall_at_k(pred, rel_dict, k=-2) == 0.0


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
