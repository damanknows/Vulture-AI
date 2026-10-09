import pytest
from experiments.metrics import ndcg_at_k, spearman_correlation

def test_spearman_perfect():
    pred = ["A", "B", "C"]
    ref = ["A", "B", "C"]
    assert abs(spearman_correlation(pred, ref) - 1.0) < 1e-5

def test_spearman_inverse():
    pred = ["A", "B", "C"]
    ref = ["C", "B", "A"]
    assert abs(spearman_correlation(pred, ref) - (-1.0)) < 1e-5

def test_ndcg_perfect():
    # rel: A=3, B=2, C=1
    rel_dict = {"A": 3, "B": 2, "C": 1}
    pred = ["A", "B", "C"]
    assert abs(ndcg_at_k(pred, rel_dict, 3) - 1.0) < 1e-5

def test_ndcg_imperfect():
    rel_dict = {"A": 3, "B": 1, "C": 0}
    
    # Ideal: A (3), B (1), C (0)
    # idcg@2 = (2^3 - 1)/log2(2) + (2^1 - 1)/log2(3) = 7/1 + 1/1.58 = 7 + 0.63 = 7.63
    
    # Pred: B, A, C
    # dcg@2 = (2^1 - 1)/log2(2) + (2^3 - 1)/log2(3) = 1/1 + 7/1.58 = 1 + 4.43 = 5.43
    
    pred = ["B", "A", "C"]
    val = ndcg_at_k(pred, rel_dict, 2)
    
    expected_dcg = 1.0 + (7.0 / 1.5849625)
    expected_idcg = 7.0 + (1.0 / 1.5849625)
    
    assert abs(val - (expected_dcg / expected_idcg)) < 1e-4

def test_spearman_with_ties_in_dataset():
    # If the rankings are strictly ordered lists, spearman formula handles the strict permutation correctly.
    # We just ensure it runs.
    pred = ["A", "B", "C", "D"]
    ref = ["B", "C", "D", "A"]
    res = spearman_correlation(pred, ref)
    # d_sq = (3-0)^2 + (0-1)^2 + (1-2)^2 + (2-3)^2 = 9 + 1 + 1 + 1 = 12
    # 1 - (6 * 12) / (4 * 15) = 1 - 72/60 = 1 - 1.2 = -0.2
    assert abs(res - (-0.2)) < 1e-5
