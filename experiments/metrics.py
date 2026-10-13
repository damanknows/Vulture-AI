"""
Vulture-AI Evaluation Metrics Module
====================================

This module implements mathematically rigorous, deterministic evaluation metrics
for vulnerability prioritization algorithms:

1. NDCG@K (Normalized Discounted Cumulative Gain at K):
   Evaluates graded ranking quality using standard exponential relevance gain
   and logarithmic rank discount:
   DCG@K = sum_{i=1}^K (2^{rel_i} - 1) / log2(i + 1)
   NDCG@K = DCG@K / IDCG@K

2. Precision@K and Recall@K:
   Evaluates top-K retrieval at two documented decision thresholds:
   - Primary Threshold (tau = 3): Act / Emergency Remediation items
   - Secondary Threshold (tau = 2): Actionable items (Act or Attend remediation)

3. Spearman Rank Correlation Coefficient (rho):
   Measures monotonic alignment between algorithmic ranking and reference priority.
   Uses fractional mid-ranks for ties and Pearson correlation of ranks:
   rho = cov(R_pred, R_ref) / (sigma_{R_pred} * sigma_{R_ref})
   Strictly validates input populations (rejects duplicates and mismatched item sets),
   and gracefully returns 0.0 for constant inputs with zero variance.
"""

from typing import Any, Dict, List, Sequence, Union
import numpy as np
import scipy.stats

# Standard SSVC evaluation thresholds
THRESHOLD_ACT = 3         # Act (Emergency remediation)
THRESHOLD_ACTIONABLE = 2  # Act or Attend (Remediation required)


def validate_ranking_population(predicted: Sequence[Any], reference: Sequence[Any]) -> None:
    """
    Validates that predicted and reference rankings:
    1. Are non-empty sequences.
    2. Contain no duplicate identifiers.
    3. Contain the exact same population of items.
    """
    if not predicted or not reference:
        raise ValueError("Rankings cannot be empty.")

    pred_list = list(predicted)
    ref_list = list(reference)
    pred_set = set(pred_list)
    ref_set = set(ref_list)

    if len(pred_list) != len(pred_set):
        seen = set()
        dups = set()
        for x in pred_list:
            if x in seen:
                dups.add(x)
            seen.add(x)
        raise ValueError(f"Duplicate identifiers detected in predicted ranking: {dups}")

    if len(ref_list) != len(ref_set):
        seen = set()
        dups = set()
        for x in ref_list:
            if x in seen:
                dups.add(x)
            seen.add(x)
        raise ValueError(f"Duplicate identifiers detected in reference ranking: {dups}")

    if pred_set != ref_set:
        missing = ref_set - pred_set
        extra = pred_set - ref_set
        raise ValueError(
            f"Ranking populations mismatch: {len(missing)} missing items ({sorted(list(missing))[:3]}...), "
            f"{len(extra)} extra items ({sorted(list(extra))[:3]}...)"
        )


def ndcg_at_k(predicted_ranking: Sequence[str], relevance_dict: Dict[str, int], k: int = 10) -> float:
    """
    Computes Normalized Discounted Cumulative Gain at K using standard exponential DCG:
    DCG@K = sum_{i=1}^K (2^{rel_i} - 1) / log2(i + 1)
    NDCG@K = DCG@K / IDCG@K
    """
    if not predicted_ranking or not relevance_dict or k <= 0:
        return 0.0

    # Ensure no duplicates in top-k evaluation sequence
    if len(predicted_ranking) != len(set(predicted_ranking)):
        raise ValueError("Duplicate items found in predicted ranking for NDCG calculation.")

    dcg = 0.0
    for i, p in enumerate(predicted_ranking[:k]):
        rel = relevance_dict.get(p, 0)
        # i is 0-indexed, so 1-indexed rank is (i + 1), denominator is log2((i + 1) + 1) = log2(i + 2)
        dcg += (2 ** rel - 1) / np.log2(i + 2)

    ideal_sorted_cves = sorted(relevance_dict.keys(), key=lambda x: relevance_dict[x], reverse=True)
    idcg = 0.0
    for i, p in enumerate(ideal_sorted_cves[:k]):
        rel = relevance_dict.get(p, 0)
        idcg += (2 ** rel - 1) / np.log2(i + 2)

    if idcg <= 0.0:
        return 0.0

    return float(round(dcg / idcg, 4))


def precision_at_k(
    predicted_ranking: Sequence[str],
    relevance_dict: Dict[str, int],
    k: int = 10,
    threshold: int = THRESHOLD_ACT
) -> float:
    """
    Computes Precision@K: the proportion of items in the top-K ranking
    whose relevance grade meets or exceeds threshold.
    """
    if not predicted_ranking or not relevance_dict or k <= 0:
        return 0.0

    if len(predicted_ranking) != len(set(predicted_ranking)):
        raise ValueError("Duplicate items found in predicted ranking for Precision calculation.")

    top_k = predicted_ranking[:k]
    hits = sum(1 for cve in top_k if relevance_dict.get(cve, 0) >= threshold)
    return float(round(hits / k, 4))


def recall_at_k(
    predicted_ranking: Sequence[str],
    relevance_dict: Dict[str, int],
    k: int = 10,
    threshold: int = THRESHOLD_ACT
) -> float:
    """
    Computes Recall@K: the proportion of all relevant items in relevance_dict
    (relevance grade >= threshold) that appear in the top-K ranking.
    """
    if not predicted_ranking or not relevance_dict or k <= 0:
        return 0.0

    if len(predicted_ranking) != len(set(predicted_ranking)):
        raise ValueError("Duplicate items found in predicted ranking for Recall calculation.")

    total_relevant = sum(1 for rel in relevance_dict.values() if rel >= threshold)
    if total_relevant == 0:
        return 0.0

    top_k = predicted_ranking[:k]
    hits = sum(1 for cve in top_k if relevance_dict.get(cve, 0) >= threshold)
    return float(round(hits / total_relevant, 4))


def spearman_correlation(
    predicted: Union[Sequence[Any], Dict[str, float]],
    reference: Union[Sequence[Any], Dict[str, float]]
) -> float:
    """
    Computes Spearman Rank Correlation Coefficient (rho).
    
    Robustness features:
    - Strict population validation: rejects duplicate items and population mismatches.
    - Tie-handling: uses fractional mid-ranks for tied items.
    - Constant ranking safety: returns 0.0 for constant inputs with zero variance.
    - Supports both identifier permutations (lists) and score mappings (dicts).
    """
    if not predicted or not reference:
        return 0.0

    if isinstance(predicted, dict) and isinstance(reference, dict):
        if set(predicted.keys()) != set(reference.keys()):
            raise ValueError("Dictionary key populations must match for Spearman correlation.")
        sorted_keys = sorted(predicted.keys())
        x = np.array([predicted[k] for k in sorted_keys], dtype=float)
        y = np.array([reference[k] for k in sorted_keys], dtype=float)
    elif isinstance(predicted, (list, tuple)) and isinstance(reference, (list, tuple)):
        # Numeric values without identifiers
        if len(predicted) > 0 and isinstance(predicted[0], (int, float)) and isinstance(reference[0], (int, float)):
            if len(predicted) != len(reference):
                raise ValueError("Numeric lists must have identical lengths for Spearman correlation.")
            x = np.array(predicted, dtype=float)
            y = np.array(reference, dtype=float)
        else:
            # String identifiers
            validate_ranking_population(predicted, reference)
            ref_dict = {item: i + 1 for i, item in enumerate(reference)}
            pred_dict = {item: i + 1 for i, item in enumerate(predicted)}
            sorted_items = sorted(predicted)
            x = np.array([pred_dict[item] for item in sorted_items], dtype=float)
            y = np.array([ref_dict[item] for item in sorted_items], dtype=float)
    else:
        raise TypeError("Predicted and reference must be both dicts or both lists/tuples.")

    # Guard against zero variance (constant inputs)
    if np.all(x == x[0]) or np.all(y == y[0]):
        return 0.0

    val = scipy.stats.spearmanr(x, y).statistic
    if np.isnan(val):
        return 0.0
    return float(round(float(val), 4))
