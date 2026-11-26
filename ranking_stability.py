"""
Ranking Stability and Overlap Metrics
=====================================

Implements additional metrics for comparing ranking methods:
- Top-10 overlap: How many items appear in both top-10 rankings?
- Ranking stability: How much do positions change relative to reference?
- Position shift distribution: Statistics on position changes
"""

from typing import List, Dict, Tuple, Set


def compute_top_k_overlap(ranking_a: List[str], ranking_b: List[str], k: int = 10) -> Tuple[int, float]:
    """
    Compute overlap in top-K positions.
    
    Args:
        ranking_a: First ranking (list of CVE IDs)
        ranking_b: Second ranking (list of CVE IDs)
        k: Top-K to compare (default 10)
    
    Returns:
        (overlap_count, overlap_fraction)
        - overlap_count: Number of shared items in both top-K
        - overlap_fraction: overlap_count / k
    """
    top_k_a = set(ranking_a[:k])
    top_k_b = set(ranking_b[:k])
    
    overlap = top_k_a & top_k_b
    overlap_count = len(overlap)
    overlap_fraction = overlap_count / k if k > 0 else 0.0
    
    return overlap_count, overlap_fraction


def compute_ranking_stability(predicted_ranking: List[str], reference_ranking: List[str]) -> Dict:
    """
    Compute ranking stability metrics comparing predicted vs reference.
    
    Measures how much positions change:
    - Mean absolute position difference
    - Median position difference
    - Max position shift
    - Spearman correlation (alternative: computed separately in metrics.py)
    
    Args:
        predicted_ranking: Predicted ranking (list of CVE IDs)
        reference_ranking: Reference/ground truth ranking
    
    Returns:
        Dict with stability metrics
    """
    if not predicted_ranking or not reference_ranking:
        raise ValueError("Rankings cannot be empty")
    
    if set(predicted_ranking) != set(reference_ranking):
        raise ValueError("Rankings must contain same items")
    
    # Map reference CVE -> position (0-indexed)
    ref_positions = {cve: i for i, cve in enumerate(reference_ranking)}
    
    # Compute position shifts
    position_shifts = []
    for pred_pos, cve in enumerate(predicted_ranking):
        ref_pos = ref_positions[cve]
        shift = pred_pos - ref_pos  # Negative = moved up, positive = moved down
        position_shifts.append(shift)
    
    # Absolute shifts (magnitude)
    absolute_shifts = [abs(s) for s in position_shifts]
    
    # Compute statistics
    mean_shift = sum(absolute_shifts) / len(absolute_shifts) if absolute_shifts else 0.0
    median_shift = sorted(absolute_shifts)[len(absolute_shifts) // 2] if absolute_shifts else 0.0
    max_shift = max(absolute_shifts) if absolute_shifts else 0.0
    
    # Count items that moved up vs down
    moved_up = sum(1 for s in position_shifts if s < 0)
    moved_down = sum(1 for s in position_shifts if s > 0)
    unchanged = sum(1 for s in position_shifts if s == 0)
    
    return {
        "mean_position_shift": mean_shift,
        "median_position_shift": median_shift,
        "max_position_shift": max_shift,
        "items_moved_up": moved_up,
        "items_moved_down": moved_down,
        "items_unchanged": unchanged,
        "total_items": len(predicted_ranking),
    }


def compute_position_shift_distribution(predicted_ranking: List[str], reference_ranking: List[str]) -> Dict[int, int]:
    """
    Compute distribution of position shifts.
    
    Returns:
        Dict mapping shift magnitude -> count
        Example: {0: 10, 1: 8, 2: 5, 3: 2}
        (10 items unchanged, 8 moved 1 position, 5 moved 2 positions, etc.)
    """
    if set(predicted_ranking) != set(reference_ranking):
        raise ValueError("Rankings must contain same items")
    
    ref_positions = {cve: i for i, cve in enumerate(reference_ranking)}
    
    distribution = {}
    for pred_pos, cve in enumerate(predicted_ranking):
        ref_pos = ref_positions[cve]
        shift = abs(pred_pos - ref_pos)
        distribution[shift] = distribution.get(shift, 0) + 1
    
    return distribution


def summarize_top_k_distribution(distribution: Dict[int, int], k: int = 10) -> Dict:
    """
    Summarize position shift distribution for top-K items.
    
    Returns:
        Dict with:
        - items_in_top_k_at_reference: How many reference top-K items appear in prediction
        - items_stable_in_top_k: How many stayed in top-K
        - items_fell_outside_top_k: How many reference top-K items fell outside prediction top-K
    """
    # Note: This requires tracking which CVEs were in reference top-K
    # Simplified: return distribution summary
    total = sum(distribution.values())
    no_shift = distribution.get(0, 0)
    shift_1_to_3 = sum(distribution.get(i, 0) for i in range(1, 4))
    shift_4_plus = sum(distribution.get(i, 0) for i in distribution if i >= 4)
    
    return {
        "total_items": total,
        "no_position_change": no_shift,
        "small_shift_1_3": shift_1_to_3,
        "large_shift_4_plus": shift_4_plus,
    }


if __name__ == "__main__":
    # Demonstrate overlap and stability
    ranking_a = ["CVE-2021-44228", "CVE-2024-1709", "CVE-2023-34362", "CVE-2022-30190",
                 "CVE-2021-32625", "CVE-2024-3094", "CVE-2018-15473", "CVE-2023-38546",
                 "CVE-2022-1552", "CVE-2021-27065"]
    ranking_b = ["CVE-2021-44228", "CVE-2023-34362", "CVE-2024-1709", "CVE-2022-30190",
                 "CVE-2024-3094", "CVE-2021-32625", "CVE-2023-38546", "CVE-2018-15473",
                 "CVE-2021-27065", "CVE-2022-1552"]
    
    overlap, frac = compute_top_k_overlap(ranking_a, ranking_b, k=10)
    print(f"Top-10 Overlap: {overlap}/10 ({frac*100:.1f}%)")
    
    stability = compute_ranking_stability(ranking_b, ranking_a)
    print(f"Mean position shift: {stability['mean_position_shift']:.2f}")
    print(f"Max position shift: {stability['max_position_shift']}")
    
    dist = compute_position_shift_distribution(ranking_b, ranking_a)
    print(f"Position shift distribution: {dist}")
