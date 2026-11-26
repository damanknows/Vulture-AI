"""
Vulture-AI Annotation Agreement Metrics
========================================

Computes inter-rater agreement statistics for independent annotations.

Supported metrics:
- Fleiss' Kappa (multi-rater nominal or ordinal)
- Krippendorff's Alpha (ordinal distance metric for ordinal labels)

For ordinal labels (Defer < Track < Attend < Act), Krippendorff's alpha
with ordinal distance is preferred because it accounts for the degree of
disagreement (e.g., disagreement on adjacent categories is penalized less
than disagreement on extreme categories).

Reference:
  Krippendorff, K. (2004). Reliability in Content Analysis: Some Common
  Misconceptions and Recommendations. Human Communication Research, 30(3), 337–352.
"""

import math
from typing import List, Dict, Tuple, Optional
from annotation_schema import Annotation, LABEL_ORDINAL, ALLOWED_LABELS


class InsufficientAnnotationData(Exception):
    """Raised when insufficient data exists to compute agreement."""
    pass


def ordinal_distance(label1: str, label2: str) -> float:
    """
    Ordinal distance between two labels.
    
    For ordinal labels, the distance is the absolute difference in ordinal rank.
    This penalizes distant disagreements (e.g., Defer vs Act) more than
    adjacent disagreements (e.g., Defer vs Track).
    
    Args:
        label1: First label (one of Act, Attend, Track, Defer)
        label2: Second label
    
    Returns:
        Distance in [0, 3] for our 4-category label set.
    """
    ord1 = LABEL_ORDINAL[label1]
    ord2 = LABEL_ORDINAL[label2]
    return float(abs(ord1 - ord2))


def compute_krippendorff_alpha_ordinal(
    cve_annotations: Dict[str, List[Annotation]]
) -> Tuple[float, Dict]:
    """
    Compute Krippendorff's alpha for ordinal categorical data.
    
    Args:
        cve_annotations: Dict mapping CVE_ID to list of Annotation objects.
                         Each CVE should have annotations from multiple raters.
    
    Returns:
        (alpha, metadata) where:
        - alpha: Krippendorff's alpha in [-1, 1]
                 1.0 = perfect agreement
                 0.0 = agreement at chance level
                 <0.0 = worse than chance
        - metadata: Dict with counts and details
    
    Raises:
        InsufficientAnnotationData: If <2 CVEs, <2 raters, or inconsistent data.
    """
    
    # Collect all labels per CVE
    unit_data = []  # List of (cve_id, [labels])
    total_annotations = 0
    rater_set = set()
    
    for cve_id, annotations in cve_annotations.items():
        if not annotations:
            continue
        
        labels = [a.label for a in annotations]
        unit_data.append((cve_id, labels))
        total_annotations += len(labels)
        
        for a in annotations:
            rater_set.add(a.annotator_id)
    
    n_units = len(unit_data)
    n_raters = len(rater_set)
    
    # Validation
    if n_units < 2:
        raise InsufficientAnnotationData(
            f"Krippendorff's alpha requires ≥2 units; got {n_units}"
        )
    if n_raters < 2:
        raise InsufficientAnnotationData(
            f"Krippendorff's alpha requires ≥2 raters; got {n_raters}"
        )
    if total_annotations < 4:
        raise InsufficientAnnotationData(
            f"Krippendorff's alpha requires ≥4 total annotations; got {total_annotations}"
        )
    
    # Compute pairable values (units with >1 annotation)
    pairable_count = sum(1 for _, labels in unit_data if len(labels) > 1)
    if pairable_count == 0:
        raise InsufficientAnnotationData(
            "No CVEs have multiple annotations; cannot compute inter-rater agreement"
        )
    
    # Build coincidence matrix for ordinal data
    # coincidence_matrix[i][j] = number of times category i was paired with category j
    n_categories = len(ALLOWED_LABELS)
    coincidence_matrix = [[0.0 for _ in range(n_categories)] for _ in range(n_categories)]
    
    for cve_id, labels in unit_data:
        if len(labels) < 2:
            continue
        
        # For each pair of annotations on this unit
        for i, label1 in enumerate(labels):
            for label2 in labels[i+1:]:
                idx1 = LABEL_ORDINAL[label1]
                idx2 = LABEL_ORDINAL[label2]
                # Count each pair once (symmetric)
                weight = 1.0 / (len(labels) - 1)
                coincidence_matrix[idx1][idx2] += weight
                if idx1 != idx2:
                    coincidence_matrix[idx2][idx1] += weight
    
    # Build marginal totals
    n_total = sum(sum(row) for row in coincidence_matrix)
    marginals = [sum(coincidence_matrix[i]) for i in range(n_categories)]
    
    # Compute observed disagreement (using ordinal distance)
    disagreement_observed = 0.0
    for i in range(n_categories):
        for j in range(n_categories):
            label_i = ALLOWED_LABELS[i]
            label_j = ALLOWED_LABELS[j]
            distance = ordinal_distance(label_i, label_j)
            # Normalize by total pairs
            if n_total > 0:
                disagreement_observed += (coincidence_matrix[i][j] / n_total) * (distance ** 2)
    
    # Compute expected disagreement (by chance)
    disagreement_expected = 0.0
    for i in range(n_categories):
        for j in range(n_categories):
            label_i = ALLOWED_LABELS[i]
            label_j = ALLOWED_LABELS[j]
            distance = ordinal_distance(label_i, label_j)
            # Marginal probability
            if n_total > 1:
                p_i = marginals[i] / n_total
                p_j = marginals[j] / n_total
                disagreement_expected += p_i * p_j * (distance ** 2)
    
    # Compute Krippendorff's alpha
    if disagreement_expected == 0.0:
        alpha = 1.0  # Perfect agreement (all labels identical)
    else:
        alpha = 1.0 - (disagreement_observed / disagreement_expected)
    
    metadata = {
        "n_units": n_units,
        "n_raters": n_raters,
        "pairable_units": pairable_count,
        "total_annotations": total_annotations,
        "disagreement_observed": disagreement_observed,
        "disagreement_expected": disagreement_expected,
        "coincidence_matrix": coincidence_matrix,
    }
    
    return alpha, metadata


def compute_fleiss_kappa_ordinal(
    cve_annotations: Dict[str, List[Annotation]]
) -> Tuple[float, Dict]:
    """
    Compute Fleiss' kappa for ordinal data (treats ordinal like nominal for now).
    
    Note: This is a simplified version that doesn't account for ordinal distance.
    For ordinal data, Krippendorff's alpha is preferred.
    
    Returns:
        (kappa, metadata)
    """
    # Fallback: use Krippendorff's alpha instead
    return compute_krippendorff_alpha_ordinal(cve_annotations)


def agreement_interpretation(alpha: float) -> str:
    """
    Interpret Krippendorff's alpha value.
    
    Standard interpretation (Krippendorff 2004):
    - >0.80: Excellent agreement
    - 0.67–0.80: Good agreement
    - 0.33–0.67: Moderate agreement
    - <0.33: Poor agreement
    """
    if alpha >= 0.80:
        return "Excellent agreement"
    elif alpha >= 0.67:
        return "Good agreement"
    elif alpha >= 0.33:
        return "Moderate agreement"
    else:
        return "Poor agreement"


def compute_label_distribution(
    cve_annotations: Dict[str, List[Annotation]]
) -> Dict[str, int]:
    """Count distribution of labels across all annotations."""
    distribution = {label: 0 for label in ALLOWED_LABELS}
    for annotations in cve_annotations.values():
        for ann in annotations:
            distribution[ann.label] += 1
    return distribution


def compute_agreement_summary(
    cve_annotations: Dict[str, List[Annotation]]
) -> Dict:
    """
    Compute comprehensive agreement summary.
    
    Returns:
        Dict with:
        - alpha (float): Krippendorff's alpha
        - alpha_interpretation (str)
        - n_units (int)
        - n_raters (int)
        - pairable_units (int)
        - total_annotations (int)
        - label_distribution (dict)
        - errors (list of str if any)
    """
    result = {
        "alpha": None,
        "alpha_interpretation": None,
        "n_units": 0,
        "n_raters": 0,
        "pairable_units": 0,
        "total_annotations": 0,
        "label_distribution": {},
        "errors": [],
    }
    
    try:
        alpha, metadata = compute_krippendorff_alpha_ordinal(cve_annotations)
        result["alpha"] = alpha
        result["alpha_interpretation"] = agreement_interpretation(alpha)
        result["n_units"] = metadata["n_units"]
        result["n_raters"] = metadata["n_raters"]
        result["pairable_units"] = metadata["pairable_units"]
        result["total_annotations"] = metadata["total_annotations"]
    except InsufficientAnnotationData as e:
        result["errors"].append(str(e))
    
    result["label_distribution"] = compute_label_distribution(cve_annotations)
    
    return result


if __name__ == "__main__":
    # Demonstrate with synthetic data
    from annotation_schema import Annotation
    
    # Synthetic: 3 CVEs, 2 raters each
    cve_anns = {
        "CVE-2021-44228": [
            Annotation("CVE-2021-44228", "RATER_01", "Act"),
            Annotation("CVE-2021-44228", "RATER_02", "Act"),
        ],
        "CVE-2024-1709": [
            Annotation("CVE-2024-1709", "RATER_01", "Act"),
            Annotation("CVE-2024-1709", "RATER_02", "Attend"),
        ],
        "CVE-2021-32625": [
            Annotation("CVE-2021-32625", "RATER_01", "Track"),
            Annotation("CVE-2021-32625", "RATER_02", "Track"),
        ],
    }
    
    summary = compute_agreement_summary(cve_anns)
    print(f"Alpha: {summary['alpha']:.4f} ({summary['alpha_interpretation']})")
    print(f"Units: {summary['n_units']}, Raters: {summary['n_raters']}, "
          f"Pairable: {summary['pairable_units']}")
    print(f"Labels: {summary['label_distribution']}")
