"""
Vulture-AI Annotation Consensus Computation
============================================

Derives consensus labels from independent annotations using transparent
majority-vote and adjudication processes.

Consensus procedures:
1. Majority vote when clear winner exists
2. Ties handled by documented tie-breaking rules
3. Adjudication flag for disputed items
4. Confidence weighting optional

Consensus labels are NOT generated synthetically; they derive from
actual annotator data.
"""

from typing import Dict, List, Tuple, Optional
from annotation_schema import Annotation, ALLOWED_LABELS, LABEL_ORDINAL


class ConsensusTie(Exception):
    """Raised when consensus cannot be determined (tie)."""
    pass


def majority_vote(labels: List[str]) -> Tuple[str, int, List[str]]:
    """
    Determine majority-vote label.
    
    Args:
        labels: List of labels (e.g., ["Act", "Act", "Track"])
    
    Returns:
        (consensus_label, vote_count, tied_labels_if_any)
    
    Raises:
        ConsensusTie: If no clear majority (e.g., 2-way tie).
    """
    if not labels:
        raise ValueError("Cannot vote on empty label list")
    
    counts = {}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    
    max_count = max(counts.values())
    winners = [label for label, count in counts.items() if count == max_count]
    
    if len(winners) > 1:
        raise ConsensusTie(
            f"Tie between {len(winners)} labels with {max_count} votes each: {winners}"
        )
    
    return winners[0], max_count, []


def majority_vote_with_tiebreak(
    labels: List[str],
    tiebreak_method: str = "severity"
) -> Tuple[str, int, str]:
    """
    Majority vote with deterministic tie-breaking.
    
    Args:
        labels: List of labels
        tiebreak_method: One of:
            - "severity": Higher severity label wins (Act > Attend > Track > Defer)
            - "confidence": Would use confidence if available
    
    Returns:
        (consensus_label, vote_count, tiebreak_applied)
    """
    if not labels:
        raise ValueError("Cannot vote on empty label list")
    
    counts = {}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    
    max_count = max(counts.values())
    winners = [label for label, count in counts.items() if count == max_count]
    
    if len(winners) == 1:
        return winners[0], max_count, ""
    
    # Tie-breaking
    if tiebreak_method == "severity":
        # Higher ordinal = higher severity
        winner = max(winners, key=lambda x: LABEL_ORDINAL[x])
        return winner, max_count, f"tiebreak={tiebreak_method}"
    else:
        raise ValueError(f"Unknown tiebreak method: {tiebreak_method}")


def compute_consensus_for_cve(
    annotations: List[Annotation],
    allow_tie: bool = False,
    tiebreak_method: str = "severity"
) -> Dict:
    """
    Compute consensus label for a single CVE.
    
    Args:
        annotations: List of Annotation objects for one CVE from multiple raters
        allow_tie: If True, return tie info instead of raising
        tiebreak_method: How to break ties (see majority_vote_with_tiebreak)
    
    Returns:
        Dict with:
        - cve_id (str)
        - consensus_label (str or None)
        - n_annotations (int)
        - n_raters (int)
        - vote_counts (dict of label -> count)
        - majority_threshold (int)
        - is_tie (bool)
        - tiebreak_applied (str)
        - error (str or None)
    """
    if not annotations:
        return {
            "cve_id": "UNKNOWN",
            "consensus_label": None,
            "n_annotations": 0,
            "n_raters": 0,
            "vote_counts": {},
            "majority_threshold": 0,
            "is_tie": False,
            "tiebreak_applied": "",
            "error": "No annotations provided",
        }
    
    cve_id = annotations[0].cve_id
    labels = [a.label for a in annotations]
    raters = set(a.annotator_id for a in annotations)
    
    vote_counts = {}
    for label in labels:
        vote_counts[label] = vote_counts.get(label, 0) + 1
    
    majority_threshold = len(labels) // 2 + 1
    
    result = {
        "cve_id": cve_id,
        "n_annotations": len(labels),
        "n_raters": len(raters),
        "vote_counts": vote_counts,
        "majority_threshold": majority_threshold,
        "is_tie": False,
        "tiebreak_applied": "",
        "error": None,
    }
    
    try:
        consensus, vote_count, _ = majority_vote(labels)
        result["consensus_label"] = consensus
    except ConsensusTie as e:
        if allow_tie:
            result["is_tie"] = True
            result["error"] = str(e)
            result["consensus_label"] = None
        else:
            # Apply tiebreak
            consensus, vote_count, tiebreak_info = majority_vote_with_tiebreak(
                labels, tiebreak_method
            )
            result["consensus_label"] = consensus
            result["tiebreak_applied"] = tiebreak_info
    
    return result


def compute_consensus_for_dataset(
    cve_annotations: Dict[str, List[Annotation]],
    allow_ties: bool = False,
    tiebreak_method: str = "severity"
) -> Dict:
    """
    Compute consensus labels for entire dataset.
    
    Args:
        cve_annotations: Dict mapping CVE_ID -> list of Annotation
        allow_ties: If True, don't auto-tiebreak; flag ties as unresolved
        tiebreak_method: How to break ties when not allowing explicit ties
    
    Returns:
        Dict with:
        - total_cves (int)
        - consensus_labels (dict of cve_id -> label)
        - ties (list of cve_ids with ties, if allow_ties=True)
        - errors (list of error messages)
        - per_cve_consensus (list of full per-CVE results)
    """
    consensus_labels = {}
    ties = []
    errors = []
    per_cve_results = []
    
    for cve_id, annotations in cve_annotations.items():
        result = compute_consensus_for_cve(
            annotations,
            allow_tie=allow_ties,
            tiebreak_method=tiebreak_method
        )
        per_cve_results.append(result)
        
        if result["consensus_label"]:
            consensus_labels[cve_id] = result["consensus_label"]
        
        if result.get("is_tie"):
            ties.append(cve_id)
        
        if result.get("error"):
            errors.append(f"{cve_id}: {result['error']}")
    
    return {
        "total_cves": len(cve_annotations),
        "consensus_cves": len(consensus_labels),
        "consensus_labels": consensus_labels,
        "ties": ties,
        "errors": errors,
        "per_cve_consensus": per_cve_results,
    }


if __name__ == "__main__":
    # Demonstrate consensus computation
    from annotation_schema import Annotation
    
    # Synthetic data: mixed agreement and ties
    anns = [
        Annotation("CVE-2021-44228", "RATER_01", "Act"),
        Annotation("CVE-2021-44228", "RATER_02", "Act"),
        Annotation("CVE-2021-44228", "RATER_03", "Attend"),
    ]
    
    result = compute_consensus_for_cve(anns, allow_tie=False, tiebreak_method="severity")
    print(f"CVE: {result['cve_id']}")
    print(f"Consensus: {result['consensus_label']}")
    print(f"Votes: {result['vote_counts']}")
    print(f"Tie-break applied: {result.get('tiebreak_applied', 'None')}")
