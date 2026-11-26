"""
Vulture-AI Revision Experiment Runner (Phase 2)
===============================================

Unified entry point for Phase 2 experiments:
- Context-aware baselines
- Weight sensitivity analysis
- Ranking stability and overlap metrics
- Reproducible output with full configuration tracking

IMPORTANT: This script preserves all original results and does not modify
the original VRS algorithm, baseline definitions, or benchmark.

Run:
    python3 revision_experiments.py
"""

import os
import json
import sys
from datetime import datetime
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_data import load_and_validate_benchmark, compute_benchmark_sha256, BENCHMARK_CSV_PATH
from experiments.run_baselines import load_benchmark, run_baselines
from risk_engine import compute_vrs, rank_findings
from context_baselines import (
    compute_baseline_epss_exposure,
    compute_baseline_exposure_criticality,
    compute_baseline_context_enhanced_cvss,
    compute_baseline_epss_context,
)
from weight_sensitivity import get_weight_config, list_weight_configs, validate_weights
from ranking_stability import compute_top_k_overlap, compute_ranking_stability, compute_position_shift_distribution

# Try importing metrics; if numpy unavailable, provide alternatives
try:
    from experiments.metrics import ndcg_at_k, precision_at_k, recall_at_k, spearman_correlation
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    print("WARNING: numpy-based metrics unavailable. Using fallback metrics only.")


def rank_by_scores(findings: List[Dict], scores: List[float], method_name: str) -> List[str]:
    """
    Rank findings by scores (descending).
    
    Args:
        findings: List of finding dicts
        scores: List of scores corresponding to findings
        method_name: Name for error messages
    
    Returns:
        Ranked list of CVE IDs
    
    Raises:
        ValueError: If lengths don't match or scores are invalid
    """
    if len(findings) != len(scores):
        raise ValueError(f"{method_name}: Length mismatch: {len(findings)} findings vs {len(scores)} scores")
    
    # Create (score, cve_id, orig_idx) tuples
    scored_items = []
    for idx, (finding, score) in enumerate(zip(findings, scores)):
        cve_id = finding["cve_matches"][0]["cve_id"]
        if score is None:
            # Sort None scores to end
            scored_items.append((float('-inf'), cve_id, idx))
        else:
            scored_items.append((score, cve_id, idx))
    
    # Sort by score descending, then by CVE ID ascending (deterministic tie-break)
    scored_items.sort(key=lambda x: (-x[0], x[1]))
    
    return [cve_id for _, cve_id, _ in scored_items]


def compute_baseline_scores(findings: List[Dict], baseline_fn, method_name: str) -> List[float]:
    """Score findings with a baseline function."""
    scores = []
    for finding in findings:
        try:
            score = baseline_fn(finding)
            scores.append(score)
        except Exception as e:
            raise ValueError(f"{method_name}: Error scoring {finding['cve_matches'][0]['cve_id']}: {e}")
    
    return scores


def run_revision_experiments(output_dir: str = "experiments/revision") -> Dict[str, Any]:
    """
    Run all Phase 2 revision experiments.
    
    Args:
        output_dir: Directory to save results (default: experiments/revision)
    
    Returns:
        Dict with all results and metadata
    """
    
    # Setup
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(f"{output_dir}/baselines", exist_ok=True)
    os.makedirs(f"{output_dir}/sensitivity", exist_ok=True)
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    print("=" * 70)
    print("Vulture-AI Phase 2 Revision Experiments")
    print("=" * 70)
    print(f"Start time: {timestamp}")
    print(f"Output dir: {output_dir}")
    print()
    
    # Load benchmark
    print("[1/4] Loading benchmark...")
    records, sha256_hash = load_and_validate_benchmark(BENCHMARK_CSV_PATH)
    findings, ref_ranking, relevance_dict = load_benchmark(BENCHMARK_CSV_PATH)
    print(f"  ✓ Loaded {len(findings)} records")
    print(f"  ✓ SHA-256: {sha256_hash[:16]}...")
    
    # Run original experiments (preserved)
    print("\n[2/4] Running original baselines (preserved)...")
    original_results = run_baselines(BENCHMARK_CSV_PATH)
    original_baselines = {
        "CVSS-only": original_results["cvss_only"],
        "EPSS-only": original_results["epss_only"],
        "KEV-first": original_results["kev_first"],
        "CVSS+EPSS+KEV": original_results["combo_baseline"],
        "VRS Proposed": original_results["vrs_v1"],
    }
    print(f"  ✓ Computed rankings for 5 original baselines")
    
    # Run context-aware baselines
    print("\n[3/4] Running context-aware baselines...")
    context_baselines = {}
    
    # Baseline 1: EPSS × Exposure
    print("  Computing EPSS × Exposure...")
    scores_1 = compute_baseline_scores(findings, compute_baseline_epss_exposure, "EPSS×Exposure")
    ranking_1 = rank_by_scores(findings, scores_1, "EPSS×Exposure")
    context_baselines["EPSS×Exposure"] = ranking_1
    
    # Baseline 2: Exposure × Criticality
    print("  Computing Exposure × Asset Criticality...")
    scores_2 = compute_baseline_scores(findings, compute_baseline_exposure_criticality, "Exposure×Criticality")
    ranking_2 = rank_by_scores(findings, scores_2, "Exposure×Criticality")
    context_baselines["Exposure×Criticality"] = ranking_2
    
    # Baseline 3: Context-Enhanced CVSS
    print("  Computing Context-Enhanced CVSS...")
    scores_3 = compute_baseline_scores(findings, compute_baseline_context_enhanced_cvss, "ContextEnhancedCVSS")
    ranking_3 = rank_by_scores(findings, scores_3, "ContextEnhancedCVSS")
    context_baselines["Context-Enhanced CVSS"] = ranking_3
    
    # Baseline 4: EPSS × Context
    print("  Computing EPSS × Context...")
    scores_4 = compute_baseline_scores(findings, compute_baseline_epss_context, "EPSS×Context")
    ranking_4 = rank_by_scores(findings, scores_4, "EPSS×Context")
    context_baselines["EPSS×Context"] = ranking_4
    
    print(f"  ✓ Computed rankings for 4 context-aware baselines")
    
    # Run weight sensitivity experiments
    print("\n[4/4] Running weight sensitivity experiments...")
    weight_configs = list_weight_configs()
    sensitivity_results = {}
    
    for config_id, config_name in weight_configs.items():
        print(f"  Computing VRS with {config_name}...")
        weights = get_weight_config(config_id)
        validate_weights(weights)
        
        # Score with these weights
        ranked_findings = []
        for finding in findings:
            vrs_result = compute_vrs(finding, weights=weights)
            ranked_findings.append({
                "cve_id": finding["cve_matches"][0]["cve_id"],
                "vrs": vrs_result["vrs"],
                "bucket": vrs_result["bucket"],
            })
        
        # Sort by VRS descending, CVE ascending
        ranked_findings.sort(key=lambda x: (
            -x["vrs"] if x["vrs"] is not None else float('-inf'),
            x["cve_id"]
        ))
        
        ranking = [item["cve_id"] for item in ranked_findings]
        sensitivity_results[config_id] = {
            "config_name": config_name,
            "weights": weights,
            "ranking": ranking,
        }
    
    print(f"  ✓ Computed rankings for {len(weight_configs)} weight configurations")
    
    # Compute metrics if available
    print("\n[Metrics] Computing ranking metrics...")
    
    all_rankings = {}
    all_rankings.update(original_baselines)
    all_rankings.update(context_baselines)
    for config_id, config_data in sensitivity_results.items():
        all_rankings[config_id] = config_data["ranking"]
    
    metrics_results = {}
    for method_name, ranking in all_rankings.items():
        try:
            if METRICS_AVAILABLE:
                ndcg10 = ndcg_at_k(ranking, relevance_dict, k=10)
                p10 = precision_at_k(ranking, relevance_dict, k=10, threshold=3)
                r10 = recall_at_k(ranking, relevance_dict, k=10, threshold=3)
                spearman = spearman_correlation(ranking, ref_ranking)
            else:
                # Fallback: use simple metrics
                ndcg10 = None
                p10 = None
                r10 = None
                spearman = None
            
            metrics_results[method_name] = {
                "ndcg@10": ndcg10,
                "precision@10": p10,
                "recall@10": r10,
                "spearman": spearman,
            }
        except Exception as e:
            print(f"  Warning: Could not compute metrics for {method_name}: {e}")
            metrics_results[method_name] = {"error": str(e)}
    
    # Compute ranking stability and overlap
    print("[Stability] Computing ranking stability relative to reference...")
    stability_results = {}
    
    reference_ranking = all_rankings["VRS Proposed"]  # Use VRS Proposed as reference
    for method_name, ranking in all_rankings.items():
        if method_name == "VRS Proposed":
            continue
        
        try:
            overlap, frac = compute_top_k_overlap(ranking, reference_ranking, k=10)
            stability = compute_ranking_stability(ranking, reference_ranking)
            dist = compute_position_shift_distribution(ranking, reference_ranking)
            
            stability_results[method_name] = {
                "top10_overlap": overlap,
                "top10_overlap_fraction": frac,
                "ranking_stability": stability,
                "position_shift_distribution": dist,
            }
        except Exception as e:
            print(f"  Warning: Could not compute stability for {method_name}: {e}")
            stability_results[method_name] = {"error": str(e)}
    
    # Compile results
    results = {
        "metadata": {
            "timestamp": timestamp,
            "benchmark_file": BENCHMARK_CSV_PATH,
            "benchmark_hash": sha256_hash,
            "total_records": len(findings),
            "metrics_available": METRICS_AVAILABLE,
        },
        "original_baselines": original_baselines,
        "context_aware_baselines": context_baselines,
        "weight_sensitivity": {
            config_id: {
                "config_name": config["config_name"],
                "weights": config["weights"],
                "ranking": config["ranking"],
            }
            for config_id, config in sensitivity_results.items()
        },
        "metrics": metrics_results,
        "stability": stability_results,
    }
    
    # Save results
    print("\n[Save] Writing results to disk...")
    
    with open(f"{output_dir}/baselines/results_original.json", "w") as f:
        json.dump(original_baselines, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/baselines/results_original.json")
    
    with open(f"{output_dir}/baselines/results_context.json", "w") as f:
        json.dump(context_baselines, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/baselines/results_context.json")
    
    with open(f"{output_dir}/sensitivity/results.json", "w") as f:
        json.dump({
            config_id: config["ranking"]
            for config_id, config in sensitivity_results.items()
        }, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/sensitivity/results.json")
    
    with open(f"{output_dir}/sensitivity/configurations.json", "w") as f:
        json.dump({
            config_id: config["weights"]
            for config_id, config in sensitivity_results.items()
        }, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/sensitivity/configurations.json")
    
    with open(f"{output_dir}/metrics.json", "w") as f:
        json.dump(metrics_results, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/metrics.json")
    
    with open(f"{output_dir}/stability.json", "w") as f:
        json.dump(stability_results, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/stability.json")
    
    with open(f"{output_dir}/summary.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"  ✓ Saved: {output_dir}/summary.json")
    
    end_timestamp = datetime.utcnow().isoformat() + "Z"
    print()
    print("=" * 70)
    print(f"End time: {end_timestamp}")
    print("Phase 2 Revision Experiments COMPLETE")
    print("=" * 70)
    
    return results


if __name__ == "__main__":
    try:
        results = run_revision_experiments()
        sys.exit(0)
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
