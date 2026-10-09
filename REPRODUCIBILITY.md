# Vulture Risk Score (VRS) Experimental Pipeline

This directory contains the reproducible experimental evaluation pipeline for the Vulture Risk Score (VRS) vulnerability prioritization module.

## Directory Structure
- `data/benchmark/cves.csv`: The evaluation dataset (snapshot frozen).
- `experiments/`: Scripts for evaluating baselines and ablations.
- `experiments/results/`: Machine-readable metrics and Markdown tables.

## Dataset & Proxy Labels
**WARNING: Proxy-Labeled Benchmark**
The `data/benchmark/cves.csv` dataset contains proxy-labeled priorities (derived from expert rubrics) for 200–500 CVEs.
Because genuine large-scale expert judgments (ground-truth exploitability/impact assessments) are scarce, this benchmark heavily relies on proxy heuristics. 
- The dataset serves to test the mathematical determinism and integration of the VRS pipeline.
- It **does not** establish real-world detection superiority. Claims of statistical significance or outperformance against baselines (like CVSS) are restricted to this specific synthetic distribution.

## Running the Pipeline

To reproduce the evaluation results:

1. **Run Baselines:**
   Computes CVSS-only, EPSS-only, Combo (CVSS+EPSS+KEV), and VRS-Proposed rankings.
   ```bash
   python experiments/run_baselines.py
   ```
   *Output saved to `experiments/results/baselines.json`*

2. **Run Ablation Studies:**
   Evaluates the VRS without EPSS, without KEV, and without contextual metrics (Exposure/Criticality).
   ```bash
   python experiments/run_ablation.py
   ```
   *Output saved to `experiments/results/ablation.json`*

3. **Compute Metrics:**
   Computes NDCG@5, NDCG@10, and Spearman Rank Correlation.
   ```bash
   python experiments/compute_metrics.py
   ```
   *Output saved to `experiments/results/metrics_table.md`*

4. **Evaluate RAG Pipeline:**
   Executes deterministic factual accuracy tests across the 4 RAG configuration modes (No Context, Scan Context, RAG, RAG + Validator) including prompt injection simulation.
   ```bash
   python experiments/evaluate_rag.py
   ```

## Reproducibility Guarantees
- **No LLM in Core Scoring:** The `risk_engine.py` operates purely mathematically.
- **Fixed Sorting:** Tie-breaking is strictly resolved alphabetically by primary CVE ID.
- **Immutable References:** The validation sets are strictly separate from tuning.

## Summary of Findings (Initial Proxy Evaluation)
Based on the proxy-labeled dataset, the VRS demonstrates strong monotonic rank correlation (Spearman) relative to CVSS+EPSS baselines. However, because the ground truth labels intrinsically mirror a blended rubric, these results validate the *implementation correctness* of the weighting system rather than its external predictive validity. Further evaluation on independently confirmed breaches is required before deployment in high-stakes environments.
