# Vulture Risk Score (VRS) Experimental Pipeline: Reproducibility Guide

This document provides exact, deterministic instructions to reproduce all vulnerability prioritization experiments, baselines, ablations, and figures in Vulture-AI.

## 1. Benchmark Dataset
- **File**: `data/benchmark/cves.csv`
- **Sample Count**: 41 records (39 verified real public CVEs + 2 synthetic missing-data edge cases)
- **SHA-256 Hash**: `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`
- **Snapshot Date**: `2026-10-14T00:00:00Z`
- **Data Provenance**:
  - CVSS v3.1: National Vulnerability Database (NIST NVD v2.0 API)
  - EPSS: FIRST.org live probability feed snapshot
  - KEV: CISA Known Exploited Vulnerabilities catalog (version `2026.10.13`)
  - Reference Labels: CISA Stakeholder-Specific Vulnerability Categorization (SSVC) Decision Rubric:
    - `Act` (Relevance = 3): 15 CVEs (Emergency mass-exploitation in KEV on exposed critical assets)
    - `Attend` (Relevance = 2): 12 CVEs (Weaponized exploits or local/client KEV listings)
    - `Track` (Relevance = 1): 8 CVEs (Standard maintenance / no public exploitation evidence)
    - `Defer` (Relevance = 0): 6 CVEs (Low severity / missing data test cases)

*Synthetic Edge Cases*: `CVE-2024-99991` (missing CVSS) and `CVE-2024-99992` (missing EPSS) use non-existent identifiers to verify missing-data fallback handling.

## 2. Compared Prioritization Methods
1. **CVSS-only**: Ranked by `cvss_score / 10.0` descending; deterministic tie-break: `cve_id` ascending. Missing CVSS sinks to bottom.
2. **EPSS-only**: Ranked by `epss_probability` descending; deterministic tie-break: `cve_id` ascending. Missing EPSS sinks to bottom.
3. **KEV-first**: Ranked by KEV status (1 before 0), then CVSS score descending; deterministic tie-break: `cve_id` ascending.
4. **CVSS + EPSS + KEV**: Equal linear combination baseline ($1/3 \cdot C + 1/3 \cdot E + 1/3 \cdot K$).
5. **Vulture-AI (VRS Proposed, `vrs-v1`)**: Context-aware weighted combination $VRS = 100 \times (0.25 C + 0.20 E + 0.20 K + 0.20 N + 0.15 A)$ with policy override bucket (`"urgent"` for KEV matches) and deterministic tie-breaking.

## 3. Reproduction Commands

To reproduce all baseline rankings, metrics, tables, and figures from scratch:

```bash
# 1. Run Unified Reproduction Runner (recomputes all baselines, ablations, metrics, tables, and manifest)
python experiments/reproduce_all.py
# Or via Makefile:
make reproduce

# 2. Run All Automated Unit & Benchmark Tests
pytest -v
# Or via Makefile:
make test
```

## 4. Empirical Evaluation Results (Exact Generated Output)

### Primary K=10 Evaluation ($N=41$)
| Model | NDCG@10 | P@10 (Act) | R@10 (Act) | P@10 (Actionable) | R@10 (Actionable) | Spearman |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **CVSS-only** | 0.7563 | 0.6000 | 0.4000 | 1.0000 | 0.3704 | 0.7357 |
| **EPSS-only** | 0.9217 | 0.8000 | 0.5333 | 1.0000 | 0.3704 | 0.8237 |
| **KEV-first** | 0.7945 | 0.7000 | 0.4667 | 1.0000 | 0.3704 | 0.8247 |
| **CVSS+EPSS+KEV** | 0.9513 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.8800 |
| **VRS Proposed (vrs-v1)** | **1.0000** | **1.0000** | **0.6667** | **1.0000** | **0.3704** | **0.9488** |
| VRS (No EPSS) | 1.0000 | 1.0000 | 0.6667 | 1.0000 | 0.3704 | 0.9575 |
| VRS (No KEV) | 0.9581 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.9451 |
| VRS (No Context) | 0.9513 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.8782 |
| VRS (No Bucket Override) | 1.0000 | 1.0000 | 0.6667 | 1.0000 | 0.3704 | 0.9535 |

### Multi-Budget Depth Sensitivity ($K \in \{5, 10, 15\}$)
| Model | NDCG@5 | NDCG@10 | NDCG@15 | Spearman |
|:---|:---:|:---:|:---:|:---:|
| CVSS-only | 0.8062 | 0.7563 | 0.7855 | 0.7357 |
| EPSS-only | 1.0000 | 0.9217 | 0.8878 | 0.8237 |
| KEV-first | 0.8062 | 0.7945 | 0.8407 | 0.8247 |
| CVSS+EPSS+KEV | 0.9250 | 0.9513 | 0.9373 | 0.8800 |
| **VRS Proposed (vrs-v1)** | **1.0000** | **1.0000** | **1.0000** | **0.9488** |
| VRS (No EPSS) | 1.0000 | 1.0000 | 1.0000 | 0.9575 |
| VRS (No KEV) | 1.0000 | 0.9581 | 0.9675 | 0.9451 |
| VRS (No Context) | 0.9250 | 0.9513 | 0.9130 | 0.8782 |
| VRS (No Bucket Override) | 1.0000 | 1.0000 | 1.0000 | 0.9535 |

## 5. Artifact Output Files
- `experiments/results/baselines.json`: Full per-record predictions and raw scores.
- `experiments/results/ablation.json`: Per-variant ablated rankings under proportional renormalization.
- `experiments/results/metrics.json`: Machine-readable multi-budget evaluation metrics.
- `experiments/results/metrics_table.md`: Formatted Markdown comparison table.
- `experiments/results/tables/main_comparison.tex`: Verified LaTeX table for paper inclusion.
- `experiments/results/tables/multi_budget.tex`: Multi-budget depth sensitivity LaTeX table.
- `experiments/results/tables/ablation.tex`: Verified LaTeX ablation table.
- `experiments/results/figures/ranking_comparison.png`: Generated plot comparing method rankings vs. reference priority.
- `experiments/results/reproducibility_manifest.json`: Complete execution provenance manifest.
