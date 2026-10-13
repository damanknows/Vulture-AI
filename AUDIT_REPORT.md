# Vulture-AI: Research Validity and Reproducibility Audit Report

**Auditor:** Senior Cybersecurity Research & Evaluation Engineer  
**Date:** 2026-10-14  
**Target Venue:** 7th International Conference on Computing and Informatics (ICCI 2026)  
**Target Repository:** [Vulture-AI](https://github.com/damanknows/Vulture-AI)  
**Evaluation Target:** 41-CVE Public Benchmark & Reproducible Pipeline (`research-v2`)

---

## 1. Executive Summary

This independent audit evaluated the experimental methodology, ground-truth label derivation, metric implementations, feature ablations, and manuscript reproducibility of the Vulture-AI vulnerability prioritization system.

The core algorithm—the Vulture Risk Score (VRS)—is a mathematically deterministic, transparent linear weighting model ($w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15$) with an urgent bucket override for CISA Known Exploited Vulnerabilities (KEV). The engineering implementation is structurally sound: 55 unit/integration tests pass (1 integration test skipped; requires network/root Nmap), the pipeline executes deterministically via `python experiments/reproduce_all.py`, and the benchmark hash is validated by SHA-256 (`27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`).

However, from an academic peer-review standpoint, the experimental methodology contains critical methodological limitations and construct dependencies that must be transparently addressed prior to camera-ready publication:

1. **Construct Circularity**: Ground-truth ordinal labels are mapped from CISA SSVC decision categories, which determine priority using exploitation likelihood (KEV/EPSS), exposure ($N$), and impact (CVSS/Asset Criticality). Furthermore, the environmental features ($N$ and $A$) in `cves.csv` were manually authored to align with these SSVC tiers. Therefore, high performance ($\text{NDCG@10}=1.0$, $\rho=0.9488$) demonstrates **construct consistency / heuristic alignment** with SSVC triage logic, rather than empirical proof of external breach prediction.
2. **Ceiling Effects at $K=10$**: Because the benchmark's top-10 items are universally extreme (CVSS $\ge 9.8$, KEV=1, EPSS $\ge 0.94$, Exposure 1.0), multiple distinct models (`VRS Full`, `VRS No EPSS`, and `VRS No Bucket Override`) achieve identical $\text{NDCG@10}=1.0000$ and $\text{P@10}=1.0000$. Similarly, because 27 of 41 items are "Actionable", every evaluated model achieves identical Actionable Precision (1.0000) and Recall (0.3704).
3. **EPSS Ablation Dynamics**: Removing EPSS increases Spearman correlation from 0.9488 to 0.9575. This is not an implementation bug; it occurs because EPSS rewards high-frequency, low-impact vulnerabilities (e.g. OpenSSH user enumeration, Tomcat DoS), whereas SSVC de-prioritizes them. Removing EPSS allows CVSS and Exposure to dominate, aligning more closely with SSVC.

---

## 2. Categorized Audit Findings

### Critical Findings (Paper Integrity & Scientific Validity)

#### [CRIT-1] Construct Circularity and Ground-Truth Coupling in Environmental Context
* **Location**: `data/benchmark/cves.csv` (lines 2–42); `risk_engine.py` (lines 8–18)
* **Evidence**:
  In `cves.csv`, the environmental features (`exposure` $N$ and `asset_criticality` $A$) were not captured from real live network scans or an independent topology; they were manually assigned to match the CISA SSVC decision categories:
  - All 15 "Act" records were assigned $N \in [0.8, 1.0]$ and $A \in [0.9, 1.0]$.
  - All 12 "Attend" records were assigned $N \in [0.3, 0.8]$ and $A \in [0.6, 0.8]$.
  - All 8 "Track" records were assigned $N \in [0.2, 0.7]$ and $A \in [0.5, 0.7]$.
  - All 6 "Defer" records were assigned $N \in [0.2, 0.6]$ and $A \in [0.2, 0.5]$.
* **Scientific Implication**:
  Because $N$ and $A$ were constructed to mirror the SSVC categories, and VRS includes $w_N \cdot N + w_A \cdot A$, the benchmark exhibits **construct circularity**. The strong performance does not demonstrate empirical discovery; it reflects tautological alignment with the heuristic rule-set used to synthesize the inputs.
* **Remediation**:
  Explicitly state in the manuscript and documentation that the benchmark evaluates *heuristic alignment with CISA SSVC decision trees under canonical deployment archetypes*, not predictive validity against unobserved enterprise breach data.

#### [CRIT-2] Ceiling Effect & Discriminative Failure at $K=10$
* **Location**: `experiments/compute_metrics.py` (lines 48–62); `experiments/results/metrics.json`
* **Evidence**:
  1. **Actionable Threshold ($\tau = 2$)**: 27 out of 41 records (65.9%) are Actionable. Every evaluated model fills its top-10 slots with items from this set. Thus, Precision@10 is 1.0000 and Recall@10 is $10/27 \approx 0.3704$ across all 9 model configurations.
  2. **Act Threshold ($\tau = 3$)**: The top 10 items in `cves.csv` are prominent zero-days with near-maximal metrics across all five dimensions. Consequently, `VRS Full`, `VRS No EPSS`, and `VRS No Bucket Override` all achieve identical NDCG@10 (1.0000) and Precision@10 (1.0000).
* **Scientific Implication**:
  The metric at $K=10$ is saturated and cannot discriminate between the proposed method and its architectural ablations.
* **Remediation**:
  Evaluate and report metrics across multiple cutoffs (e.g., $K=5$, $K=15$) and include Mean Reciprocal Rank (MRR) or Average Precision (MAP) to reveal ranking divergence masked by $K=10$.

---

### High Findings (Methodological & Interpretive Clarity)

#### [HIGH-1] Counterintuitive EPSS Ablation Behavior (EPSS Removal Increases Spearman Correlation)
* **Location**: `experiments/run_ablation.py`; `experiments/results/ablation.json` (lines 61–146)
* **Evidence**:
  Spearman correlation rises from $\rho = 0.9488$ (`VRS Full`) to $\rho = 0.9575$ (`VRS No EPSS`).
* **Root Cause Analysis**:
  EPSS reflects statistical exploit prediction regardless of impact. In the benchmark:
  - `CVE-2018-15473` (OpenSSH user enumeration) has $\text{EPSS} = 0.986$, but $\text{CVSS} = 5.3$ and $\text{SSVC} = \text{Defer}$ (rank 36).
  - `CVE-2020-13935` (Tomcat WebSocket DoS) has $\text{EPSS} = 0.866$, but $\text{CVSS} = 7.5$ and $\text{SSVC} = \text{Track}$ (rank 35).
  In `VRS Full`, EPSS promotes these low-impact vulnerabilities upward. When EPSS is ablated ($w_E = 0$), CVSS and Exposure dominate, demoting them back down toward their low SSVC reference positions.
* **Remediation**:
  Document this divergence in the paper as a substantive finding: EPSS measures exploit likelihood (which includes low-impact automated scanning), whereas SSVC emphasizes mission impact. Removing EPSS aligns better with impact-dominated rubrics.

#### [HIGH-2] Severe Benchmark Selection Bias toward Famous "Headline" Vulnerabilities
* **Location**: `data/benchmark/cves.csv` (lines 2–42)
* **Evidence**:
  The benchmark almost exclusively features famous, branded vulnerabilities (Log4Shell, MOVEit, ScreenConnect, Spring4Shell, EternalBlue, Zerologon, XZ Utils, Follina, PrintNightmare, Dirty Pipe).
* **Scientific Implication**:
  In real enterprise environments, over 95% of scanner findings are obscure internal library dependencies with low EPSS and ambiguous exploit status. The benchmark evaluates performance on a curated "hall of fame" rather than the noisy long-tail of real-world findings.
* **Remediation**:
  Explicitly classify this as a "Representative Archetype Benchmark" rather than a naturalistic enterprise corpus, and identify long-tail enterprise evaluation as future work.

---

### Medium Findings (Documentation & Presentation Precision)

#### [MED-1] Conflation of Absolute Metric Point Difference with Percentage Change
* **Location**: `paper/manuscript.tex` (lines 28, 219)
* **Evidence**:
  The manuscript claims "a 7.1% gain in rank correlation" for the drop from $\rho = 0.9488$ to $\rho = 0.8782$. The absolute difference is $0.9488 - 0.8782 = 0.0706$ ($\approx 0.071$), while the relative percentage change is $(0.9488 - 0.8782) / 0.9488 = 7.44\%$.
* **Remediation**:
  Rephrase text to explicitly distinguish between absolute correlation difference (+0.0706) and relative change (+7.44%).

#### [MED-2] Ambiguous Snapshot Timestamp Semantics
* **Location**: `data/benchmark/cves.csv` (lines 2–42)
* **Evidence**:
  `source_timestamp` is uniformly set to `2026-10-14T00:00:00Z` for all rows, spanning CVEs published between 2015 and 2024.
* **Remediation**:
  Clarify in `data/benchmark/README.md` that `source_timestamp` represents the intelligence retrieval snapshot date, not the initial CVE disclosure date.

---

### Low Findings (Code Quality & Ergonomics)

#### [LOW-1] Fixed $K=10$ Budget Across Reporting Scripts
* **Location**: `experiments/compute_metrics.py`; `experiments/make_tables.py`
* **Evidence**:
  Reporting scripts hardcode $K=10$ without accepting CLI arguments for alternative cutoff depths ($K=5, 15, 20$).
* **Remediation**:
  Parameterize cutoff depths in `compute_metrics.py` to allow multi-cutoff evaluation.

---

## 3. Potential Data Leakage and Ground-Truth Independence Assessment

| Dimension | Assessment | Finding / Status |
|---|---|---|
| **Data Leakage across Splits** | N/A | Unsupervised heuristic ranking; no ML training/test split exists. |
| **Feature Re-use in Ground Truth** | Present | CISA SSVC decision tree uses Exploitation (correlating with KEV/EPSS), Exposure ($N$), and Impact ($C, A$). |
| **Environmental Feature Synthesization** | Present | $N$ and $A$ in `cves.csv` were assigned specifically to match the SSVC tier archetypes. |
| **Intra-Tier Order Independence** | Absent | 1-to-41 ranking inside tiers was manually ordered based on expert severity intuition, matching VRS design. |

**Verdict**: The benchmark does not possess independent external ground truth (such as breach occurrences or SOC mean-time-to-remediate). It evaluates **internal construct consistency and heuristic alignment**. This distinction must be maintained across all research claims.

---

## 4. Metric Implementation Assessment

The ranking metrics in `experiments/metrics.py` were audited against formal mathematical specifications:

1. **Spearman Rank Correlation ($\rho$)**:
   - Uses `scipy.stats.spearmanr` on aligned item permutations.
   - Accurately assigns fractional mid-ranks for tied items.
   - Validates ranking population (`validate_ranking_population`), catching duplicates and mismatched sets.
   - Safely returns `0.0` for zero-variance constant arrays.
   - Verified against a 4-item hand-calculated manual example ($r = 0.9487$).
2. **NDCG@K**:
   - Implements standard exponential formulation: $\sum_{i=1}^K \frac{2^{\text{rel}_i} - 1}{\log_2(i+1)}$.
   - Ideal DCG correctly sorts relevance grades descending.
   - Verified against hand-calculated manual example ($\text{NDCG@3} = 0.7896$).
3. **Precision@K & Recall@K**:
   - Formally parameterized at $\tau=3$ (Act, $N=15$) and $\tau=2$ (Actionable, $N=27$).
   - Accurately normalizes by $K$ (Precision) and total class population (Recall).

---

## 5. Ablation Interpretation

| Variant | Formulation | NDCG@10 | Spearman ($\rho$) | Interpretation |
|---|---|---|---|---|
| **VRS (Full Model)** | $w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15$ + Urgent Bucket | 1.0000 | 0.9488 | Complete context-aware prioritization. |
| **VRS (No EPSS)** | $w_E=0$, Proportional Renormalization | 1.0000 | 0.9575 | Removing EPSS improves Spearman because SSVC de-prioritizes high-EPSS low-impact flaws (e.g. OpenSSH user enum). |
| **VRS (No KEV Weight)** | $w_K=0$, Proportional Renormalization | 0.9581 | 0.9451 | Deactivating KEV drops NDCG@10 from 1.0000 to 0.9581 as unexploited flaws enter top 10. |
| **VRS (No Context)** | $w_N=0, w_A=0$, Proportional Renormalization | 0.9513 | 0.8782 | Dropping Exposure and Asset Criticality causes the largest performance drop (-0.0706 $\rho$). |
| **VRS (No Bucket Override)** | Full weights, Pure Numerical Score Ranking | 1.0000 | 0.9535 | Continuous scoring alone surfaces KEV items to the top tier without requiring categorical bucket overrides. |

---

## 6. Reproducibility & Manuscript Consistency Assessment

1. **Reproduction Runner**: `experiments/reproduce_all.py` runs end-to-end and outputs:
   - `experiments/results/baselines.json`
   - `experiments/results/ablation.json`
   - `experiments/results/metrics.json`
   - `experiments/results/metrics_table.md`
   - `experiments/results/tables/main_comparison.tex`
   - `experiments/results/tables/ablation.tex`
   - `experiments/results/figures/ranking_comparison.png`
   - `experiments/results/reproducibility_manifest.json`
2. **Determinism**: 100% deterministic; zero stochastic components in scoring or tie-breaking.
3. **Manuscript Alignment**:
   - Table 1 (Main Comparison) and Table 2 (Ablation) in `paper/manuscript.tex` match `metrics.json` exactly.
   - `paper/manuscript.pdf` compiles cleanly (6 pages) with no broken references.

---

## 7. Prioritized Remediation Plan

1. **Step 1 (Immediate - Manuscript & Documentation)**:
   - Qualify all claims regarding "outperforming baselines" to clarify that the benchmark measures heuristic alignment with CISA SSVC decision categories on canonical archetypes.
   - Clarify the EPSS ablation rationale in Section VI (Discussion).
   - Rephrase the "7.1% gain" in the abstract and results to distinguish absolute point differences (+0.0706) from relative percentage changes (+7.44%).
2. **Step 2 (Immediate - Multi-Budget Metric Support)**:
   - Update `experiments/compute_metrics.py` and `experiments/make_tables.py` to evaluate $K=5$ and $K=15$ in addition to $K=10$, resolving the ceiling effect.
3. **Step 3 (Pre-Camera Ready)**:
   - Add a table footnote explaining why Actionable Precision (1.0000) and Recall (0.3704) are identical across models at $K=10$ due to budget saturation.

---

## 8. Additional Experiments Recommended for Journal Extension

1. **Long-Tail Uncurated Benchmark ($N \ge 1,000$)**:
   Evaluate VRS on randomly sampled CVEs from the full NVD catalog, where EPSS probabilities are low and KEV listing is rare.
2. **Empirical Honeypot / SOC Telemetry Evaluation**:
   Compare VRS rankings against actual intrusion attempt frequencies observed on live enterprise perimeter honeypots or SIEM alert queues rather than synthetic SSVC labels.
3. **Sensitivity Analysis of Default Weights**:
   Perform a Monte Carlo or grid search over the simplex $\sum w_i = 1$ to map sensitivity landscapes and verify that performance is stable across weight perturbations.
