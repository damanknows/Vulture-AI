# Remaining Unresolved Reviewer Concerns

Status key: **Open** = not addressed; **Partial** = addressed in part, with a named gap; **Disclosed** = addressed by stating the limitation, with no new evidence.

| # | Concern | Status | What remains | What would resolve it |
|---|---|---|---|---|
| 1 | Novelty vs SSVC and CVSS v4.0 | **Partial** | No comparison against an SSVC decision tree or CVSS v4.0 scores was run. The paper claims only a narrower contribution. | Implement the SSVC tree and CVSS v4.0 scoring on the same inputs; compare. |
| 2 | Circular author-generated labels | **Partial** | Labels are author judgments; no independent annotation; the circularity is disclosed and partly quantified by the context ablation. | Independent analysts re-rate the 41 records blind to VRS; compute agreement with the Phase 1 pipeline. |
| 3 | Baseline information asymmetry | **Partial (disclosed negative)** | Context baselines were added, and `paired_comparisons.csv` includes their paired bootstrap intervals against VRS (all four include zero on NDCG@10 and Spearman). EPSS×Context is competitive with VRS (+0.015 [-0.038, 0.080] Spearman). | Larger independent benchmark to test whether VRS's 5-input weighting improves over simpler context products. |
| 4 | Unjustified weights | **Partial** | Weights are exploratory and hard-coded. Top-10 is stable across six configurations. No full-ordering stability summary, and no selection procedure. | Compute Spearman/Kendall stability across configurations; state a held-out selection procedure if weights are to be tuned. |
| 5 | Guardrail evaluation | **Partial** | 60-case corpus with confusion matrix. Frontier models, multilingual prompts, multi-turn attacks, and the query/banner channels are not tested. The live-model claim has no artifact and was removed. | Run the corpus against live models with logged versions and settings; extend the corpus to other channels and languages. |
| 6 | RAG retrieval unclear | **Addressed by correction** | Retrieval quality is not measured. The paper does not claim retrieval quality. | Not required for the current claims. |
| 7 | Explanation quality | **Open** | Not measured. No ratings exist. | Human raters on a sampled set (with inter-rater statistic), or a documented automated judge with a human spot-check. |
| 8 | Small benchmark; intervals and tests | **Partial** | Bootstrap intervals provided. No significance tests (judged invalid for these metrics). Benchmark remains small (n=41). | Larger independently labelled benchmark. |
| 9 | Temporal leakage | **Disclosed** | Evaluation is retrospective present-state. Historical reconstruction not performed. | Archived daily EPSS, NVD CVSS history, KEV `dateAdded` as-of evaluation at several decision dates. |
| 10 | 500-CVE independence | **Disclosed** | The 39 curated records appear in both analyses. KEV concordance is circular for KEV-first and the urgent bucket. | Evaluate on CVEs not in the curated set, with independent labels. |
| 11 | Actionable metrics | **Partial** | Actionable P@10 and R@10 computed; they do not discriminate. No time-to-remediation or analyst-productivity data. | Operational study with remediation timestamps and analyst workload. |
| 12 | Missing and incorrect references | **Partial** | Verified set corrected and extended. Unconfirmed: EPSS methodology venue, Greshake venue and pages, SEI SSVC report. ML/LLM triage and context-aware enterprise sources not found. "EPSS v2" not found in pages read. | Confirm the three venue records; obtain sources for ML/LLM triage or drop the claim. |
| 13 | CPE/Nmap matching evaluation | **Open** | No accuracy, false-negative, or version-ambiguity evaluation. Only four unit tests exist, and they do not measure accuracy. | Labelled corpus of scan outputs with correct CVE identifiers; report precision, recall, and ambiguity cases. |

## Open data issues that affect the headline numbers

- **KEV flag discrepancy (4 records in `cves.csv`).** CVE-2022-1292 and CVE-2019-15846 are flagged `kev=1` but are absent from the 2026.10.13 feed; CVE-2021-3560 and CVE-2022-0492 are flagged `kev=0` but are listed. The headline results use the flags as they are. Correcting them could change the KEV-first, VRS, and combined results. This decision belongs to the authors, and it was not made in this revision, because the task forbids changing benchmark labels or results. Evidence: `revision/evidence/kev_consistency.json`.
- **Benchmark `source_timestamp` for added records.** Publication dates are shown, but features are 2026 values. Disclosed in the paper; the CSV is unchanged.

## Items not completed in this revision

- The manuscript was **not compiled to PDF**. No LaTeX engine is installed here. Structural checks passed, but the PDF build and page-length check (IEEE conference format) remain to be run by the authors.
- **Figure 1** was not visually inspected (the image viewer failed in this session). Its extracted text matches the table values.
- **BOD 26-04** (the current directive) was identified but not read. The paper refers only to BOD 22-01's history.
- The **live-model results** from the earlier manuscript were removed because no run artifact exists. If the authors have a run log with model version, date, and settings, it should be added to the repository and the claim reinstated with that artifact.
