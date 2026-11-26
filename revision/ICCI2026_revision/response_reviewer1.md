# Response to Reviewer #1

**Paper 144:** Vulture-AI. **Decision:** Accept After Modification.

**Attribution note.** The revision record does not assign concerns to named reviewers. This letter covers the concerns on novelty, benchmark construction, baselines, weights, and guardrails (Concerns 1–5 and 8–11 below), which are the methodological comments. Concerns on retrieval, explanation, references, and matching are in Reviewer #2's letter. Please reconcile against the original reviewer identities if they differ.

---

## Concern 1: Novelty and differentiation from SSVC and CVSS v4.0
**Comment (summarised from the revision record):** Paper claims novelty in multi-factor prioritization, but SSVC formalizes decision trees over exploitation, exposure, and impact. How does VRS differ substantively from automating SSVC tiers, and what does it add beyond CVSS v4.0 environmental metrics?

**Modification.** We removed the novelty claim for the indicators and the weighted-sum form. The Introduction now states three contributions: a combined scoring design, a score-integrity boundary, and an evaluation with explicit scope. Related Work §3 explains that VRS is a continuous score with a binary KEV bucket and is not an implementation of the SSVC tree. Related Work §2 explains that CVSS v3.1 and v4.0 include optional Environmental and Threat groups.

**Section.** Introduction (contributions); Related Work §2–3; System Architecture.

**Experiment added.** None. We did not implement or evaluate an SSVC decision tree or CVSS v4.0 scores.

**Result.** Not available for the SSVC tree or CVSS v4.0 comparison.

**Status: partially addressed.** The claim is narrowed, and the comparison that would test "beyond SSVC" and "beyond CVSS v4.0" is not run. The manuscript says so in Related Work §3 and in Threats.

---

## Concern 2: Circular author-generated benchmark labels
**Comment:** Reference labels are author-curated under an SSVC-based rubric. SSVC uses KEV, EPSS, and exposure, the same features VRS uses, so high agreement reflects feature alignment, not validation. How do you disentangle this?

**Modification.** The Methodology section now states the overlap directly and says that high agreement measures consistency with the rubric, not predictive validity. The Threats section lists circularity as the most important limit. The Discussion separates measured findings from hypotheses.

**Section.** Methodology (Benchmark construction and reference labels); Threats (Ground-truth circularity); Discussion.

**Experiment added.** None that removes the circularity. Independent annotation was not performed.

**Result.** The Phase 1 annotation infrastructure exists, but no annotator data was produced (`revision/PHASE1_IMPLEMENTATION_REPORT.md` lists independent validation as pending). No inter-rater agreement is reported. The ablation that removes context (Spearman 0.9488 → 0.8782) is reported as evidence of rubric dependence, not as a validation result.

**Status: partially addressed.** Circularity is disclosed and quantified in the sense that the ablation shows the rubric depends on context. It is not resolved. Independent labels are the required next step.

---

## Concern 4: Unjustified VRS weights
**Comment:** The default weights (0.25, 0.20, 0.20, 0.20, 0.15) look arbitrary. How were they chosen, and what is the impact of varying them?

**Modification.** The Methodology section calls the weights exploratory, states that they were set by the authors and not fitted to the benchmark, and reports the sensitivity results. The Results section includes a weight-sensitivity paragraph.

**Section.** Methodology (VRS formula); Results (Weight sensitivity); Discussion (Weight stability); Threats (Weight selection).

**Experiment.** The Phase 2 sensitivity run (`experiments/revision/sensitivity/results.json`) evaluates six configurations: default, equal, CVSS-heavy, EPSS-heavy, context-heavy, and exposure-heavy.

**Result.** All six configurations produce the same top-10 set as the default (10 of 10 overlap in each). We did not compute a rank-correlation summary over the full ordering, so full-ranking stability is not reported.

**Status: partially addressed.** The weights are disclosed as exploratory, and top-10 stability is measured. No derivation procedure exists, and the paper does not claim one. A full-ordering stability analysis and a held-out weight selection remain undone.

---

## Concern 3: Baselines lack network exposure and asset criticality
**Comment:** Baselines use only C, E, and K, while VRS uses N and A. This asymmetry means the comparison may reflect data availability, not method quality.

**Modification.** We added four context-aware baselines that use exposure or criticality: EPSS×Exposure, Exposure×Criticality, Context-Enhanced CVSS, and EPSS×Context. The "No Context" ablation removes N and A from VRS.

**Section.** Methodology (Baselines); Results (Context-aware baselines, Table III; Ablations, Table IV); Threats (Baseline fairness).

**Experiment added.** Phase 2 baselines (`experiments/revision/baselines/results_context.json`) and the existing ablation.

**Result (Table III, 41-record benchmark):**

| Method | NDCG@10 | R@10 (Act) | Spearman |
|---|---|---|---|
| EPSS×Exposure | 1.0000 | 0.6667 | 0.8909 |
| Exposure×Criticality | 0.9552 | 0.6000 | 0.8951 |
| Context-Enhanced CVSS | 0.9458 | 0.6000 | 0.9243 |
| EPSS×Context | 1.0000 | 0.6667 | 0.9334 |
| VRS | 1.0000 | 0.6667 | 0.9488 |

Removing context from VRS lowers Spearman from 0.9488 to 0.8782, close to the vulnerability-only combination (0.8800). The context-aware baselines are competitive: EPSS×Context is 0.0154 below VRS on Spearman. We did not compute paired intervals of VRS against these four baselines in this revision; the Phase 3 output covers only the original baselines. VRS therefore shows no demonstrated advantage over EPSS×Context on this benchmark.

**Status: addressed with new baselines, with a negative result disclosed.** The asymmetry is removed. The added baselines match VRS closely, and the manuscript says VRS is not shown to be better.

---

## Concern 5: Guardrail evaluation is insufficient
**Comment:** The evaluation covers eight regex patterns on a deterministic mock and five banners on a live model. How does it generalize to unknown attacks, multilingual prompts, or frontier models? What is the false-negative rate?

**Modification.** We added a 60-case corpus (30 benign, 30 adversarial, version 1.0.0) with channel labels, a confusion matrix, Wilson intervals, and a per-case error table. The Results section reports false positives and false negatives by name. The Threats section lists the limits.

**Section.** Results (Guardrail evaluation, Table VI); Threats (Guardrail corpus limitations); Conclusion.

**Experiment added.** Phase 4 guardrail evaluation (`experiments/revision/guardrail/`). A deterministic stub model drives the score-integrity harness.

**Result (48 inspected cases, retrieved content only):** TP 9, FN 16, FP 7, TN 16. Recall 0.36 (Wilson 95% [0.20, 0.55]); false-positive rate 0.30 ([0.16, 0.51]); precision 0.56; accuracy 0.52. The 12 cases on queries, banners, and descriptions are not inspected by the filter and are excluded from these rates.

**Not done.** We did not test frontier models, multilingual prompts, or multi-turn attacks. The live-model result cited in the earlier manuscript has no run artifact in the repository (`experiments/results/rag_eval.json` records `live_model_evaluated: false`), so we removed it from the claims. The reviewer's concern about frontier models is therefore not addressed.

**Status: addressed in part.** The false-negative and false-positive rates are now measured on a corpus we report in full. The filter is shown to be weak (recall 0.36) and it is described as a narrow check, not a defense. Generalization to other models, languages, and channels is not established.

---

## Concern 8: Small benchmark; no confidence intervals or significance tests
**Comment:** The 41-record benchmark is small. No confidence intervals or tests are given. NDCG@10 = 1.0 could be a small-sample artifact.

**Modification.** We added bootstrap intervals (2,000 paired resamples, seed 20261126) for each metric and model, and paired intervals for VRS minus each baseline. The NDCG@10 ceiling is explained in the Results section.

**Section.** Results (Table II, bootstrap; ceiling discussion); Methodology (Metrics); Threats (Small benchmark; Metric limitations).

**Experiment added.** Phase 3 bootstrap and paired analysis (`experiments/revision/statistics/`).

**Result (Table II, from `paired_comparisons.csv`):**
- Spearman, VRS minus CVSS-only: +0.213, [0.055, 0.430]. Excludes zero.
- Spearman, VRS minus EPSS-only: +0.125, [0.048, 0.243]. Excludes zero.
- Spearman, VRS minus CVSS+EPSS+KEV: +0.069, [0.020, 0.169]. Excludes zero.
- Spearman, VRS minus KEV-first: +0.124, [−0.001, 0.307]. Includes zero.
- NDCG@10, all baselines: intervals include zero, because VRS attains 1.0 in all 2,000 resamples.

The bootstrap intervals are descriptive. No p-values are reported, and no significance is claimed. The bootstrap resamples records, so duplicates and the discrete metric scale mean nominal coverage is not guaranteed. The Phase 3 report records 75 warnings.

**Status: addressed for intervals; significance tests are not reported.** We judged that a classical test is not valid for these metrics (one ranking per model, no independent observations). The manuscript explains this in the Methodology.

---

## Concern 9: Temporal leakage from later EPSS and KEV snapshots
**Comment:** The manuscript uses EPSS and KEV snapshots dated 2026-10-13. If the paper predates that, the evaluation uses future information.

**Modification.** The Experimental Setup now states the snapshot dates and the temporal setting: all features come from a single 2026 snapshot; EPSS and KEV contain post-disclosure information; the evaluation is retrospective present-state prioritization and makes no early-prediction claim. We removed claims that imply prediction at disclosure.

**Section.** Experimental Setup (Data sources and snapshot; Temporal setting); Threats (Temporal leakage); Conclusion.

**Experiment added.** None. Historical reconstruction was not feasible: no archived daily EPSS values or NVD CVSS history exist in the repository, and we did not download them.

**Result.** The EPSS cache holds 461 entries, all dated 2026-10-13 (verified). The KEV feed is version 2026.10.13 with 1,741 entries. The 461 added CVEs have 2023–2024 publication dates in `source_timestamp` while their features are 2026 values (`revision/TEMPORAL_AUDIT.md`).

**Status: addressed by disclosure; historical evaluation not performed.** The temporal leakage is real and is now stated. A point-in-time evaluation is future work.

---

## Concern 10: Possible lack of independence in the 500-CVE experiment
**Comment:** The 500-CVE corpus includes the 39 curated CVEs. Are they also in the evaluation? This may be training on test data.

**Modification.** The Results section states that the 500-CVE corpus includes the 39 curated records, that KEV entries in the corpus all come from those 39, and that the KEV concordance is a policy-consistency check because the KEV flag is both an input and the evaluation label. The concordance is restricted to the 39 curated records for SSVC-based statements.

**Section.** Results (Retrospective KEV concordance); Experimental Setup; Threats (Data-source limitations).

**Experiment added.** None. The overlap is an existing property of the corpus.

**Result.** 0 of 461 added CVEs are in the KEV feed (`revision/evidence/kev_consistency.json`). The 25 KEV entries are all among the 39 curated records. Weights were not fitted to either set; the weights are fixed defaults. The overlap therefore does not show tuning on test data, but it does mean the 39 records appear in both analyses.

**Status: addressed by disclosure.** The overlap is stated. No independent 500-CVE labels exist, so the KEV-based check remains circular for KEV-first and the urgent bucket.

---

## Concern 11: Missing actionable metrics
**Comment:** Only ranking metrics are reported. What about false-positive rate, false-negative rate, or time-to-remediation?

**Modification.** We defined and computed Actionable Precision@10 and Recall@10 (grade ≥ 2; denominators 10 and 27). The Methodology states the definitions and tie handling. The Results report that they do not discriminate between methods. Time-to-remediation and analyst productivity are not measured, and the manuscript says so.

**Section.** Methodology (Metrics, Actionable metrics); Results (Point estimates); Threats (Metric limitations).

**Experiment added.** Actionable P@10 and R@10 were computed in the Phase 3 verification and match `metrics.py` for every model.

**Result.** Actionable P@10 = 1.0000 and Actionable R@10 = 0.3704 for every ranking. The 27-record denominator includes Attend items. These metrics therefore do not separate methods on this benchmark.

**Not done.** Time-to-remediation and SOC analyst productivity were not measured. We removed claims that imply operational effect.

**Status: partially addressed.** The metrics are computed and reported as non-discriminative. Operational outcome measures are absent and are listed as future work.

---

## Summary for Reviewer #1

Concerns 1–5 and 8–11 are addressed to the extent the evidence allows. We added context baselines, bootstrap intervals, and a guardrail corpus, and each reports its actual values, including the negative ones. Concerns 1, 2, 4, and 11 remain partially addressed, because the comparisons (SSVC tree, CVSS v4.0 scores, independent labels, full-ordering stability, operational outcomes) were not run.
