# Final Revision Audit: Paper 144

**Paper:** Vulture-AI: Context-Aware Vulnerability Prioritization with Guardrailed Retrieval-Augmented Generation
**Decision:** Accept After Modification
**Audit date:** 2026-11-26

## 1. Deliverables

All under `revision/ICCI2026_revision/`:

| File | Purpose |
|---|---|
| `manuscript_revised.tex` | Revised manuscript (387 lines, 9 sections, 7 tables, 1 figure) |
| `references_revised.bib` | Original bibliography plus 9 verified entries |
| `response_combined.md` | Combined response letter with summary table |
| `response_reviewer1.md` | Response to Reviewer #1 (concerns 1–5, 8–11) |
| `response_reviewer2.md` | Response to Reviewer #2 (concerns 6, 7, 9*, 10*, 12, 13) |
| `CHANGELOG.md` | Change log from the original to the revised draft |
| `UNRESOLVED.md` | Open and partial concerns, with what would resolve each |
| `integrity_comparison.json` | Saved before/after score-integrity results |
| `original/` | Preserved original manuscript and bib, with SHA-256 checksums |

\* Concerns 9 and 10 have data-side parts that are assigned to Reviewer #2. Their methodological parts are in Reviewer #1's letter.

Attribution note: the revision record does not assign concerns to named reviewers. The split above is by topic and must be checked against the original reviewer identities.

## 2. Reviewer concerns: status

| # | Concern | Status |
|---|---|---|
| 1 | Novelty vs SSVC and CVSS v4.0 | Partial |
| 2 | Circular labels | Partial (disclosed; no independent labels) |
| 3 | Baseline asymmetry | Partial (context baselines added; a negative result disclosed) |
| 4 | Unjustified weights | Partial (top-10 stable across six configurations) |
| 5 | Guardrail evaluation | Partial (60-case corpus measured; scope still narrow) |
| 6 | Retrieval unclear | Addressed by correction |
| 7 | Explanation quality | **Open** (not measured) |
| 8 | Small benchmark, intervals, tests | Partial (intervals added; no significance tests) |
| 9 | Temporal leakage | Disclosed (historical evaluation not performed) |
| 10 | 500-CVE independence | Disclosed |
| 11 | Actionable metrics | Partial (computed; non-discriminative) |
| 12 | References | Partial (verified set corrected; 3 items unconfirmed) |
| 13 | CPE/Nmap matching | **Open** (not evaluated) |

**Summary:** 1 addressed by correction, 2 disclosed, 8 partial, 2 open.

## 3. What changed in the manuscript

- **Abstract:** removed "outperforming" and "intuitive"; added the measured intervals, the guardrail rates, the explicit statement that explanation quality was not measured, and the temporal setting.
- **Introduction:** removed the unsupported "25,000 CVEs" figure and the "fewer than 5%" attribution; stated three limited contributions and three research questions.
- **Related Work:** rewritten to compare approaches by question. Added Spotlighting, StruQ, SecAlign, and Liu et al. Removed the unsourced claim about LLM-judge defenses.
- **System Architecture (new):** describes what is implemented: exact and keyword retrieval, no vector store, CPE matching, scoring, and validation.
- **Methodology:** VRS formula unchanged; weights labelled exploratory and hard-coded; missing-data policy; benchmark construction; the circularity statement; baseline and metric definitions.
- **Results:** point estimates (unchanged values); bootstrap paired intervals (Table II); context baselines (Table III); ablations (Table IV); KEV concordance (Table V); guardrail confusion matrix (Table VI); score integrity (Table VII); a negative-results subsection. Removed the live-LLM paragraph, which has no run artifact.
- **Threats:** expanded to all categories requested, including the open KEV-flag discrepancy.
- **Conclusion:** restricted to demonstrated findings and listed non-claims.

## 4. Evidence trail for key numbers

| Claim in revised paper | Source file | Re-verified this session |
|---|---|---|
| VRS NDCG@10 = 1.0, Spearman = 0.9488 | `experiments/results/metrics.json` | Yes |
| Ablation Spearman values, context drop 0.0706 | `experiments/results/metrics.json` | Yes |
| Restricted 39-record Spearman 0.9433 | recomputed from `cves.csv` and `risk_engine.rank_findings` | Yes (recomputed) |
| Paired intervals (Table II) | `experiments/revision/statistics/paired_comparisons.csv` | Yes |
| Context baselines (Table III) | `experiments/revision/statistics/bootstrap_results.csv` (observed) | Yes |
| Weights stable top-10 | `experiments/revision/sensitivity/results.json` | Yes (10/10 overlap) |
| Guardrail TP 9, FN 16, FP 7, TN 16 | `experiments/revision/guardrail/metrics.json` | Yes |
| Integrity 2/5 unmodified, 5/5 with floor | `integrity_comparison.json` (re-run) | Yes |
| KEV concordance (Table V) | `experiments/results/expanded_500_table.md` | Read; values match |
| Four KEV-flag mismatches | `revision/evidence/kev_consistency.json` | Yes |
| Weights hard-coded, no fitting code | `risk_engine.py:35` | Yes |

## 5. Claim support summary

Claims in the revised manuscript fall into these groups:

- **Supported by a completed experiment, with the file cited:** the point estimates, bootstrap intervals, context baselines, ablations, guardrail rates, score-integrity comparison, weight top-10 stability, and the 500-CVE concordance.
- **Supported by a verified primary source:** the CVSS, EPSS, KEV, SSVC, and BOD 22-01 descriptions, the arXiv-verified RAG-security entries, and the statement that BOD 22-01 is superseded.
- **Supported by a code check:** the VRS formula, the hard-coded weights, the KEV priority floor, and retrieval as exact and keyword lookup.
- **Stated as limitations, not claims:** explanation quality (not measured), CPE accuracy (not measured), generalization, temporal prediction (not evaluated), and the SSVC and CVSS v4.0 comparisons (not run).

No claim in the revised manuscript rests on an unrun experiment.

## 6. Problems found and handled during this revision

1. **Table and sensitivity wording was wrong in a first draft.** I had said the top-10 sets change across weight configurations. The data show they do not (10/10 overlap). Corrected.
2. **Abstract omitted EPSS-only from the Spearman intervals that exclude zero.** Corrected.
3. **The change log claimed two citations were removed when they were not.** Corrected: they are kept and flagged as unverified.
4. **Nine citation keys were used without bibliography entries.** Added entries only for sources that were fetched, with unconfirmed fields left out.
5. **The change log's Table VII source was not saved.** Re-run and saved as `integrity_comparison.json`.
6. **Table numbers in the combined letter were wrong** (the guardrail table is VI). Corrected from the labels.
7. **The 39-record Spearman caveat was marked "not re-derived".** Recomputed and now stated as computed.
8. **Figure 1 was dropped from the first draft.** Restored with a source caption.

## 7. Remaining limitations of this revision

1. **The manuscript was not compiled.** No LaTeX engine is installed here. Structural checks passed (environments, braces, references), but the PDF, page count, and IEEE formatting were not verified.
2. **Figure 1 was not visually inspected.** The image viewer failed in this session. The caption was checked against the figure's extracted text.
3. **Three bibliographic items remain unconfirmed:** the EPSS methodology venue, the Greshake venue and pages, and the SEI SSVC report (author list and report number). They are flagged in the text and in `VERIFIED_REFERENCES.md`.
4. **BOD 26-04 was not read.**
5. **The KEV flag discrepancy (4 records) is unresolved.** Correcting it could change the headline values. The authors must decide. The task forbids changing labels or results, so it was not corrected.
6. **File mode changes on `paper/manuscript.tex` and `paper/references.bib`** (`100644` to `100755`) predate this work. Content is identical to `HEAD`. I did not revert the mode.
7. **Original reviewer identities** were not available, so the response letters split concerns by topic.

## 8. Required before resubmission

1. Compile `manuscript_revised.tex` with the project's `make paper` target (adapted to the revised path) and check page count and figure placement.
2. Resolve the KEV-flag mismatch and state the decision in the paper.
3. Confirm the three unverified bibliographic records, or remove the citations.
4. Read BOD 26-04 if the paper refers to current federal policy.
5. Decide whether to run the context-baseline paired intervals, the SSVC tree comparison, and independent annotation. Any of these would change the status of concerns 1–3 and 2.
6. Explanation quality and CPE accuracy are open. Either run them or keep the current statements that they were not measured.

## 9. Bottom line

The revised manuscript now matches the implementation and the saved outputs. Every number in the revised paper traces to a file in the repository, and the claims that depended on missing artifacts were removed rather than kept. Several reviewer concerns are only partly resolved, and two are open (explanation quality and CPE matching). The paper does not claim superiority over the context-aware baselines, does not claim significance, and does not claim generalization or predictive validity. The original manuscript and bibliography are preserved with checksums.
