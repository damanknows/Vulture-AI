# Change Log: Paper 144 Revision

Original manuscript preserved at `revision/ICCI2026_revision/original/` with SHA-256 checksums in `CHECKSUMS.sha256`. The original `paper/manuscript.tex` and `paper/references.bib` were not modified (verified by checksum before and after).

Revised manuscript: `revision/ICCI2026_revision/manuscript_revised.tex`. Revised bibliography: `revision/ICCI2026_revision/references_revised.bib`.

Counts below are from `diff` of the original and revised files: 296 original lines and 387 revised lines, with 385 changed lines in the diff.

## 1. Structural changes

| Change | Original | Revised | Reason |
|---|---|---|---|
| Section split | "Proposed Method" (one section) | "System Architecture" and "Methodology" | Separates implemented components from the formula and evaluation design |
| New section | none | "Discussion" | Interprets measured findings separately from hypotheses |
| Figure | Figure 1 (`fig1.pdf`) | Figure 1 retained with a caption that states its source and the values it shows | Caption now cites the source file. Figure not visually inspected in this session. |
| Added tables | 2 (per original structure) | 7 (main, bootstrap, context, ablation, KEV-500, guardrail, integrity) | Reviewer requests for intervals, baselines, guardrail, and integrity |
| Section numbering | 7 sections | 9 sections | Follows from the splits above |

## 2. Abstract

- **Removed:** the phrase "outperforming CVSS-only ... EPSS-only ... and unweighted baselines".
- **Removed:** "intuitive triaging assistance".
- **Replaced:** the claim of superiority with the paired interval results.
- **Added:** explicit statement that explanation quality was not measured, the temporal setting, and the guardrail's measured rates.
- **Corrected:** the Spearman interval statement now lists EPSS-only as excluding zero (the earlier draft omitted it).

## 3. Introduction

- **Removed:** "With over 25,000 CVEs published annually" (unsupported; claim audit A1).
- **Corrected:** CVSS description now cites CVSS v4.0 for the statement that base scores are not complete risk (verified).
- **Corrected:** BOD 22-01 is no longer described as current; the revised text does not present it as active policy.
- **Replaced:** "fewer than 5% exploited" attribution removed (unverified; claim audit G2).
- **Added:** the three contributions with their limits, and the three research questions RQ1–RQ3 reworded to match the evidence.

## 4. Related Work

- **Kept with flags (not removed):** `spring2020ssvc` and `jacobs2021epss` are still cited. The EPSS venue and the SSVC author list and report number are unverified, and the text now says so. Removing them would drop real sources, so they stay flagged rather than deleted.
- **Removed:** the unsourced claim that prior defenses rely on secondary LLM judges or fine-tuning (claim audit G8).
- **Added:** Spotlighting, StruQ, SecAlign, and Liu et al. with the verified details, described as not implemented here.
- **Added:** comparison of context handling in CVSS v3.1/v4.0 with VRS.
- **Corrected:** "substantially higher precision" for EPSS over CVSS replaced by FIRST's statement that CVSS severity is only slightly better than random (claim audit G3).

## 5. System Architecture (new section)

- Describes the four stages from the implementation.
- **Corrected:** retrieval described as exact CVE lookup and keyword substring matching; no vector store or embeddings.
- **Stated:** CPE matching has no accuracy evaluation.

## 6. Methodology

- VRS formula and weights unchanged. Weights labelled exploratory and stated to be hard-coded (verified in `risk_engine.py:35`).
- **Added:** missing-data policy with defaults (E=0, N and A=0.5).
- **Added:** benchmark construction, reference labels, and the statement that labels are author judgments with no measured agreement.
- **Added:** the circularity statement.
- **Added:** actionable metric definitions and the finding that they do not discriminate.

## 7. Experimental Setup (new subsection content)

- **Added:** snapshot dates (benchmark 2026-10-14; EPSS 2026-10-13; KEV 2026.10.13 with 1,741 entries).
- **Added:** temporal setting, with the statement that the evaluation is retrospective.
- **Added:** software versions from `requirements-lock.txt`.

## 8. Results

- **Table I:** point estimates (unchanged values from `metrics.json`; rounded to 4 decimals).
- **Table II (new):** bootstrap paired intervals from `paired_comparisons.csv`.
- **Table III (new):** context-aware baselines from Phase 2.
- **Table IV:** ablations, values unchanged from `ablation.json`. Text corrected: "Removing EPSS raises Spearman" is described as a rubric property, not redundancy.
- **Table V (new):** KEV concordance on 500 CVEs, values unchanged from `expanded_500_table.md`.
- **Table VI (new):** guardrail confusion matrix (Phase 4).
- **Table VII (new):** score-integrity simulation. The current results are saved (`score_integrity.json`, 5/5). The 'Unmodified' column is saved in `integrity_comparison.json`, which re-runs the harness against `git HEAD:vulture_chatbot.py` and the working tree. Unmodified 2/5 (S01, S02, S04 fail on priority); with the floor 5/5.
- **Added:** weight-sensitivity paragraph (top-10 identical across six configurations).
- **Added:** explicit negative results subsection.
- **Removed:** "Superiority of Context-Aware Prioritization" heading; replaced by "Ablations (RQ2)".
- **Removed:** the "live Llama-3.1-8B" trial paragraph (no run artifact exists; `rag_eval.json` records `live_model_evaluated: false`).
- **Removed:** "41/41 structural validity" and "39/41 numeric grounding" figures (no artifact).

## 9. Threats to Validity

- **Expanded** from the original to cover each category in the revision brief: circularity, benchmark size, author curation, synthetic cases, annotation independence, temporal leakage, data sources, weights, metrics, baseline fairness, guardrail corpus, automated evaluation bias, and generalizability.
- **Added:** the KEV-flag discrepancy for four records, with the note that it is unresolved.

## 10. Conclusion

- **Rewritten** to state only the demonstrated findings and the listed non-claims.
- **Removed:** "clinical SOC trials" future-work wording (not planned anywhere in the repository).

## 11. Bibliography

Original `references.bib` unchanged. The revised file adds nine entries for verified sources (listed in `references_revised.bib`). Keys used in the text all resolve in the revised file (checked). The original keys `greshake2023prompt`, `lyon2009nmap`, `mell2006cvss`, `nvd2023`, and `cisa2023kev` are retained in the file but are no longer cited in the text, so they do not appear in the bibliography output.

Entries whose details could not be verified are still flagged in `VERIFIED_REFERENCES.md`: the EPSS methodology venue, the Greshake venue and pages, and the SEI SSVC report.

## 12. Items not changed

- No benchmark label, ranking, or original result was modified.
- The KEV-flag mismatch for four records was reported, not corrected.
- The Phase 3 Spearman value 0.9487 (bootstrap observed, four decimals) and 0.9488 (point estimate) differ by rounding; the paper uses 0.9488, matching `metrics.json`.

## 13. Not verified

- The manuscript was not compiled to PDF. No LaTeX engine is installed in this environment. Structural checks passed: environments balanced, braces balanced, all `\ref` targets defined.
- Figure 1 was not visually inspected in this session (the image viewer was unavailable). Its extracted text was checked against the table values.
