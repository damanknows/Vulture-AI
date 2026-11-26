# Phase 2 Initial Audit — Vulture-AI Manuscript Revision

**Audit Date:** 2026-11-27  
**Branch:** `research-v2`  
**Paper ID:** 144 (ICCI 2026 — Accepted after Modification)

---

## 1. Repository State
- **Git branch:** `research-v2`
- **Untracked Phase 1 & Audit artifacts (preserved):**
  - `data/benchmark/temporal/` (`PROTOCOL.md`, `DATA_DICTIONARY.md`, `PROVENANCE.md`, `teob_2026-07-01_90d.csv`, `teob_manifest.json`, `cache/`)
  - `experiments/build_temporal_benchmark.py`
  - `experiments/evaluate_temporal.py`
  - `experiments/revision/teob_evaluation.json`, `experiments/revision/teob_evaluation.md`
  - `tests/test_temporal_benchmark.py`
  - `revision/ICCI2026_revision/TEOB_METHODOLOGY_AUDIT.md`, `revision/ICCI2026_revision/TEOB_PHASE1_FINAL_REPORT.md`
- **No tracked files modified** prior to Phase 2.

## 2. Existing Manuscript Status
- **Source:** `revision/ICCI2026_revision/manuscript_revised.tex` (390 lines, `IEEEtran` conference format)
- **Compiled PDF:** `revision/ICCI2026_revision/manuscript_revised.pdf` (7 pages, built with `/tmp/tectonic-bin/tectonic`)
- **Bibliography:** `revision/ICCI2026_revision/references_revised.bib` (173 lines, verified entries including `first2019cvss`, `first2023cvss4`, `first2024epss`, `jacobs2021epss`, `cisa2021bod`, `cisa2024kev`, `cisa2024ssvc`, `spring2020ssvc`, `lewis2020rag`, `greshake2023indirect`, `liu2024formalizing`, `hines2024spotlighting`, `chen2024struq`, `chen2024secalign`)
- **Gap in current `manuscript_revised.tex`:** Still presents the **41-record author-labelled benchmark** and **500-CVE retrospective KEV check** as the primary evaluation, and states *"historical evaluation not performed"* (Concern 9), even though **Phase 1 TEOB** (`N = 7,927`, `P = 11`, cutoff `2026-07-01T00:00:00Z`, 90-day horizon) is now complete and frozen.

## 3. Frozen Phase 1 & Existing Artifacts Verified
- **TEOB Dataset:** `data/benchmark/temporal/teob_2026-07-01_90d.csv` (SHA-256 `94c7b4cab13daccb5dbe3abdebe6bf4d17f7643bfe0036316dfb792359e07794`), `teob_manifest.json` (`7,927` eligible, `11` positives, `7,916` negatives; CVSS v3.x available `6,683`, reconstructed `156`, excluded post-cutoff `726`, missing/v4.0-only `518`; EPSS `7,927/7,927`).
- **TEOB Evaluation:** `experiments/revision/teob_evaluation.json` and `teob_evaluation.md` (1,000-iteration paired stratified bootstrap, seed `20261127`).
- **Guardrail Evaluation:** `experiments/revision/guardrail/metrics.json` (60-case corpus, 48 inspected: TP=9, FN=16, FP=7, TN=16; TPR=0.36, FPR=0.3043, Precision=0.5625, Accuracy=0.5208, F1=0.4390) and `score_integrity.json` (5/5 pass with KEV priority floor).
- **Explanation Quality:** `experiments/revision/guardrail/explanation_evaluation.csv` has header only (0 rows; unmeasured).
- **41-CVE Exploratory Benchmark:** `experiments/results/metrics.json` and `experiments/revision/statistics/paired_comparisons.csv` (kept separate as exploratory policy concordance).

## 4. Risks Before Editing
1. **Page-limit / layout overflow:** Adding TEOB as the primary evaluation (plus comparison table, TEOB cohort/metrics/bootstrap tables, and TEOB protocol figure/description) while preserving the 41-CVE exploratory summary and guardrail tables must remain clean and readable in `IEEEtran` without table overflow or orphan references.
2. **Overclaiming TEOB:** TEOB has `K = 0` and `N = A = 0.5` constant, so VRS reduces to `0.25*C + 0.20*E`; manuscript must not claim TEOB validates context awareness or KEV weights, nor claim superiority over `CVSS+EPSS+KEV` (all 95% CIs include zero).
3. **Preserving frozen artifacts:** Do not modify `teob_2026-07-01_90d.csv`, `teob_evaluation.json`, `cves.csv`, or `risk_engine.py`.
