# Final Submission Audit — Vulture-AI (ICCI 2026)

**Date:** 2026-11-27  
**Branch:** `research-v2` (at commit `2a38f34`, ahead of `origin/research-v2` at start; no commits or pushes performed during this final audit)  
**Finalization Backup:** `revision/ICCI2026_revision/manuscript_revised.pre_final_audit.tex`  
**Final Manuscript:** `revision/ICCI2026_revision/manuscript_revised.tex`  
**Final Compiled PDF:** `revision/ICCI2026_revision/final_submission/Vulture_AI_ICCI2026_Anonymous_Submission.pdf` (also `revision/ICCI2026_revision/manuscript_revised.pdf`)

---

## 1. Initial Repository State & Artifacts Inspected
- **Git state at start:** Clean working tree on branch `research-v2` (`2a38f34`).
- **Artifacts inspected:**
  - `revision/ICCI2026_revision/manuscript_revised.tex` & `references_revised.bib`
  - `data/benchmark/temporal/teob_manifest.json`, `teob_2026-07-01_90d.csv`, `cache/epss_2026-07-01.json`, `experiments/build_temporal_benchmark.py`
  - `experiments/revision/teob_evaluation.json`
  - `experiments/revision/baselines/compute_actionable_summary.py`, `exploratory_actionable.json`, `results_ssvc.json`, `results_cvss_env.json`
  - `experiments/results/metrics.json`, `ablation.json`, `figures/fig1.pdf`
  - `experiments/revision/guardrail/metrics.json`, `score_integrity.json`
  - `experiments/revision/cpe/cpe_matching_results.json`
  - `experiments/revision/manuscript_audit.py`, `experiments/audit_remaining_gaps.py`

---

## 2. Scientific Consistency, Temporal Validity & Missing-CVSS Checks
- **TEOB Cohort Arithmetic (Verified):**
  - June 2026 NVD cohort: `8,001`
  - Sequential exclusions: `59` Rejected, `15` pre-cutoff KEV (`dateAdded <= 2026-07-01`), `0` duplicates/post-cutoff/invalid -> `7,927` eligible (`8001 - 59 - 15 = 7927`).
  - Outcomes: `11` future KEV additions (`0.139%` prevalence), `7,916` not observed in KEV during horizon (`99.861%`).
  - Feature coverage: `7,927` EPSS (`100.0%`); `6,683` historical CVSS v3.x (`5,704` no post-cutoff change + `823` unchanged + `156` reconstructed from `cvehistory`); `1,244` missing CVSS (`726` post-cutoff added excluded + `518` CVSS v4.0-only).
- **Missing-CVSS Fairness (Verified):**
  - All 5 TEOB methods rank the identical `7,927`-record population (`P = 11`, including 2 positives with missing CVSS: `CVE-2026-56290`, `CVE-2026-8452`).
  - `CVSS-only`, `CVSS+EPSS+KEV`, and `VRS` assign `None` (`-inf`, `1,244`-record bottom tied block); `KEV-first` assigns `0.0` (`1,248`-record bottom tied block with 4 `CVSS = 0.0` records); `EPSS-only` scores all `7,927` records.
  - Limitation explicitly retained in §VII: unequal feature availability disadvantages CVSS-dependent methods relative to `EPSS-only` on the 1,244 missing-CVSS records.
- **EPSS Temporal Availability (Critical Finding & Resolution):**
  - Live check against `https://api.first.org/data/v1/epss?date=2026-06-30` confirmed that a complete `2026-06-30` EPSS snapshot is **unavailable** across all `7,927` records: `date=2026-06-30` omitted 8 of 10 sampled `2026-06-30` CVEs and both `2026-06-30` positives (`CVE-2026-48282`, `CVE-2026-8452`).
  - Accordingly, `date=2026-07-01` EPSS is retained without fabrication/approximation.
  - Removed the unsupported claim that 6 days between `2026-07-01` and the earliest positive KEV (`2026-07-07`) eliminates feature leakage; updated Abstract, RQ1, Table I, §IV.C, §VII, and §VIII to disclose that TEOB is **not** a fully verified point-in-time evaluation for EPSS.

---

## 3. Statistical & Terminology Audit
- **Bootstrap Protocol (Verified):** `B = 1,000`, `seed = 20261127`, paired stratified resampling (positives and negatives resampled separately with identical indices across methods), 95% percentile CIs (`teob_evaluation.json`).
- **Nominal Significance Caveat (Added):** Confidence intervals are unadjusted for multiple comparisons across metrics and baselines; all significant findings (`Recall@50` vs `CVSS-only`: `+0.2193 [0.0152, 0.4684]`; `AP` vs `EPSS-only`: `+0.0655 [0.0089, 0.1982]`) are now explicitly labeled **nominal** / exploratory, with the `P = 11` wide-CI limitation stated in Abstract, §IV.D, §V.A, §VII, and §VIII.
- **Exploratory Metric Terminology (Verified & Clarified):** Verified in `compute_metrics.py` and `compute_actionable_summary.py`: `P@10 (Act)` / `R@10 (Act)` use threshold `3` (Act-only, denominators `10` and `15`), whereas `AP@10` / `AR@10` denote Actionable Precision@10 / Actionable Recall@10 (threshold `>= 2`, Act or Attend, denominators `10` and `27`, distinct from Average Precision). Clarified in §V.B and corrected "all Act/Attend items" to "all 10 top slots with Act/Attend items (10 of 27, AR@10 = 0.3704)".

---

## 4. Citation, Double-Blind, Formatting & Reproducibility Audit
- **Citations:** All 18 `\cite{...}` keys match `references_revised.bib` (`0` missing keys).
- **Double-Blind Anonymity:** `rg` scan on manuscript/bib and `pdfinfo` on `manuscript_revised.pdf` (`Author: Anonymous Author(s)`) and `fig1.pdf` (`Creator: Matplotlib`) confirm zero author, username, or local-path leaks.
- **IEEE Formatting & Visual Inspection:** Compiled cleanly with `tectonic` (7 pages, `138.79 KiB`, letter size, two-column `IEEEtran`). All 7 pages were rendered (`pdftoppm -r 150`) and visually inspected: zero overlapping text, clean tables I–VIII, legible `fig1.pdf`, clean URL wrapping.
- **Official ICCI 2026 Page Limit:** **UNVERIFIED** from local repository files (no official ICCI 2026 CFP/page-limit document is stored locally). User must verify the 7-page length against the ICCI 2026 submission portal limit.
- **Automated Audits:**
  - `python -m experiments.revision.manuscript_audit`: `114 / 114` cells passed (`0` failed).
  - `python -m experiments.audit_remaining_gaps`: `"all_match": true`.
  - `pytest tests/test_manuscript_audit.py tests/test_remaining_gaps_audit.py tests/test_temporal_benchmark.py`: `13 / 13` passed.
  - `git diff --check`: exited `0`.

---

## 5. Remaining Limitations & Exact Final Artifact Locations
- **Research Limitations (disclosed in paper):** Calendar-day EPSS granularity (non-verified point-in-time EPSS), sparse `P=11` TEOB positives and unadjusted CIs, unequal missing-CVSS availability (`1,244` records), circularity and uncalibrated weights in the 41-CVE exploratory set (`PENDING` human rater data), weak prototype regex guardrail (`TPR 0.36`, `FPR 0.30`), `NOT_AVAILABLE` semantic explanation quality (HTTP 402 / no local Ollama), and unmeasured live-network scanner-to-CVE recall.
- **Clean Upload Package:** `revision/ICCI2026_revision/final_submission/`
  - `Vulture_AI_ICCI2026_Anonymous_Submission.pdf`
  - `manuscript_revised.tex`
  - `references_revised.bib`
  - `fig1.pdf`
  - `UPLOAD_MANIFEST.md`
