# Phase 3 — Missing CVSS Handling & Technical Consistency Audit

**Date:** 2026-11-27  
**Branch:** `research-v2`  
**Status:** Audited (no commits/pushes performed)

---

## 1. Phase 0 — Repository & Artifact State
- **Branch:** `research-v2` (HEAD `6612feb`, clean working tree prior to Phase 3).
- **TEOB evaluation script:** `experiments/evaluate_temporal.py` (Note: prompt referenced `experiments/revision/evaluate_temporal.py`; the actual file in the repository is `experiments/evaluate_temporal.py`).
- **Frozen TEOB dataset:** `data/benchmark/temporal/teob_2026-07-01_90d.csv` (`7,927` eligible CVEs, `11` positives, `7,916` negatives; SHA-256 `94c7b4cab13daccb5dbe3abdebe6bf4d17f7643bfe0036316dfb792359e07794`).

## 2. Phase 1 — Missing CVSS Handling Audit (`1,244` CVEs)
Inspection of `experiments/evaluate_temporal.py` (`compute_unrounded_scores`, `tie_blocks`, `compute_all_metrics`) and `data/benchmark/temporal/teob_2026-07-01_90d.csv` confirms:

1. **Population & Denominator Consistency:** All 5 methods rank the **exact same `7,927` CVEs**, and all metric denominators use the full `7,927` cohort (`P = 11` positives). No method drops missing-CVSS records.
2. **Positives with Missing CVSS:** Of the `1,244` missing-CVSS records (`726` `added_after_cutoff_excluded` + `518` `missing_in_nvd` CVSS v4.0-only), **`2` are positive KEV additions** (`CVE-2026-56290` with `EPSS = 0.00276`; `CVE-2026-8452` with `EPSS = 0.00403`).
3. **Per-Method Behavior:**
   - **`CVSS-only`:** Assigns `None` -> mapped to `-inf` -> `1,244`-record bottom tied block `(1244, 2, -inf)` below the `4` records with `CVSS = 0.0`.
   - **`CVSS+EPSS+KEV`:** Assigns `None` -> `-inf` -> `1,244`-record bottom tied block `(1244, 2, -inf)` (EPSS is not used when CVSS is missing).
   - **`VRS (default context=0.5)`:** Assigns `None` (`unavailable` bucket) -> `-inf` -> `1,244`-record bottom tied block `(1244, 2, -inf)` (EPSS is not used when CVSS is missing).
   - **`KEV-first`:** `c_val = cvss if cvss is not None else 0.0` -> assigns `0.0`, merging the `1,244` missing-CVSS records with the `4` records having `CVSS = 0.0` into a `1,248`-record bottom tied block `(1248, 2, 0.0)`.
   - **`EPSS-only`:** Scores all `7,927` records (including all `1,244` missing-CVSS records) using their `2026-07-01` EPSS probabilities (`0` `None` values).
4. **Metric & Bootstrap Validity:** Under `tie_aware_*` analytical expectations and paired stratified bootstrap (`seed = 20261127`, `n_boot = 1,000`), all reported NDCG@10, Precision@10, Recall@{10, 50, 100}, Average Precision, and 95% CIs in `experiments/revision/teob_evaluation.json` remain **valid** without re-running or altering evaluation code.
5. **Manuscript Correction:** Added explicit documentation of this missing-CVSS policy across all five methods in §IV.B of `revision/ICCI2026_revision/manuscript_revised.tex` and recompiled `manuscript_revised.pdf`.
