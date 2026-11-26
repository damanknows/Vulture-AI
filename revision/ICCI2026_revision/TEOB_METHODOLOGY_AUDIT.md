# Independent Methodology Audit of the Temporal Exploitation Outcome Benchmark (TEOB)

**Audit Date:** 2026-11-27  
**Repository:** `Vulture-AI` (branch `research-v2`)  
**Scope:** Read-only methodology audit of TEOB documentation, dataset builder, evaluation pipeline, scoring/baseline/metric modules, and automated tests.

---

## 1. Executive Verdict

**TEOB is a well-motivated, structurally sound step toward eliminating ground-truth circularity, but the current infrastructure is NOT yet safe to run or publish without fixes.**

1. **Missing CVSS History Cache (Blocker):** `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json` does not exist yet (Task 363 is in progress), so `experiments/build_temporal_benchmark.py` cannot execute and `data/benchmark/temporal/teob_2026-07-01_90d.csv` has not been built.
2. **CVSS Reconstruction & Leakage Risks:** `resolve_cvss_as_of_cutoff()` conflates `Primary` (NVD) and `Secondary` (CNA) CVSS v3.x entries, ignores CVSS v4.0 (`518` CVEs in the June 2026 cohort have CVSS v4.0 only), uses date-only `[:10]` string comparisons that conflict with `PROVENANCE.md`'s `00:00:00Z` cutoff, and silently falls back to current CVSS if `cvehistory` has no matching events.
3. **Massive Tie-Breaking & Precision Artifacts in Evaluation:** `62` eligible CVEs tie at `CVSS = 10.0` (and `368` at `9.8`), so `CVSS-only` and `KEV-first` top-10/top-50 metrics in `experiments/evaluate_temporal.py` are determined entirely by arbitrary alphabetical `cve_id` ordering rather than tie-aware expectation. Additionally, `compute_epss_only()` in `risk_engine.py` rounds `100 * epss` to 2 decimal places, destroying precision for `epss < 0.01` (which affects `8` of the `11` positive KEV CVEs).
4. **Severe Statistical Power & Component-Scope Limitations:** The eligible June 2026 cohort (`N = 7,927`) contains only **`11` positive 90-day KEV additions** (`0.139%`), and because `kev_at_cutoff = 0` and `N = A = 0.5` are constant across all rows, TEOB reduces VRS to a 2-feature linear combination of CVSS and EPSS (`25*C + 20*E + 17.5`) and cannot evaluate KEV, network exposure, or asset criticality.

---

## 2. Files Inspected

- `data/benchmark/temporal/PROTOCOL.md` (lines 1–58)
- `data/benchmark/temporal/DATA_DICTIONARY.md` (lines 1–21)
- `data/benchmark/temporal/PROVENANCE.md` (lines 1–40)
- `experiments/build_temporal_benchmark.py` (lines 1–284)
- `experiments/evaluate_temporal.py` (lines 1–219)
- `experiments/metrics.py` (lines 1–202)
- `risk_engine.py` (lines 1–229)
- `tests/test_temporal_benchmark.py` (lines 1–97)
- `experiments/run_baselines.py` (lines 1–154)
- `experiments/paired_corrected.py` (lines 1–61)
- Cached inputs (read-only inspection):
  - `data/benchmark/temporal/cache/nvd_pub_2026-06-01_to_2026-07-01.json` (`8,001` CVEs)
  - `data/benchmark/temporal/cache/epss_2026-07-01.json` (`7,927` entries)
  - `data/external/known_exploited_vulnerabilities.json` (`1,741` entries, `catalogVersion: 2026.10.13`)

---

## 3. Critical Findings

### C1. Missing `nvd_cvss_history_post_2026-07-01.json` and Silent Fallback to Current CVSS
- **Severity:** CRITICAL  
- **Locations:** `experiments/build_temporal_benchmark.py:29, 136-139, 164-165`  
- **Details:**  
  1. `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json` does not exist yet, causing `build_temporal_benchmark()` to fail with `FileNotFoundError` at line 164.  
  2. More importantly, in `resolve_cvss_as_of_cutoff()` (lines 136–139), if `lastModified > cutoff_date` (which applies to **6,987 of 8,001** CVEs in the June 2026 cache) and `v3_events` is empty, the code assumes `"no_post_cutoff_cvss_change"` and returns `current_cvss`. There is no verification that `nvd_history` actually covers `[cutoff_date, lastModified]` or was retrieved at/after `lastModified`. Any truncation, pagination miss, or stale history cache silently leaks post-cutoff CVSS scores.

### C2. Arbitrary Alphabetical Tie-Breaking Dominates Top-K Metrics (`62` CVEs Tied at `CVSS = 10.0`)
- **Severity:** CRITICAL  
- **Locations:** `experiments/evaluate_temporal.py:89-123, 134-141`, `risk_engine.py:217-227`  
- **Details:**  
  In the non-rejected, non-pre-KEV June 2026 cohort, **`62` CVEs have `CVSS = 10.0`**, `102` have `9.9`, and `368` have `9.8` (computed from `nvd_pub_2026-06-01_to_2026-07-01.json`).  
  In `build_rankings()` (`experiments/evaluate_temporal.py:90-115`), ties are broken lexicographically by `cve_id` (`"CVE-2026-10000" < "CVE-2026-48282" < "CVE-2026-49869"`). Consequently, for `CVSS-only` and `KEV-first`, **100% of the top-10 and top-50 slots** are determined by arbitrary CVE ID string ordering rather than CVSS score. Reporting `NDCG@10`, `P@10`, `R@10`, and `R@50` from a single deterministic tie-break makes baseline comparisons non-informative and invalidates top-K comparisons against `VRS` or `EPSS-only`.

### C3. `compute_epss_only()` Rounds `100 * epss` to 2 Decimal Places, Creating Artificial Ties on 8/11 Positives
- **Severity:** CRITICAL (materially distorts `EPSS-only` baseline)  
- **Locations:** `risk_engine.py:168-172` (called at `experiments/evaluate_temporal.py:100`)  
- **Details:**  
  `compute_epss_only()` returns `round(100 * raw_epss, 2)`. In the June 2026 cohort, most EPSS values are `< 0.01` (including **8 of the 11 positive KEV CVEs**, e.g., `0.00129`, `0.00233`, `0.00276`, `0.00315`, `0.00403`, `0.00522`, `0.00691`, `0.00734`). Multiplying by `100` and rounding to 2 decimals collapses all EPSS values within `[0.00195, 0.00205)` to `0.20`, destroying ranking resolution and forcing `EPSS-only` into arbitrary alphabetical `cve_id` tie-breaking across large buckets of CVEs. (`compute_vrs` at `risk_engine.py:146` also rounds to 2 decimals, losing resolution for EPSS differences `< 0.00025`.)

---

## 4. High Findings

### H1. `resolve_cvss_as_of_cutoff()` Conflates `Primary` (NVD) and `Secondary` (CNA) CVSS Events
- **Severity:** HIGH  
- **Locations:** `experiments/build_temporal_benchmark.py:94-106, 127-150`  
- **Details:**  
  `extract_current_cvss_v3()` selects `Primary` over `Secondary`, and `cvssMetricV31` over `cvssMetricV30`. However, `resolve_cvss_as_of_cutoff()` filters `cvehistory` with `"CVSS V3" in e.get("type", "")` without distinguishing `Primary` vs `Secondary` sources or `V3.1` vs `V3.0`:
  - If a CVE had a `Secondary` (CNA) CVSS v3.1 score *before* cutoff and NVD `Added` a `Primary` CVSS v3.1 *after* cutoff, `v3_events[0]` has `action == "Added"`, causing line 150 to return `(None, "added_after_cutoff_excluded")` and discard valid pre-cutoff CNA data.
  - Conversely, if `Secondary` was `Changed` after cutoff while `Primary` was unchanged, line 144 reconstructs `Secondary`'s `oldValue` instead of `Primary`.
  - If two `cvehistory` events share the same `created` timestamp, `sorted(..., key=lambda e: e.get("created", ""))` (line 133) is order-dependent.

### H2. Cutoff Timestamp Boundary Inconsistency (`00:00:00Z` vs `[:10] <= "2026-07-01"`)
- **Severity:** HIGH  
- **Locations:** `data/benchmark/temporal/PROVENANCE.md:10, 18` vs `experiments/build_temporal_benchmark.py:118, 121, 131, 193-195`  
- **Details:**  
  `PROVENANCE.md` queries NVD `cves/2.0` with `pubEndDate=2026-07-01T00:00:00.000` and `cvehistory/2.0` with `changeStartDate=2026-07-01T00:00:00.000` (midnight UTC at the **start** of `2026-07-01`). In contrast, `build_temporal_benchmark.py` slices `[:10]` and uses `last_mod <= "2026-07-01"` (line 121) and `created[:10] > "2026-07-01"` (line 131), which treats the **end** of `2026-07-01` as the cutoff and ignores any `cvehistory` events occurring on `2026-07-01` itself. Additionally, if `published` is empty `""`, `"" > CUTOFF_DATE` at line 194 is `False`, silently admitting records with missing publication dates.

### H3. Severe Class Imbalance & Low Statistical Power (`11` Positives in `7,927` CVEs)
- **Severity:** HIGH  
- **Locations:** `data/benchmark/temporal/PROTOCOL.md:23-29`, `experiments/evaluate_temporal.py:126-190`  
- **Details:**  
  In the June 2026 cohort (`8,001` NVD CVEs; `59` `Rejected`; `15` pre-cutoff KEV), only **`11` CVEs** (`0.139%`) are added to CISA KEV within the 90-day horizon (`2026-07-02` to `2026-09-29`). With `P = 11`:
  - `P@10` has a minimum step of `0.10` and `R@10` has a step of `0.0909`; a single CVE crossing rank 10 flips conclusions.
  - Stratified bootstrap (`experiments/evaluate_temporal.py:155-170`) resamples `11` positives with replacement, meaning each replicate contains ~7 distinct positives with duplicates. When a top-10 positive is duplicated in `samp_pos`, it occupies multiple top-10 slots in `ordered_keys`, distorting `NDCG@10` and `P@10`.

### H4. TEOB Cannot Evaluate VRS's `K`, `N`, or `A` Components (Reduces VRS to 2-Feature Linear Sum)
- **Severity:** HIGH  
- **Locations:** `experiments/evaluate_temporal.py:67-85`, `risk_engine.py:136-142`  
- **Details:**  
  Because `kev_at_cutoff = 0` (`K = 0.0`) and `network_exposure = None, asset_criticality = None` (`N = 0.5, A = 0.5` constant) for all `7,927` eligible CVEs:
  - `VRS = 25*C + 20*E + 17.5` (effective `C:E` ratio `1.25:1`).
  - `CVSS+EPSS+KEV = 33.33*C + 33.33*E` (effective `C:E` ratio `1:1`).
  - `KEV-first` is identical to `CVSS-only` (except `None` vs `0.0` at the bottom).
  Thus, TEOB only tests two fixed linear combinations of CVSS and EPSS and provides **zero** evidence regarding VRS's KEV bucket, network exposure, or asset criticality weights.

---

## 5. Medium Findings

### M1. `518` CVEs Have CVSS v4.0 Only and Are Marked `missing_in_nvd`
- **Severity:** MEDIUM  
- **Locations:** `experiments/build_temporal_benchmark.py:94-106`, `experiments/evaluate_temporal.py:90-122`  
- **Details:**  
  `extract_current_cvss_v3()` only checks `cvssMetricV31` and `cvssMetricV30`. In the June 2026 cohort, **`518` non-rejected CVEs** have `cvssMetricV40` only. All 518 receive `cvss_as_of_cutoff = None` (`missing_in_nvd`), causing `CVSS-only`, `CVSS+EPSS+KEV`, and `VRS` to return `None` and push them to the bottom, whereas `EPSS-only` still scores them.

### M2. `precision_at_k()` Divides by `k` When `len(predicted_ranking) < k`
- **Severity:** MEDIUM  
- **Locations:** `experiments/metrics.py:125-127`  
- **Details:**  
  `hits / k` does not guard against `len(predicted_ranking) < k` (should be `min(k, len(top_k))` if small cohorts are ever evaluated).

### M3. Bootstrap Coverage, Multiple Comparisons, and Pre-Subtraction Rounding
- **Severity:** MEDIUM  
- **Locations:** `experiments/evaluate_temporal.py:153-180`, `experiments/metrics.py:106`  
- **Details:**  
  - Bootstrap CIs are computed only for `ndcg@10` and `average_precision`, omitting `precision@10`, `recall@10`, `recall@50`, and `recall@100`.
  - Four baseline comparisons × two metrics (`8` tests) use unadjusted 95% percentile intervals (`[2.5, 97.5]`) without multiple-comparison adjustment.
  - `ndcg_at_k` and `average_precision` round to 4 decimal places *before* computing `scores_b[vrs_name][met] - scores_b[name][met]`.

### M4. Post-Cutoff `vulnStatus == "Rejected"` Filtering & Missing Deduplication
- **Severity:** MEDIUM  
- **Locations:** `experiments/build_temporal_benchmark.py:186-191`  
- **Details:**  
  `vulnStatus == "Rejected"` (`59` CVEs) is checked at retrieval time (`2026-11-26`), not as of `2026-07-01`. Also, `build_temporal_benchmark.py` does not explicitly deduplicate `cve_id` in the input loop (though `nvd_pub_2026-06-01_to_2026-07-01.json` currently has `8,001` unique IDs).

### M5. Raw Cache Download Scripts Not Included in `build_temporal_benchmark.py`
- **Severity:** MEDIUM  
- **Locations:** `experiments/build_temporal_benchmark.py:28-31`, `data/benchmark/temporal/PROVENANCE.md:9-30`  
- **Details:**  
  The builder is reproducible from local caches (`teob_manifest.json` records SHA-256 hashes), but the NVD/EPSS fetch logic is not in the repository, and `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json` is not yet present.

---

## 6. Low Findings

### L1. `PROTOCOL.md` vs `PROVENANCE.md` Publication Window Notation
- **Severity:** LOW  
- **Locations:** `data/benchmark/temporal/PROTOCOL.md:24` vs `data/benchmark/temporal/PROVENANCE.md:10`  
- **Details:**  
  `PROTOCOL.md` writes `[2026-06-01, 2026-07-01]` (closed), while `PROVENANCE.md` uses `pubStartDate=2026-06-01T00:00:00.000&pubEndDate=2026-07-01T00:00:00.000` (half-open `[2026-06-01, 2026-07-01)`). In the cached data, `published` spans `2026-06-01T00:16:41.927` to `2026-06-30T23:17:32.537`.

### L2. Single Later KEV Snapshot Cannot Detect Post-Cutoff Additions Later Removed
- **Severity:** LOW (already disclosed in `PROVENANCE.md:35`)  
- **Locations:** `data/benchmark/temporal/PROVENANCE.md:35`

### L3. `pytest` Not Installed in Default `/usr/bin/python3` Environment
- **Severity:** LOW  
- **Details:** `python3 -m pytest tests/test_temporal_benchmark.py` fails with `No module named pytest` outside `.venv-audit`.

---

## 7. Correctness Assessment of Metric Implementations

| Metric | Implementation | Correctness & Issues |
|---|---|---|
| **NDCG@10** | `experiments/metrics.py:78-106` | Binary `DCG@10` (`(2^1 - 1)/log2(i+2)`) and `IDCG@10` are mathematically correct; returns `0.0` when `idcg <= 0.0` (no positives). **Issue:** Evaluates a single alphabetical tie-break and rounds to 4 decimals before bootstrap differencing. |
| **Precision@10** | `experiments/metrics.py:109-127` | Correct for `N >= 10` (`hits / k`), but **buggy if `len(predicted_ranking) < k`** (divides by `k` instead of `len(top_k)`). Hyper-discrete (`0.1` steps) for `P = 11`. |
| **Recall@10/50/100** | `experiments/metrics.py:130-152` | Correct (`hits / total_relevant`, `0.0` if `total_relevant == 0`). Still sensitive to alphabetical tie-breaking when ties span rank `10` or `50`. |
| **Average Precision** | `experiments/evaluate_temporal.py:43-54` | Standard uninterpolated binary AP (`sum(hits/idx)/total_pos`, `0.0` if `total_pos == 0`). **Issue:** Sensitive to alphabetical tie-breaking within CVSS/EPSS tied blocks; rounds to 4 decimals. |
| **Spearman $\rho$** | `experiments/metrics.py:155-202` | Correctly uses `scipy.stats.spearmanr` with constant-input guard (`0.0`). **Not called** in `evaluate_temporal.py` (appropriate, as rank correlation on `7,916` zeros and `11` ones is dominated by ties). |
| **Paired Bootstrap CI** | `experiments/evaluate_temporal.py:144-180` | Stratified by positive/negative class. **Issues:** Resampling `P = 11` with replacement causes duplicate top-10 positives; freezes alphabetical tie-breaks; omits `P@10` and `R@10/50/100`; no multiple-comparison adjustment. |

---

## 8. Missing Automated Tests (`tests/test_temporal_benchmark.py`)

`tests/test_temporal_benchmark.py` currently has only 3 active unit tests (lines 22–66) and 1 skipped CSV test (lines 69–97). Missing test coverage:
1. **Future CVSS data:** `Primary` vs `Secondary` post-cutoff `Added`/`Changed` interaction; multiple post-cutoff `Changed` events (verifying earliest `oldValue`); `CVSS V3.0` vs `V3.1`; unparseable `oldValue`; `Removed` action.
2. **Future EPSS data:** Rejecting/flagging EPSS entries where `ep["date"] != CUTOFF_DATE`; verifying missing EPSS is never backfilled.
3. **CVEs published after cutoff:** `published > CUTOFF_DATE` exclusion and empty/missing `published` handling.
4. **CVEs already in KEV at cutoff:** `dateAdded < CUTOFF_DATE` exclusion.
5. **KEV additions exactly at cutoff:** `dateAdded == "2026-07-01"` must be excluded (`kev_at_cutoff = 1`), not counted as a positive.
6. **KEV additions at horizon boundary:** `dateAdded == "2026-09-29"` (`future_kev_within_horizon = 1`) vs `"2026-09-30"` (`0`).
7. **Incomplete observation windows:** KEV catalog `dateReleased` earlier than `HORIZON_END`.
8. **Missing historical snapshots:** Missing `NVD_HISTORY_CACHE`/`EPSS_CACHE`, or `lastModified > cutoff` with missing/empty `cvehistory` events.
9. **Duplicate CVEs:** Duplicate `cve_id` in NVD input JSON.
10. **Invalid timestamps:** Malformed `published`, `lastModified`, `created`, or `dateAdded`.
11. **Timezone boundaries:** Same-day `2026-07-01T12:00:00` events in `published`, `lastModified`, and `cvehistory.created`.
12. **Empty datasets:** Empty NVD cohort in builder; empty CSV in `evaluate_temporal.py`.
13. **No-positive-label cohorts:** `n_pos == 0` in `evaluate_teob()` (metrics return `0.0`, bootstrap handled gracefully).
14. **Ranking ties:** Tie-handling and tie-averaging behavior in `evaluate_temporal.py` (especially `CVSS = 10.0` ties and `compute_epss_only` rounding).
15. **Bootstrap edge cases:** `n_pos == 0`, `n_pos == 1`, `n_boot == 0`, and deterministic seed reproducibility.

---

## 9. Baseline Fairness Assessment

- **Information Parity:** VRS does **not** receive extra historical information unavailable to baselines (`K = 0`, `N = A = 0.5` constant).
- **Missing-Data Asymmetry:** `CVSS-only`, `CVSS+EPSS+KEV`, and `VRS` return `None` on missing CVSS (including the `518` CVSS v4.0-only CVEs) and sort them to the bottom, whereas `EPSS-only` still scores them.
- **Weight Tuning:** VRS weights (`0.25, 0.20, 0.20, 0.20, 0.15`) are frozen from `risk_engine.py` and were not tuned on TEOB.
- **Accidental Bias / Distortion:** `compute_epss_only()`'s 2-decimal rounding (`round(100 * epss, 2)`) artificially handicaps `EPSS-only` on small probabilities (`< 0.01`), and alphabetical tie-breaking distorts `CVSS-only` and `KEV-first` top-10/top-50 metrics.

---

## 10. What TEOB Can and Cannot Establish (Research Claims & Paper Wording)

| Research Question | Assessment |
|---|---|
| **1. Addresses circularity of SSVC benchmark?** | **Yes (partially).** Replaces author-assigned grades with external CISA KEV additions. |
| **2. Outcome-based evaluation independent of original grades?** | **Yes.** Uses an independent June 2026 NVD cohort and external KEV outcomes. |
| **3. Predictive vs retrospective ranking?** | **Post-hoc temporal (pseudo-prospective) ranking concordance**, not a live prospective deployment trial. |
| **4. Exploitation vs future KEV inclusion?** | **Only future CISA KEV inclusion within 90 days**, NOT total real-world exploitation. |
| **5. Remediation urgency?** | **Cannot establish.** Organizational urgency requires asset exposure (`N`) and criticality (`A`), which are absent. |
| **6. VRS superiority?** | **Cannot establish.** TEOB only tests `0.25*C + 0.20*E` vs `C`, `E`, and `C + E` on `11` positive events; it does not test `K`, `N`, or `A`. |

**Scientifically Appropriate Paper Wording:**
> *"To evaluate temporal ranking concordance without author-assigned labels, we construct a post-hoc point-in-time cohort of 7,927 non-rejected NVD CVEs published in June 2026 (cutoff 2026-07-01) and track additions to the CISA KEV catalog over a 90-day horizon (2026-07-02 to 2026-09-29; n = 11 observed additions). Because historical asset context is unavailable and pre-cutoff KEV entries are excluded, this experiment evaluates only the CVSS and EPSS components of VRS under constant default context (N = A = 0.5) against future federal KEV inclusion—not total real-world exploitation, organizational remediation urgency, or full 5-component VRS superiority."*

---

## 11. Prioritized Recommendations

1. **Before First Evaluation (Required):**
   - Complete Task 363 to generate and verify `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json`.
   - Fix `resolve_cvss_as_of_cutoff()` to track `Primary` vs `Secondary` CVSS sources separately, align timestamp comparisons with `2026-07-01T00:00:00Z`, and verify `cvehistory` coverage rather than defaulting to `no_post_cutoff_cvss_change`.
   - Replace alphabetical tie-breaking in `evaluate_temporal.py` with **tie-aware expected metrics** (averaging over tied score blocks) and compute unrounded rankings for `EPSS-only` and `VRS` (removing `round(..., 2)` from ranking keys).
2. **After Preliminary Results (Recommended):**
   - Add the 15 missing unit/edge-case tests in `tests/test_temporal_benchmark.py`.
   - Report missingness rates (`518` CVSS v4.0-only, `15` missing EPSS, post-cutoff CVSS exclusions) and extend bootstrap CIs to `R@50` / `R@100` (or expand to a multi-month cohort, e.g., Q1–Q2 2026, to increase `P` beyond `11`).
   - Guard `precision_at_k()` with `min(k, len(top_k))`.

---

## 12. Concise Final Verdict

- **Is the current TEOB infrastructure safe to run?** **No.** `nvd_cvss_history_post_2026-07-01.json` is missing, `CVSS-only`/`KEV-first` top-K metrics are artifacts of alphabetical tie-breaking across `62` CVSS=10.0 ties, `compute_epss_only()` truncates EPSS precision on `8/11` positives, and `resolve_cvss_as_of_cutoff()` has `Primary`/`Secondary` and boundary-timestamp leakage/exclusion bugs.
- **What must be fixed before the first evaluation?** (1) Complete `nvd_cvss_history_post_2026-07-01.json` (Task 363) with coverage verification; (2) fix `Primary`/`Secondary` and `00:00:00Z` boundary handling in `resolve_cvss_as_of_cutoff()`; (3) implement tie-aware evaluation metrics and unrounded score keys in `evaluate_temporal.py`.
- **What can be fixed after preliminary results?** Expanding the automated test suite (`tests/test_temporal_benchmark.py`), adding `min(k, len(top_k))` in `precision_at_k()`, reporting CVSS v4.0 missingness sensitivity, and expanding the cohort beyond 1 month (`P = 11`).
- **Which claims would be scientifically defensible if the evaluation succeeds?** Only that VRS's frozen CVSS+EPSS weighting (`0.25*C + 0.20*E`) achieves competitive or improved post-hoc point-in-time ranking concordance with 90-day CISA KEV additions relative to CVSS-only and EPSS-only on the June 2026 cohort—**not** universal VRS superiority, real-world exploitation prediction, or remediation urgency.
