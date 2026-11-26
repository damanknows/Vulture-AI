# TEOB Phase 1 Final Report

**Date:** 2026-11-27  
**Repository:** `Vulture-AI` (`research-v2`)  
**Benchmark:** Temporal Exploitation Outcome Benchmark (`teob_2026-07-01_90d.csv`, v1.1.0)

---

## 1. Task 363 Historical Data Audit Outcome
Task 363 completed retrieval and caching of `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json` (`retrieved_utc: 2026-11-26T21:51:46Z`, covering `883` June 2026 CVEs with `1,006` post-cutoff CVSS change events: `992` CVSS V3.1, `14` CVSS V4.0; `935` `Added`, `71` `Removed`). Crucially, inspection revealed that NVD `cvehistory/2.0` represents modifications as paired `Added` + `Removed` events (never `"Changed"`), and `402` CVEs had `428` events on `2026-07-01` itself (after `00:00:00Z`).

## 2. Task 364 Methodology Audit Outcome
Task 364 (`revision/ICCI2026_revision/TEOB_METHODOLOGY_AUDIT.md`) identified three CRITICAL and four HIGH defects in the initial TEOB v1.0.0 pipeline:
- Missing `nvd_cvss_history_post_2026-07-01.json` and silent fallback without coverage checks.
- Arbitrary alphabetical `cve_id` tie-breaking across `62` (`63` after reconstruction) CVEs tied at `CVSS = 10.0`.
- `compute_epss_only()` rounding `100 * epss` to 2 decimal places, collapsing `8/11` positive KEV CVEs into artificial ties.
- `Primary`/`Secondary` CVSS conflation and `[:10]` cutoff boundary mismatch (`2026-07-01T00:00:00Z` vs end of day).
- Low statistical power (`P = 11`) and inability of TEOB (`K = 0`, `N = A = 0.5`) to evaluate VRS's `K`, `N`, or `A` weights.

## 3. Defects Identified
1. **CVSS `Added`+`Removed` & `Primary`/`Secondary` conflation** (`experiments/build_temporal_benchmark.py`).
2. **Cutoff timestamp boundary `[:10]` vs `2026-07-01T00:00:00Z`** (`experiments/build_temporal_benchmark.py`, `PROTOCOL.md`).
3. **Missing history/KEV completeness checks and duplicate/invalid-published guards** (`experiments/build_temporal_benchmark.py`).
4. **Arbitrary alphabetical tie-breaking on tied scores** (`experiments/evaluate_temporal.py`).
5. **Score rounding (`round(..., 2)`) before ranking** (`risk_engine.py` via `evaluate_temporal.py`).
6. **Bootstrap freezing alphabetical tie-breaks and omitting `P@10`, `R@10/50/100`** (`experiments/evaluate_temporal.py`).
7. **Display-precision `significant_95` mismatch when CI lower bound rounds to `0.0000`** (`experiments/evaluate_temporal.py`).

## 4. Defects Fixed
- **`experiments/build_temporal_benchmark.py`:** Implemented UTC timestamp parsing (`parse_utc_timestamp`), strict `< 2026-07-01T00:00:00Z` cutoff boundary, backward `cvehistory` reconstruction handling `Added`/`Removed`/`Changed` and `Primary`/`Secondary` sources, preservation of `cvss_vector_as_of_cutoff` and `cvss_source_at_cutoff`, duplicate CVE deduplication, EPSS exact-date validation (`ep["date"] == cutoff_date`), NVD history retrieval-timestamp validation, and KEV horizon-completeness validation.
- **`experiments/evaluate_temporal.py`:** Implemented unrounded float64 scoring (using frozen `DEFAULT_WEIGHTS` from `risk_engine.py`), exact analytical tie-aware expected metrics (`NDCG@10`, `Precision@10` with `min(k, N)` for `N < k`, `Recall@10/50/100`, `Average Precision`), paired stratified bootstrap preserving ties across all 6 metrics, and `significant_95` checked against 4-decimal rounded CI bounds.
- **`tests/test_temporal_benchmark.py`:** Expanded from 4 to 10 comprehensive regression tests covering all Stage 4 requirements.
- **`data/benchmark/temporal/{PROTOCOL.md,DATA_DICTIONARY.md,PROVENANCE.md}`:** Synchronized to v1.1.0 semantics and schema.

## 5. Unresolved / Structural Limitations
- **Cohort size & class imbalance (`P = 11` positives in `7,927` CVEs):** Structural property of a 1-month June 2026 cohort over a 90-day KEV horizon; cannot be altered without expanding to additional months.
- **CVSS v4.0-only CVEs (`518` records):** Marked `missing_in_nvd` because VRS and CVSS-only baselines operate on CVSS v3.x.
- **Constant context & `K = 0`:** Historical `network_exposure` and `asset_criticality` are unavailable (`N = A = 0.5`).

## 6. Dataset Cohort Size & Exclusions
- **NVD June 2026 total:** `8,001`
- **Excluded — Rejected (`vulnStatus == "Rejected"`):** `59`
- **Excluded — Pre-cutoff KEV (`dateAdded <= 2026-07-01`):** `15`
- **Excluded — Duplicate / Post-cutoff / Invalid published:** `0`
- **Eligible cohort (`teob_2026-07-01_90d.csv`):** **`7,927`**

## 7. Positive & Negative Label Counts
- **Positives (`observed_kev_addition`, `2026-07-02` to `2026-09-29`):** **`11`** (`0.139%`)
- **Negatives (`not observed in KEV during the horizon`):** **`7,916`** (`99.861%`)

## 8. CVSS Historical Reconstruction Breakdown
- `no_post_cutoff_cvss_change`: `5,704`
- `unchanged_since_cutoff` (`lastModified < 2026-07-01T00:00:00Z`): `823`
- `reconstructed_from_cvehistory` (pre-cutoff `Secondary` preserved or `Removed` `oldValue` restored): `156`
- `added_after_cutoff_excluded` (CVSS v3.x only added at/after cutoff): `726`
- `missing_in_nvd` (CVSS v4.0 only): `518`
- **Total CVSS v3.x available at cutoff:** `6,683` (`84.31%`); **missing:** `1,244` (`15.69%`).

## 9. EPSS Coverage
- **EPSS available (`date=2026-07-01`):** `7,927` (`100.0%`); **missing:** `0`.

## 10. KEV Source Coverage & Limitations
- Source: CISA KEV `2026.10.13` (`1,741` entries, `dateReleased: 2026-10-13T19:10:43.6568Z`), covering the full 90-day horizon through `2026-09-29` with a 14-day buffer.
- Limitation: Measures CISA federal KEV catalog addition, not total real-world exploitation; any hypothetical entry added after `2026-07-01` and removed before `2026-10-13` would not appear.

## 11. Metric Definitions & Tie Handling
All metrics are computed on unrounded float64 scores using exact analytical expectation over uniform random permutations within tied score blocks (`tie_blocks()`):
- **Tie-Aware NDCG@10, Precision@10 (`denom = min(k, N)`), Recall@10/50/100:** Expected relevance/hits per rank `i` in block `B_b` is `p_b / n_b`.
- **Tie-Aware Average Precision:** Exact analytical expectation summing `(p_b / n_b) * sum_{r=1}^{n_b} (1 + P_before + (p_b - 1)*(r - 1)/(n_b - 1)) / (S_before + r)` divided by `total_pos`.

## 12. Final Results for All Baselines

| Method | NDCG@10 | P@10 | R@10 | R@50 | R@100 | Avg Precision | Top Tie Block |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CVSS-only | 0.0317 | 0.0317 | 0.0289 | 0.1443 | 0.2148 | 0.0259 | 63 |
| EPSS-only | 0.0948 | 0.1000 | 0.0909 | 0.1818 | 0.1818 | 0.0449 | 1 |
| KEV-first | 0.0317 | 0.0317 | 0.0289 | 0.1443 | 0.2148 | 0.0259 | 63 |
| CVSS+EPSS+KEV | 0.1795 | 0.2000 | 0.1818 | 0.3636 | 0.3636 | 0.0928 | 1 |
| VRS (default context=0.5) | 0.2083 | 0.2000 | 0.1818 | 0.3636 | 0.3636 | 0.1104 | 1 |

## 13. Bootstrap Methodology & Confidence Intervals
Paired stratified bootstrap (`n_boot = 1,000`, `n_valid = 1,000`, `seed = 20261127`), resampling `11` positives and `7,916` negatives separately with replacement using identical indices across all methods, with 95% percentile CIs (`VRS - baseline`):
- **vs CVSS-only / KEV-first:** `NDCG@10` diff `+0.1765` `[-0.0484, 0.4737]` (not sig.); `R@50` diff `+0.2193` `[0.0152, 0.4684]` (sig.); `AP` diff `+0.0845` `[-0.0029, 0.3204]` (not sig.).
- **vs EPSS-only:** `NDCG@10` diff `+0.1135` `[0.0000, 0.2593]` (not sig.); `AP` diff `+0.0655` `[0.0089, 0.1982]` (sig.).
- **vs CVSS+EPSS+KEV:** `NDCG@10` diff `+0.0288` `[0.0000, 0.1541]` (not sig.); `AP` diff `+0.0177` `[0.0000, 0.1084]` (not sig., CI includes `0.0000`).

## 14. Tests Executed & Results
- `/home/daman/Projects/vulture/.venv-audit/bin/python -m pytest tests/test_temporal_benchmark.py tests/test_metrics.py tests/test_benchmark.py tests/test_revision_statistics.py -v --tb=short`: **86 passed, 0 failed**.
- `git diff --check`: **passed** (exit code 0).

## 15. Dataset & Output SHA-256 Hashes
- `data/benchmark/temporal/teob_2026-07-01_90d.csv`: `94c7b4cab13daccb5dbe3abdebe6bf4d17f7643bfe0036316dfb792359e07794`
- `data/benchmark/temporal/cache/nvd_pub_2026-06-01_to_2026-07-01.json`: `4b5f498866eb236be82952446547be0986cb6591e788b049b9e286fe30692079`
- `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json`: `378848f33e38029c1fae66177e6b28bd346eda76d3e24e22faa358c8d82d88f4`
- `data/benchmark/temporal/cache/epss_2026-07-01.json`: `9fcdb844a599b3fd08abaa0677b506fb3f2f823f59ad383e25f6dae68165981d`
- `data/external/known_exploited_vulnerabilities.json`: `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28`

## 16. Files Changed
- `experiments/build_temporal_benchmark.py`
- `experiments/evaluate_temporal.py`
- `tests/test_temporal_benchmark.py`
- `data/benchmark/temporal/PROTOCOL.md`
- `data/benchmark/temporal/DATA_DICTIONARY.md`
- `data/benchmark/temporal/PROVENANCE.md`
- `data/benchmark/temporal/teob_2026-07-01_90d.csv`
- `data/benchmark/temporal/teob_manifest.json`
- `experiments/revision/teob_evaluation.json`
- `experiments/revision/teob_evaluation.md`
- `revision/ICCI2026_revision/TEOB_PHASE1_FINAL_REPORT.md`

## 17. Research Limitations
- Single 1-month cohort (`n = 11` positives) limits statistical power and widens CIs.
- `K = 0` and `N = A = 0.5` are constant across all rows; `EPSS × Context` is omitted.
- Future CISA KEV addition is a proxy for federal-reported exploitation, not exhaustive real-world exploitation or organizational remediation urgency.

## 18. Claims Supported by the Final Experiment
- Under strict pre-cutoff (`< 2026-07-01T00:00:00Z`) feature reconstruction on the June 2026 NVD cohort, VRS's frozen CVSS+EPSS weighting (`0.25*C + 0.20*E`) achieves higher point estimates than `CVSS-only`, `KEV-first`, and `EPSS-only` for 90-day KEV ranking concordance, with statistically significant gains (`95%` CI excluding zero) in `Recall@50` over `CVSS-only`/`KEV-first` (`+0.2193`) and `Average Precision` over `EPSS-only` (`+0.0655`).

## 19. Claims That Remain Unsupported
- Universal superiority of VRS over `CVSS+EPSS+KEV` (all 6 bootstrap 95% CIs include zero), superiority of VRS's `K`/`N`/`A` components, total real-world exploitation prediction, or organizational remediation urgency.
