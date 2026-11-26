# Temporal Exploitation Outcome Benchmark (TEOB) — Protocol

**Version:** 1.1.0  
**Date:** 2026-11-27  
**Purpose:** Outcome-based, temporally separated evaluation of vulnerability prioritization methods to address ground-truth circularity and temporal leakage in the 41-record author-graded benchmark (`data/benchmark/cves.csv`).

---

## 1. Design Principles

1. **No reuse of author-assigned SSVC-inspired grades.** TEOB does not use `reference_priority` or `independent_label` from `data/benchmark/cves.csv`.
2. **Outcome-independent cohort selection.** Candidate CVEs are selected strictly by calendar publication window (`published_date` prior to `cutoff_date`), never by whether they later appear in CISA KEV.
3. **Strict temporal separation.** All input features (`cvss_as_of_cutoff`, `epss_as_of_cutoff`, `kev_at_cutoff`) must be demonstrably available on or before `cutoff_date`. Future values are never substituted for missing historical inputs.
4. **Cautious outcome semantics.** Positive outcomes (`future_kev_within_horizon = 1`) represent CISA KEV additions observed strictly within `(cutoff_date, cutoff_date + 90 days]`. Non-positive records (`future_kev_within_horizon = 0`) are labelled `"not observed in KEV during the horizon"`, never `"not exploited"`.
5. **No fabricated asset context.** Because no independent historical network exposure or asset criticality records exist for public CVEs, TEOB does not invent context values. Consequently:
   - `EPSS × Context` is **not evaluated** on TEOB.
   - `VRS` is evaluated using `risk_engine.py`'s documented missing-context defaults (`N = 0.5`, `A = 0.5`), which are constant across the cohort and recorded in `uncertainties`.

---

## 2. Cutoff Date & Cohort Selection

- **Selected Cutoff Date (`T_0`):** `2026-07-01T00:00:00Z` (UTC midnight at the start of `2026-07-01`)
- **Pre-Cutoff Publication Window:** `[2026-06-01T00:00:00Z, 2026-07-01T00:00:00Z)` (all non-rejected CVEs published by NVD during June 2026 UTC).
- **Observation Horizon (`H`):** `90` calendar days (`2026-07-02` through `2026-09-29`, inclusive).
- **Eligibility Rules:**
  1. `vulnStatus != "Rejected"` in NVD `cves/2.0` (deduplicated by `cve_id`).
  2. `published < 2026-07-01T00:00:00Z` (strictly pre-cutoff in UTC).
  3. **Exclude prior KEV entries:** `kev_at_cutoff == 0` (any CVE with CISA KEV `dateAdded <= 2026-07-01` is excluded so the benchmark evaluates *future* KEV discovery rather than trivial retention of already-known KEVs).

---

## 3. Historical Feature Reconstruction Rules

1. **EPSS (`epss_as_of_cutoff`):**
   - Queried directly from the FIRST EPSS API (`https://api.first.org/data/v1/epss?cve=...&date=2026-07-01`).
   - Records absent from the historical EPSS snapshot on `2026-07-01` are left blank (`None`) and handled by each scorer's documented missing-data policy (e.g., `E = 0.0` in `risk_engine.py`).

2. **CVSS (`cvss_as_of_cutoff`):**
   - If `nvd_last_modified < 2026-07-01T00:00:00Z`, the NVD CVSS v3.x base score in `cves/2.0` is demonstrably unchanged since cutoff (`cvss_status_at_cutoff = "unchanged_since_cutoff"`).
   - If `nvd_last_modified >= 2026-07-01T00:00:00Z`, NVD `cvehistory/2.0` CVSS v3.x events at or after `2026-07-01T00:00:00Z` are walked backwards in reverse chronological order from the current NVD metrics state:
     - If no CVSS v3.x event occurred at or after `2026-07-01T00:00:00Z`, the current CVSS v3.x score was already present at cutoff (`"no_post_cutoff_cvss_change"`).
     - `Added` events are undone by removing the matching vector (preserving pre-cutoff `Secondary` CNA scores when `Primary` NVD scores were added post-cutoff); `Removed` events are undone by restoring `oldValue`; `Changed` events are undone by replacing `newValue` with `oldValue`. If a pre-cutoff entry remains, the score is reconstructed (`"reconstructed_from_cvehistory"`).
     - If no pre-cutoff CVSS v3.x entry remains after undoing post-cutoff events, `cvss_as_of_cutoff` is set to `None` (`"added_after_cutoff_excluded"`), preventing future-CVSS leakage.
     - If post-cutoff history cannot be cleanly matched or parsed, `cvss_as_of_cutoff` is set to `None` (`"unreconstructable_post_cutoff_change"`).
     - CVSS v4.0-only CVEs without CVSS v3.x are recorded as `None` (`"missing_in_nvd"`).

3. **KEV (`kev_at_cutoff` and Outcome Labels):**
   - Derived from CISA KEV catalog `2026.10.13` (`data/external/known_exploited_vulnerabilities.json`, 1,741 entries, `dateAdded` covering `2021-11-03` to `2026-10-13`).
   - `kev_at_cutoff = 1` if `dateAdded <= 2026-07-01` (excluded from eligible cohort).
   - `future_kev_within_horizon = 1` and `future_kev_addition_date = dateAdded` if `2026-07-01 < dateAdded <= 2026-09-29`.
   - `future_kev_within_horizon = 0` and `outcome_label = "not observed in KEV during the horizon"` otherwise (including KEV additions after `2026-09-29`, whose `future_kev_addition_date` is recorded as `None` for the 90-day label or noted as post-horizon).

---

## 4. Evaluation Scope & Limitations

- TEOB evaluates **ranking concordance with future observed CISA KEV additions** over a 90-day horizon.
- It does **not** measure total real-world exploitation (non-KEV exploits are unobserved) or organizational remediation urgency (which depends on asset exposure and criticality).
- VRS weights (`0.25, 0.20, 0.20, 0.20, 0.15`) are frozen from `risk_engine.py` and never tuned on TEOB.
