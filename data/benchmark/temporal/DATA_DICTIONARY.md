# TEOB Data Dictionary

**Dataset file:** `data/benchmark/temporal/teob_2026-07-01_90d.csv`  
**Schema version:** `1.1.0`

| Column | Type | Nullable | Description |
|---|---|---|---|
| `cve_id` | string | No | Canonical CVE identifier (`CVE-YYYY-NNNN+`). |
| `cutoff_date` | ISO-8601 date (`YYYY-MM-DD`) | No | Evaluation cutoff date (`2026-07-01`, corresponding to `2026-07-01T00:00:00Z`). |
| `published_date` | ISO-8601 date (`YYYY-MM-DD`) | No | NVD `cve.published` UTC date. Always strictly before `2026-07-01T00:00:00Z`. |
| `cvss_as_of_cutoff` | float `[0.0, 10.0]` | Yes | CVSS v3.x base score demonstrably available before `2026-07-01T00:00:00Z`. Blank (`""`) if CVSS was added post-cutoff, unreconstructable, or missing (including CVSS v4.0-only records). |
| `cvss_status_at_cutoff` | string (enum) | No | Provenance status of `cvss_as_of_cutoff`: `unchanged_since_cutoff`, `no_post_cutoff_cvss_change`, `reconstructed_from_cvehistory`, `added_after_cutoff_excluded`, `unreconstructable_post_cutoff_change`, or `missing_in_nvd`. |
| `cvss_vector_as_of_cutoff` | string | Yes | Core CVSS v3.x vector (`AV:.../A:...`) available at cutoff, or blank (`""`) if `cvss_as_of_cutoff` is missing. |
| `cvss_source_at_cutoff` | string | Yes | Selected CVSS metric source (`Primary:<source>`, `Secondary:<source>`, or `Reconstructed:<source>`), or blank (`""`) if missing. |
| `epss_as_of_cutoff` | float `[0.0, 1.0]` | Yes | FIRST EPSS probability queried for `date=cutoff_date`. Blank (`""`) if absent from the historical EPSS snapshot for `cutoff_date`. |
| `epss_percentile_as_of_cutoff` | float `[0.0, 1.0]` | Yes | FIRST EPSS percentile for `date=cutoff_date`. |
| `kev_at_cutoff` | integer `{0, 1}` | No | Whether the CVE was in CISA KEV on `cutoff_date` (`dateAdded <= cutoff_date`). Always `0` in the eligible benchmark dataset. |
| `future_kev_addition_date` | ISO-8601 date (`YYYY-MM-DD`) | Yes | Exact CISA KEV `dateAdded` if `cutoff_date < dateAdded <= cutoff_date + 90d`; blank (`""`) otherwise. |
| `future_kev_within_horizon` | integer `{0, 1}` | No | Binary outcome: `1` if added to CISA KEV within `(cutoff_date, cutoff_date + 90d]`, else `0`. |
| `outcome_label` | string (enum) | No | `"observed_kev_addition"` when `future_kev_within_horizon == 1`; `"not observed in KEV during the horizon"` when `0`. Never `"not exploited"`. |
| `observation_horizon_days` | integer | No | Observation window length in days (`90`). |
| `nvd_last_modified` | ISO-8601 date (`YYYY-MM-DD`) | No | NVD `cve.lastModified` date at retrieval time, recorded for auditability. |
| `source_provenance` | string | No | Pipe-delimited provenance tags identifying exact NVD, EPSS, and KEV sources used for the row. |
