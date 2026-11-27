# Why No CVSS v4.0 Environmental Baseline Is Run on TEOB

A CVSS v4.0 Threat/Environmental baseline cannot be constructed on the Temporal Exploitation Outcome Benchmark (TEOB, `data/benchmark/temporal/teob_2026-07-01_90d.csv`) without inventing unavailable historical data:

1. **Incomplete Historical CVSS v4.0 Vectors:** While 2,365 June 2026 NVD records contain a `cvssMetricV40` object at retrieval time (`2026-11-26`), `nvd_cvss_history_post_2026-07-01.json` records only 14 CVSS v4.0 change events, and NVD `Initial Analysis` / `Deferred` transitions mean pre-cutoff v4.0 vector availability is not established across the cohort.
2. **Unavailable Historical Environmental Context:** TEOB has no historical asset exposure, criticality, or security-requirement (`CR`/`IR`/`AR`) telemetry as of `2026-07-01T00:00:00Z`, and `kev_at_cutoff = 0` for all 7,927 eligible records.

Consequently, CVSS v4.0 environmental evaluation is omitted from TEOB and flagged as a limitation in Section VII.
