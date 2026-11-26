# TEOB Source Provenance Manifest

**Benchmark:** Temporal Exploitation Outcome Benchmark (`teob_2026-07-01_90d.csv`)  
**Cutoff Date:** `2026-07-01`  
**Observation Horizon:** `90` days (`2026-07-02` through `2026-09-29`)  

---

## Source 1: NVD CVE API 2.0 (Publication Cohort)
- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2026-06-01T00:00:00.000&pubEndDate=2026-07-01T00:00:00.000`
- **Local Cache:** `data/benchmark/temporal/cache/nvd_pub_2026-06-01_to_2026-07-01.json`
- **Retrieval Timestamp:** `2026-11-26T21:32Z` UTC (`2026-11-27` IST)
- **Relevant Timestamp Fields:** `cve.published`, `cve.lastModified`, `cve.vulnStatus`
- **Coverage & Limitations:** Returns all 8,001 NVD CVEs published in June 2026 (100% outcome-independent calendar cohort). Rejected CVEs (`vulnStatus == "Rejected"`) are excluded.
- **Cutoff Verifiability:** `cve.published <= 2026-07-01` establishes public disclosure by cutoff. Where `cve.lastModified <= 2026-07-01`, CVSS is demonstrably unchanged since cutoff; where `cve.lastModified > 2026-07-01`, CVSS is verified/reconstructed via Source 2.

## Source 2: NVD CVE History API 2.0 (Post-Cutoff CVSS Audit)
- **URL:** `https://services.nvd.nist.gov/rest/json/cvehistory/2.0?changeStartDate=2026-07-01T00:00:00.000&changeEndDate=2026-11-27T23:59:59.999`
- **Local Cache:** `data/benchmark/temporal/cache/nvd_cvss_history_post_2026-07-01.json` (`retrieved_utc: 2026-11-26T21:51:46Z`, `883` CVEs with post-cutoff CVSS changes)
- **Relevant Timestamp Fields:** `change.created`, `change.eventName`, `details[].action`, `details[].type`, `details[].oldValue`, `details[].newValue`
- **Coverage & Limitations:** Captures every CVSS addition or removal recorded by NVD at or after `2026-07-01T00:00:00Z`. The builder walks post-cutoff `Added`/`Removed`/`Changed` events backwards from the current NVD metrics state: CVEs whose only CVSS v3.x was *Added* at or after `2026-07-01T00:00:00Z` (`726` records) have `cvss_as_of_cutoff` set to blank (`None`) rather than leaking post-cutoff scores, while pre-cutoff `Secondary` CNA scores and `Removed` `oldValue` vectors (`156` records) are reconstructed.
- **Cutoff Verifiability:** Demonstrably enforces pre-cutoff (`< 2026-07-01T00:00:00Z`) CVSS availability without assuming current CVSS equals historical CVSS.

## Source 3: FIRST EPSS API (Historical Daily Snapshot)
- **URL:** `https://api.first.org/data/v1/epss?cve=<CVE_LIST>&date=2026-07-01`
- **Local Cache:** `data/benchmark/temporal/cache/epss_2026-07-01.json`
- **Relevant Timestamp Fields:** `data[].date` (`2026-07-01`)
- **Coverage & Limitations:** FIRST serves exact historical daily EPSS scores via the `date` parameter. Very newly published CVEs (e.g., late June 2026) may not yet have an EPSS score on `2026-07-01`; such records are left blank (`None`) and never backfilled from later dates.
- **Cutoff Verifiability:** Directly verified via API `date=2026-07-01`.

## Source 4: CISA Known Exploited Vulnerabilities (KEV) Catalog
- **Official URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Local Cache:** `data/external/known_exploited_vulnerabilities.json` (`catalogVersion: 2026.10.13`, `dateReleased: 2026-10-13T19:10:43.6568Z`, `count: 1741`, SHA-256 `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28`)
- **Relevant Timestamp Fields:** `vulnerabilities[].dateAdded` (`2021-11-03` to `2026-10-13`)
- **Coverage & Limitations:** Covers the entire 90-day observation window (`2026-07-02` to `2026-09-29`, ending 14 days before `dateReleased`). Known limitation: `dateAdded` reflects entries present in the `2026.10.13` catalog; any hypothetical entry added after `2026-07-01` and removed before `2026-10-13` would not appear. Absence from KEV means unobserved in CISA federal reporting, not absence of exploitation.
- **Cutoff Verifiability:** `dateAdded <= 2026-07-01` identifies pre-cutoff KEV entries (excluded); `2026-07-01 < dateAdded <= 2026-09-29` identifies future KEV additions within the 90-day horizon.

## Source 5: Asset Context (`network_exposure`, `asset_criticality`)
- **Status:** **Unavailable / Not independently documented.**
- **Handling:** No context values are fabricated. `EPSS × Context` is omitted from TEOB evaluation. `VRS` is evaluated using `risk_engine.py`'s documented missing-context defaults (`N = 0.5`, `A = 0.5`).
