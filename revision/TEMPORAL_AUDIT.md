# Temporal Validity Audit

Scope: all data snapshots, benchmark CSVs, the KEV and EPSS caches, and the experiment scripts that produce the manuscript's numbers. Audit date: 2026-11-26. Files were inspected directly; the numbers below come from those inspections.

## 1. Summary

The benchmark is a **present-state, retrospective** evaluation. Each record's CVSS, EPSS, exposure, and criticality are read from a single 2026 snapshot, and the KEV label is from the 2026-10-13 catalog. None of the features were reconstructed as they were known at disclosure or at any earlier time. Historical (point-in-time) validation is **not feasible within this revision** for the reasons in §5. The manuscript must describe the evaluation as retrospective present-state prioritization, and must not claim forward or early prediction.

## 2. Date inventory

| Data element | Where | Date(s) found | Source / how derived | Point-in-time? |
|---|---|---|---|---|
| CVE disclosure (publication) date | `cves_500.csv` `source_timestamp` for 461 added records | 2023 (204), 2024 (251), 2025 (6) | `date_published` from cvelistV5 (`generate_benchmark_500.py:182, 286`) | Yes, but used only as a label on the row, not as a feature date |
| Frozen snapshot date, curated 39 | `cves.csv` / `cves_500.csv` `source_timestamp` | 2026-10-14 (39 rows) | hard-coded in the CSV | No: this is the freeze date for all curated features |
| CVSS base score | `cves.csv` `cvss` column | 2026 snapshot (retrieved 2026-10-14 per README) | NVD values, frozen | No: current-version scores, not those available at disclosure |
| CVSS for 461 added | `cves_500.csv` `cvss` | cvelistV5 release `cve_2026-10-13_2300Z` | "CNA-verified" base scores from the cvelistV5 release | No: present-release values |
| EPSS | `cves.csv` `epss`; `data/external/epss_cache_500.json` | `date: 2026-10-13` on every cache entry (checked on `CVE-2023-0297`, 461 entries) | FIRST EPSS API, cached | No: a single day's forecast |
| KEV membership | `cves.csv` `kev`; `cves_500_enriched.csv` `cisa_kev_listed`; `data/external/known_exploited_vulnerabilities.json` | catalog version 2026.10.13, released 2026-10-13T19:10:43Z, 1,741 entries | CISA feed, cached | No: a present-day catalog |
| KEV dateAdded | enriched CSV `cisa_kev_date_added` | 2021-11-03 to 2026-10-08 | CISA catalog attribute | Yes: the catalog's own date, but it was not used as a feature cut-off |
| Exposure `N` and criticality `A` | `cves.csv`, `cves_500.csv` | no date; hand-assigned archetypes | author-assigned | Not dated; not time-varying |
| Reference labels | `cves.csv` `independent_label`, `reference_priority` | source_timestamp 2026-10-14 | author-assigned SSVC-inspired rubric, 2026 | Not a historical label; assigned now using present-state features |
| Asset context | none | no dated source | archetype values | N/A |

Notes:
- The EPSS date is verified across the full cache: all 461 entries carry `date: 2026-10-13`, none is missing a score (counted in this audit).
- KEV catalog dates are real CISA dates. They are the only historical signal in the benchmark, and they are used only as a label, not as a feature cut-off.

## 3. Mismatch between feature date and row date

For the 461 added records, the row's `source_timestamp` is the CVE's **publication** date (2023–2024), while `cvss`, `epss`, and `kev` are **2026** values. A reader who sorts or filters by `source_timestamp` will think the features are from 2023–2024. They are not.

The 39 curated records use 2026-10-14 for everything, so the row date does match the feature date for them.

This is a labelling inconsistency in the artifact. It is not a leakage path into the metrics, since the metrics do not use `source_timestamp`. It does risk misleading readers and reviewers, and the manuscript should state the mismatch explicitly.

Fallback behaviour: `generate_benchmark_500.py:286` sets `source_ts = date_published or date_updated or "2026-10-14T00:00:00Z"`. Any CVE without a publication or update date would be stamped with the freeze date. The current corpus has no such rows (all 500 rows have a 2023–2026 value), but the fallback is a silent default and should be documented.

## 4. Leakage assessment

### 4.1 Features vs. labels (benchmark construction)

- **Label leakage into features:** the reference grade is assigned by the authors from SSVC-style inputs (KEV, EPSS, exposure, criticality). VRS uses the same inputs. This is **construct circularity**, already disclosed in the manuscript (Threats to Validity). It is not temporal leakage, but it means the Spearman and NDCG results are not independent of the features.
- **KEV label leakage:** the `kev` feature and the KEV-based evaluation (`500-CVE concordance`) use the same catalog. For KEV-first and VRS, the policy uses KEV as an input and KEV as the label, so the "100% recall at depth 25" is an identity by construction. The manuscript already flags this (`Structural Ceiling Effects`).

### 4.2 Future information in features

- **KEV status is post-disclosure information.** A CVE that is KEV-listed in 2026 may have been added years after disclosure. When used as a feature for a "prioritization at disclosure" question, KEV status contains information from after that time. This is the most important temporal leak, and it is structural: the benchmark cannot separate "known to be exploited now" from "known to be exploited at disclosure."
- **EPSS is a 2026 forecast.** EPSS is recomputed daily and incorporates exploitation activity and exploit-code signals observed up to the snapshot. Its value for a 2023 CVE in 2026 is not what a practitioner would have seen in 2023. FIRST's FAQ states that scores change as "new information ... arrived", so the cached value is post-disclosure information.
- **CVSS base scores** are NVD/CNA values that were often revised after publication. The 2026 score may differ from the first published score.

### 4.3 Future information in labels

- The labels are from 2026 knowledge (SSVC-inspired, using 2026 KEV status). For a CVE first published in 2023 and listed in KEV in 2025, the label "Act" reflects knowledge that did not exist at disclosure.

### 4.4 Evaluation-time leakage

- No train/test split exists. VRS weights were fixed a priori (exploratory weights, `vrs-v1`). The ablations and weight-sensitivity analyses in Phase 2 were run on the same 41 records used to read off results, so they are **in-sample** sensitivity analyses, not held-out validation. The manuscript should not describe them as out-of-sample.

## 5. Is historical reconstruction feasible?

**Not within this revision.** The reasons, each checked against the repository:

1. **No historical EPSS snapshots are stored.** The cache holds one date (2026-10-13) per CVE. FIRST's FAQ says historical daily score files exist in an archive, but none is in the repository, and no archive was fetched. Reconstruction would need network access to FIRST's archive and is out of scope (and would be a new data acquisition, which this task did not authorise).
2. **No historical CVSS.** NVD records in the repo are current. The NVD history (score changes over time) was not retrieved.
3. **KEV has dateAdded**, so "was this CVE in KEV on date X" *can* be answered from the existing feed: a CVE is KEV-listed at date X if `dateAdded <= X`. This is the one feature that could be reconstructed point-in-time without new downloads. It was not done. It would need the full catalog history. CISA's FAQ states it will remove an entry only in a specific case (a vendor fix causing a significant unforeseen issue), but it gives no removal frequency, so whether the single-snapshot approximation is accurate is unverified.
4. **Exposure and criticality** are archetypes with no time dimension, so they cannot be reconstructed. They are assumed constant.
5. **Reference labels** are assigned in 2026 from 2026 features. A historical label would need a historical rubric application, which the authors would have to perform.

Conclusion: a fully point-in-time evaluation requires (a) archived EPSS daily scores, (b) archived NVD/CVSS records, and (c) new reference labels assigned from data available at each disclosure date. None of these exist in the repository. The one partial reconstruction (KEV-at-date via `dateAdded`) is feasible but was not done and would still leave EPSS and CVSS non-historical.

## 6. Limits of this audit

- The EPSS date was verified across all 461 cache entries (all `2026-10-13`, none missing) and the manuscript's "dated 2026-10-13" claim is supported for the 461 cached values. The 39 curated EPSS values come from `cves.csv` and carry the 2026-10-14 freeze date; their exact EPSS date was not separately verified.
- The statement "none of the 461 added records is in the KEV snapshot" was verified (0 of 461). The 4 KEV flag mismatches for curated records are reported in `revision/evidence/kev_consistency.json`.
- The KEV catalog version is from the cached file. The manuscript's "version 2026.10.13" was confirmed from that file's `catalogVersion` field.

## 7. Required manuscript changes

1. Describe the 500-CVE study as **"retrospective present-state prioritization"** against a single 2026-10-13 snapshot. Remove any wording that implies prediction at disclosure.
2. State that features (CVSS, EPSS, KEV, exposure, criticality) are **not point-in-time reconstructed**, and that KEV and EPSS carry post-disclosure information.
3. State that the 461 added records have **publication-date `source_timestamp` values but 2026 feature values**.
4. State that the Phase 2 weight-sensitivity and ablation results are **in-sample**.
5. Retain the KEV "structural ceiling" disclaimer and extend it to cover post-disclosure KEV information.

## 8. Future work (for the manuscript's discussion section)

- Obtain FIRST's daily EPSS archive and align each CVE's score to its disclosure date and to a fixed set of later observation dates.
- Obtain NVD CVSS history per CVE and use the score available at disclosure.
- Use KEV `dateAdded` to define "exploited by date X" and evaluate prioritization at several decision dates, scoring only with features available on each date.
- Re-label records with a rubric applied to each decision date, with independent raters, to avoid present-state label leakage.
- Hold out a temporal test set (e.g., CVEs disclosed after a cutoff) and fix weights before evaluation.

## 9. Findings to escalate (not changed)

- **KEV flag mismatch (4 records, `cves.csv`):** CVE-2022-1292 and CVE-2019-15846 are flagged `kev=1` in the benchmark but are absent from the 2026.10.13 feed; CVE-2021-3560 and CVE-2022-0492 are flagged `kev=0` but are present in the feed (dateAdded 2023-05-12 and 2026-06-02). This affects the headline results and needs an author decision. No benchmark value was changed.
