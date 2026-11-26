# KEV correction provenance

Compared `cves_v2_kev_corrected_2026-11-26.csv` with `cves_v1_original_2026-10-14.csv` by CVE ID. The 41 IDs, row order, and all non-`kev` values are unchanged. Membership was checked against `data/external/known_exploited_vulnerabilities.json`, cached catalog `2026.10.13` (1,741 entries), not a November catalog.

| CVE | v1 | v2 | Cached catalog evidence |
| --- | --: | --: | --- |
| CVE-2022-1292 | 1 | 0 | ID absent |
| CVE-2019-15846 | 1 | 0 | ID absent |
| CVE-2021-3560 | 0 | 1 | `dateAdded`: 2023-05-12 |
| CVE-2022-0492 | 0 | 1 | `dateAdded`: 2026-06-02 |

All 39 real CVEs agree with the cache: 25 listed, 14 absent. The two synthetic rows are excluded from those counts. Absence is not evidence of non-exploitation. The cache hash matches the [enrichment provenance](../cisa_kev_provenance.json); the upstream historical release was not independently verified.

| Artifact | SHA-256 |
| --- | --- |
| v1 CSV (also `data/benchmark/cves.csv`) | `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e` |
| v2 CSV | `2b78d7c280ad29a1f25f06359b73453cb493974fc3a503281bad23a3d472780e` |
| Cached catalog | `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28` |
