# Vulture-AI Benchmark Dataset Card

## 1. Summary
The Vulture-AI benchmark dataset (`data/benchmark/cves.csv`) is a curated collection of **41 records** designed to evaluate vulnerability prioritization algorithms against standard decision trees.

- **Verified Public CVEs**: 39 records
- **Synthetic Edge-Case Records**: 2 records (deliberately constructed to test missing-data handling)
- **Snapshot Date**: `2026-10-14T00:00:00Z`
- **SHA-256 Checksum**: `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`

## 2. Field Schema

| Field Name | Type | Allowed Values | Description |
|:---|:---|:---|:---|
| `cve_id` | String | `CVE-\d{4}-\d+` | Primary CVE identifier (or synthetic test ID). |
| `cvss` | Float / Empty | `0.0 - 10.0` | Official NIST NVD CVSS v3.1 base score. Empty for missing CVSS test case. |
| `epss` | Float / Empty | `0.0 - 1.0` | Live FIRST.org EPSS exploit probability. Empty for missing EPSS test case. |
| `kev` | Integer | `0` or `1` | Binary indicator of presence in the CISA KEV catalog. |
| `exposure` | Float | `0.0 - 1.0` | Reference network exposure ($1.0$ = perimeter gateway, $0.2$ = internal). |
| `asset_criticality` | Float | `0.0 - 1.0` | Reference mission impact / criticality ($1.0$ = domain controller, $0.2$ = test workstation). |
| `reference_priority` | Integer | `1 - 41` | Ordinal reference rank (1 = highest urgency). |
| `independent_label` | String | `Act`, `Attend`, `Track`, `Defer` | Ordinal relevance tier based on CISA SSVC rubric. |
| `source_timestamp` | String | ISO 8601 | Snapshot retrieval timestamp. |
| `source_reference` | String | URL / Note | Traceable URL to authoritative NVD advisory or synthetic note. |
| `description` | String | Text | Brief vulnerability summary. |

## 3. Threat Tiers (CISA SSVC Rubric)

1. **Act (Relevance Grade = 3, 15 records)**: Confirmed active mass-exploitation in CISA KEV affecting internet-exposed, mission-critical assets (e.g., Log4Shell, MOVEit, ScreenConnect, Cisco IOS XE, Citrix ADC, Spring4Shell).
2. **Attend (Relevance Grade = 2, 12 records)**: Weaponized exploits or KEV-listed items with local/client vectors, or critical zero-days without active KEV confirmation (e.g., XZ Utils backdoor, Follina, PrintNightmare, WinRAR, Dirty Pipe).
3. **Track (Relevance Grade = 1, 8 records)**: Validated high/medium CVSS vulnerabilities without public exploitation evidence (e.g., Redis STRALGO, PostgreSQL, Polkit).
4. **Defer (Relevance Grade = 0, 6 records)**: Low severity, client-side, non-exploitable, or missing critical data records (e.g., OpenSSH user enumeration, curl cookie injection).

## 4. Synthetic Edge-Case Disclosure
* `CVE-2024-99991` (Item 40): Missing CVSS score. Tests the missing-CVSS policy (`vrs=None`, `bucket="unavailable"`, sorted last).
* `CVE-2024-99992` (Item 41): Missing EPSS probability. Tests the missing-EPSS policy (defaults to `0.0`, flags uncertainty).

Neither identifier exists in the NVD or CNA registries. They are preserved strictly to test missing-data edge cases without contaminating the verified CVE records.

## 5. Telemetry Enrichment (CISA KEV)

An enriched companion dataset (`data/benchmark/cves_enriched.csv`, SHA-256: `666e040f01a491e58a9bf345a81e0a74d9deca1591f72f800872c5336bab9ff7`) links each benchmark record to official CISA Known Exploited Vulnerabilities catalog telemetry. The original frozen benchmark (`data/benchmark/cves.csv`, SHA-256: `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`) remains completely unchanged.

### 5.1 Enriched Field Schema

| Field Name | Type | Allowed Values | Description & Origin |
|:---|:---|:---|:---|
| `is_synthetic` | Boolean String | `True`, `False` | Flags synthetic missing-data test cases (`CVE-2024-99991`, `CVE-2024-99992`). |
| `cisa_kev_listed` | String | `True`, `False`, `N/A (synthetic)` | Boolean presence indicator in the CISA KEV catalog. |
| `cisa_kev_status` | String | `listed`, `not_listed_or_unknown`, `synthetic_excluded` | Explicit categorization. Unlisted CVEs are marked `not_listed_or_unknown`, NOT confirmed non-exploitation. |
| `cisa_kev_date_added` | String | `YYYY-MM-DD` / Empty | Administrative date CISA added the CVE under BOD 22-01 mandates (NOT first exploitation date). |
| `cisa_kev_due_date` | String | `YYYY-MM-DD` / Empty | Remediation deadline mandated for federal civilian executive branch agencies. |
| `cisa_kev_required_action` | String | Text / Empty | Official CISA remediation requirement (e.g., vendor patch or mitigation). |
| `cisa_kev_source_url` | String | Valid URL / Empty | Primary validated `http://` or `https://` advisory or reference URL parsed from KEV notes. |
| `cisa_kev_vulnerability_name` | String | Text / Empty | Official `vulnerabilityName` attribute from the CISA KEV catalog. |
| `cisa_kev_notes` | String | Text | Complete raw vendor advisories and directives from CISA KEV notes (or unlisted/synthetic explanation). |

### 5.2 Matching Statistics ($N=41$)
* **Real Public CVEs**: 39 records.
  * **Matched in CISA KEV**: 25 records (64.1% of real CVEs).
  * **Unlisted in CISA KEV**: 14 records (35.9% of real CVEs; indicates unobserved in federal reporting, NOT confirmed non-exploitation).
* **Synthetic Test Cases**: 2 records (`CVE-2024-99991`, `CVE-2024-99992`), strictly excluded from empirical real-world outcome evaluations.

### 5.3 Authoritative Telemetry Provenance
* **Official Feed URL**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
* **Local Cache Path**: `data/external/known_exploited_vulnerabilities.json`
* **Catalog Version**: `2026.10.13`
* **Catalog Release Timestamp**: `2026-10-13T19:10:43.6568Z`
* **Catalog Vulnerability Count**: 1,741 entries
* **Catalog SHA-256**: `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28`
* **Provenance Manifest**: `data/benchmark/cisa_kev_provenance.json`
* **Enrichment Pipeline**: `python experiments/enrich_benchmark_kev.py`

## 6. Expanded Research Benchmark (v2.0-500)

To validate prioritization behavior on realistic enterprise vulnerability volumes, the repository includes an expanded dataset of **500 unique, real public CVE records**:

* **Base CSV**: `data/benchmark/cves_500.csv` (SHA-256: `009c8566f1fdc4ed38b453deb351025019adac1942c5c5c2c52c822f856129ef`)
* **Enriched CSV**: `data/benchmark/cves_500_enriched.csv` (SHA-256: `24dc74c14d4fd36ec3c3cd023cbd68072a454195ec37bacb368fe5955efe9517`)
* **Manifest**: `data/benchmark/cves_500_manifest.json`
* **Composition**: 39 preserved original real CVE records + 461 newly sampled real CVE records from official `CVEProject/cvelistV5` (release `cve_2026-10-13_2300Z`, seed `42`). Zero synthetic records.
* **CISA KEV Matches**: 25 of 500 records are confirmed in CISA KEV (5.0%, matching real-world empirical exploitation rates).
* **Scientific Label Protocol**: Author-curated SSVC reference labels are maintained exclusively for the 39 original records. The 461 newly sampled records are marked `unlabeled`. No synthetic labels are fabricated. SSVC ranking alignment is evaluated strictly on the labeled subset, while KEV precision/recall is evaluated across all 500 CVEs.
