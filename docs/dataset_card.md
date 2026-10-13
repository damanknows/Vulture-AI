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
