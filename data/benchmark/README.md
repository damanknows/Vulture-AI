# Vulture-AI Benchmark Dataset

## 1. Overview
This benchmark contains **39 real, publicly documented CVE records plus 2 synthetic edge-case records** designed to evaluate vulnerability prioritization algorithms (CVSS-only, EPSS-only, KEV-first, and Vulture-AI's Vulture Risk Score).

All real vulnerability data is traceable to authoritative public sources:
- **NIST National Vulnerability Database (NVD)**: Official CVSS v3.1 base scores.
- **FIRST.org EPSS**: Live Exploit Prediction Scoring System probabilities (retrieved 2026-10-14).
- **CISA KEV Catalog**: Known Exploited Vulnerabilities catalog (catalog version 2026.10.13).
- **CISA SSVC Decision Tree**: Stakeholder-Specific Vulnerability Categorization used as the reference labeling rubric.

> **⚠ Synthetic Records Disclosure**: Records `CVE-2024-99991` (Items 40) and `CVE-2024-99992` (Item 41) use **non-existent CVE identifiers** that are not registered in the NVD or any CNA. They are deliberately constructed to test missing-data handling: missing CVSS and missing EPSS respectively. These records have no authoritative public source and must not be cited as real vulnerabilities.

## 2. Selection Methodology & Risk Profiles
The dataset spans diverse software ecosystems (web servers, firewalls, enterprise gateways, operating system kernels, libraries) across 4 operational threat tiers, plus 2 explicit synthetic edge cases for missing data:
1. **Tier 1 (Act / Emergency Remediation)** (Items 1–15): Actively exploited in the wild (CISA KEV = 1) affecting high-exposure, critical network or authentication services (e.g. Log4Shell, MOVEit, Spring4Shell, Citrix ADC, ScreenConnect).
2. **Tier 2 (Attend / High Urgency)** (Items 16–27): Confirmed weaponized exploits or KEV listings with client/local attack vectors, or critical zero-days without active mass exploitation in KEV (e.g. XZ Utils backdoor, Follina, PrintNightmare, WinRAR, Dirty Pipe, Sudo Baron Samedit).
3. **Tier 3 (Track / Standard Maintenance)** (Items 28–35): Validated high/medium CVSS vulnerabilities without active KEV exploitation or with low exploit likelihood (e.g. Redis STRALGO, PostgreSQL, Polkit, Linux cgroups).
4. **Tier 4 (Defer / Low Urgency)** (Items 36–39): Low severity, client-side, or non-actionable bugs (e.g. OpenSSH user enum, curl cookie path traversal).
5. **Synthetic Missing-Data Edge Cases** (Items 40–41): **Not real CVEs.** Synthetic records constructed to verify missing-data handling:
   - `CVE-2024-99991`: Synthetic record with no CVSS base score (tests missing-CVSS policy).
   - `CVE-2024-99992`: Synthetic record with no EPSS probability (tests missing-EPSS policy).

## 3. Reference Labels & Evaluation Protocol
Reference relevance grades are categorized into 4 ordinal levels based on a **manual application of the CISA SSVC decision rubric** by the authors. These labels represent expert-curated heuristic judgments and are NOT independently validated breach ground truth. High rank correlation with SSVC-derived labels reflects construct consistency with established triage principles, not empirical prediction of real-world exploitation outcomes.
- **Act (Relevance = 3)**: Super-critical / immediate emergency action required.
- **Attend (Relevance = 2)**: Actionable within standard patch cycle.
- **Track (Relevance = 1)**: Regular tracking / patch maintenance.
- **Defer (Relevance = 0)**: Low priority / non-actionable / missing data.

For top-$K$ binary relevance evaluation (Precision@10, Recall@10):
- **Primary Threshold ($\tau = 3$, Act / Emergency Action)**: Evaluates whether the top 10 items identify the most critical Tier 1 vulnerabilities requiring immediate response ($N_{\text{relevant}} = 15$).
- **Secondary Threshold ($\tau = 2$, Actionable Action)**: Evaluates whether the top 10 items identify high/urgent remediation items ($N_{\text{relevant}} = 27$).

## 4. Dataset Integrity & Checksum
- **Dataset File**: `data/benchmark/cves.csv`
- **SHA-256 Hash**: `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`
- **Validation Command**: `python generate_data.py`

## 5. Threats to Validity & Limitations
1. **Construct Circularity / Heuristic Alignment**: The ground-truth ordinal labels derive from CISA SSVC decision categories based on exploitation state (correlated with KEV and EPSS), exposure ($N$), and mission impact ($C$ and $A$). Consequently, high rank correlation with SSVC labels reflects **construct consistency / heuristic alignment** with established vulnerability triage principles, rather than independent empirical evidence of enterprise breach prevention.
2. **Catalog Incompleteness**: Absence from the CISA KEV catalog does not guarantee that a vulnerability has never been exploited in targeted or covert campaigns.
3. **Temporal Dynamics**: EPSS probabilities represent a rolling 30-day forecast and fluctuate daily. This benchmark captures a snapshot frozen on **2026-10-14**.
4. **Environmental Context**: Network exposure ($N$) and asset criticality ($A$) in public benchmarks reflect reference deployment baselines (e.g. external edge service vs. internal host) rather than a specific organization's internal network topography.
5. **Sample Size & Generalization**: The 41 records cover distinct risk archetypes and missing-data edge cases, but do not represent the entire historical universe of vulnerabilities. Observed ranking differences must not be interpreted as proving causal superiority across all network topologies.
6. **Snapshot Timestamps vs. Disclosure Dates**: The `source_timestamp` field in `cves.csv` indicates the date the intelligence was retrieved and frozen for the benchmark (2026-10-14), not the historic disclosure dates of the underlying vulnerabilities (which span 2015 through 2024).
