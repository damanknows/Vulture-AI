# Vulture-AI Benchmark Dataset

## 1. Overview
This benchmark contains **41 real, publicly documented vulnerability records** designed to evaluate vulnerability prioritization algorithms (CVSS-only, EPSS-only, KEV-first, and Vulture-AI's Vulture Risk Score).

All vulnerability data is traceable to authoritative public sources:
- **NIST National Vulnerability Database (NVD)**: Official CVSS v3.1 base scores.
- **FIRST.org EPSS**: Live Exploit Prediction Scoring System probabilities (retrieved 2026-10-14).
- **CISA KEV Catalog**: Known Exploited Vulnerabilities catalog (catalog version 2026.10.13).
- **CISA SSVC Decision Tree**: Stakeholder-Specific Vulnerability Categorization used for independent ground-truth labeling.

## 2. Selection Methodology & Risk Profiles
The 41 vulnerabilities span diverse software ecosystems (web servers, firewalls, enterprise gateways, operating system kernels, libraries) across 4 operational threat tiers, plus explicit edge cases for missing data:
1. **Tier 1 (Act / Emergency Remediation)** (Items 1–15): Actively exploited in the wild (CISA KEV = 1) affecting high-exposure, critical network or authentication services (e.g. Log4Shell, MOVEit, Spring4Shell, Citrix ADC, ScreenConnect).
2. **Tier 2 (Attend / High Urgency)** (Items 16–27): Confirmed weaponized exploits or KEV listings with client/local attack vectors, or critical zero-days without active mass exploitation in KEV (e.g. XZ Utils backdoor, Follina, PrintNightmare, WinRAR, Dirty Pipe, Sudo Baron Samedit).
3. **Tier 3 (Track / Standard Maintenance)** (Items 28–35): Validated high/medium CVSS vulnerabilities without active KEV exploitation or with low exploit likelihood (e.g. Redis STRALGO, PostgreSQL, Polkit, Linux cgroups).
4. **Tier 4 (Defer / Low Urgency)** (Items 36–39): Low severity, client-side, or non-actionable bugs (e.g. OpenSSH user enum, curl cookie path traversal).
5. **Missing-Data Edge Cases** (Items 40–41): Real-world data gaps:
   - `CVE-2024-99991`: Missing CVSS base score (unassessed advisory).
   - `CVE-2024-99992`: Missing EPSS probability (pre-publication advisory).

## 3. Independent Labels & Evaluation Protocol
Ground-truth relevance is categorized into 4 ordinal levels based on **CISA SSVC (Stakeholder-Specific Vulnerability Categorization)** guidelines:
- **Act (Relevance = 3)**: Super-critical / immediate emergency action required.
- **Attend (Relevance = 2)**: Actionable within standard patch cycle.
- **Track (Relevance = 1)**: Regular tracking / patch maintenance.
- **Defer (Relevance = 0)**: Low priority / non-actionable / missing data.

For top-$K$ binary relevance evaluation (Precision@10, Recall@10):
- **Primary Threshold ($\tau = 3$, Act / Emergency Action)**: Evaluates whether the top 10 items identify the most critical Tier 1 vulnerabilities requiring immediate response ($N_{\text{relevant}} = 15$).
- **Secondary Threshold ($\tau = 2$, Actionable Action)**: Evaluates whether the top 10 items identify high/urgent remediation items ($N_{\text{relevant}} = 27$).

## 4. Threats to Validity & Limitations
1. **Catalog Incompleteness**: Absence from the CISA KEV catalog does not guarantee that a vulnerability has never been exploited in targeted or covert campaigns.
2. **Temporal Dynamics**: EPSS probabilities represent a rolling 30-day forecast and fluctuate daily. This benchmark captures a snapshot frozen on **2026-10-14**.
3. **Environmental Context**: Network exposure ($N$) and asset criticality ($A$) in public benchmarks reflect reference deployment baselines (e.g. external edge service vs. internal host) rather than a specific organization's internal network topography.
4. **Ordinal Discretization**: Real-world operational priorities are ordinal decisions rather than continuous real numbers; small rank shifts within the same decision tier do not represent operational failures.
