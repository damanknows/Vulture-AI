# Retrospective CISA KEV Concordance Summary

**Benchmark Population**: 41 records (39 eligible real CVEs + 2 synthetic missing-data test cases)  
**Authoritative Source**: CISA Known Exploited Vulnerabilities Catalog (Version: `2026.10.13`, Released: `2026-10-13T19:10:43.6568Z`)  
**Catalog SHA-256**: `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28`  
**Processing Timestamp (UTC)**: `2026-10-13T23:42:06.248010+00:00`  

## 1. Top-15 VRS Recommendations vs. CISA KEV Evidence

Evaluated on the top 15 prioritized real vulnerabilities from Vulture-AI (`vrs-v1`). Synthetic test cases are excluded from ranking evaluation.

| VRS Rank | CVE ID | Vulnerability Summary | CVSS | EPSS | Exposure | SSVC Label | In KEV? | KEV Date Added | KEV Due Date | Source Advisory |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | `CVE-2021-44228` | Apache Log4j2 JNDI RCE (Log4Shell) | 10.0 | 0.99999 | 1.0 | Act | **YES** | 2021-12-10 | 2021-12-24 | [Link](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) |
| 2 | `CVE-2024-1709` | ConnectWise ScreenConnect Authentication | 10.0 | 0.9998 | 1.0 | Act | **YES** | 2024-02-22 | 2024-02-29 | [Link](https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8) |
| 3 | `CVE-2023-20198` | Cisco IOS XE Web UI Privilege Escalation | 10.0 | 0.99571 | 1.0 | Act | **YES** | 2023-10-16 | 2023-10-20 | [Link](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-dublin-17121/221128-software-fix-availability-for-cisco-ios.html) |
| 4 | `CVE-2023-34362` | Progress MOVEit Transfer SQLi RCE | 9.8 | 0.99934 | 1.0 | Act | **YES** | 2023-06-02 | 2023-06-23 | [Link](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) |
| 5 | `CVE-2023-3519` | Citrix ADC and NetScaler Gateway RCE | 9.8 | 0.99749 | 1.0 | Act | **YES** | 2023-07-19 | 2023-08-09 | [Link](https://support.citrix.com/article/CTX561482/citrix-adc-and-citrix-gateway-security-bulletin-for-cve20233519-cve20233466-cve20233467) |
| 6 | `CVE-2019-11510` | Pulse Connect Secure VPN Arbitrary File  | 10.0 | 0.99999 | 1.0 | Act | **YES** | 2021-11-03 | 2022-05-03 | [Link](https://www.cisa.gov/news-events/directives/ed-21-03-mitigate-pulse-connect-secure-product-vulnerabilities) |
| 7 | `CVE-2021-26855` | Microsoft Exchange Server Pre-auth SSRF  | 9.8 | 0.99996 | 1.0 | Act | **YES** | 2021-11-03 | 2022-05-03 | [Link](https://www.cisa.gov/news-events/directives/ed-21-02-mitigate-microsoft-exchange-premises-product-vulnerabilities) |
| 8 | `CVE-2022-1388` | F5 BIG-IP iControl REST Auth Bypass RCE | 9.8 | 0.99954 | 1.0 | Act | **YES** | 2022-05-10 | 2022-05-31 | [Link](https://nvd.nist.gov/vuln/detail/CVE-2022-1388) |
| 9 | `CVE-2022-22965` | Spring Framework RCE (Spring4Shell) | 9.8 | 0.99638 | 1.0 | Act | **YES** | 2022-04-04 | 2022-04-25 | [Link](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) |
| 10 | `CVE-2020-1472` | Microsoft Netlogon Privilege Escalation  | 10.0 | 0.99389 | 0.8 | Act | **YES** | 2021-11-03 | 2022-05-03 | [Link](https://www.cisa.gov/news-events/directives/ed-20-04-mitigate-netlogon-elevation-privilege-vulnerability-august-2020-patch-tuesday) |
| 11 | `CVE-2023-46805` | Ivanti Connect Secure Authentication Byp | 8.2 | 0.99986 | 1.0 | Act | **YES** | 2024-01-10 | 2024-01-22 | [Link](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US) |
| 12 | `CVE-2023-23397` | Microsoft Outlook NTLM Credential Theft  | 9.8 | 0.97159 | 0.8 | Act | **YES** | 2023-03-14 | 2023-04-04 | [Link](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-23397) |
| 13 | `CVE-2024-21413` | Microsoft Outlook Moniker RCE (#MonikerL | 9.8 | 0.9466 | 0.8 | Act | **YES** | 2025-02-06 | 2025-02-27 | [Link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413) |
| 14 | `CVE-2021-41773` | Apache HTTP Server 2.4.49 Path Traversal | 7.5 | 0.99992 | 1.0 | Act | **YES** | 2021-11-03 | 2021-11-17 | [Link](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) |
| 15 | `CVE-2017-0144` | SMBv1 Remote Code Execution (EternalBlue | 8.1 | 0.9923 | 0.9 | Act | **YES** | 2022-02-10 | 2022-08-10 | [Link](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) |

> **Top-15 Retrospective Precision**: **15/15 (100.0%)** of the top 15 prioritized items are confirmed in the official CISA KEV catalog.
> **Top-15 Retrospective Recall**: **15/25 (60.0%)** of all KEV-listed items in the benchmark are captured within the top 15.

## 2. Multi-Cutoff KEV Retrospective Precision and Recall Across Methods

This table evaluates the fraction of recommendations at depth $k$ that correspond to confirmed KEV entries (Precision@$k$, denominator $= k$) and the proportion of all benchmark KEV entries captured (Recall@$k$, denominator $= N_{\text{KEV}} = 25$). All comparisons use the identical eligible benchmark population ($N = 39$).

| Prioritization Method | Precision@5 | Recall@5 | Precision@10 | Recall@10 | Precision@15 | Recall@15 |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **CVSS-only** | 1.0000 (5/5) | 0.2000 (5/25) | 0.7000 (7/10) | 0.2800 (7/25) | 0.7333 (11/15) | 0.4400 (11/25) |
| **EPSS-only** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) |
| **KEV-first** | 1.0000 (5/5) | 0.2000 (5/25) | 0.8000 (8/10) | 0.3200 (8/25) | 0.8667 (13/15) | 0.5200 (13/25) |
| **Combo Baseline** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) |
| **VRS Proposed (vrs-v1)** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) |

## 3. Scientific Disclaimers & Methodological Limitations

1. **Retrospective Association vs. Temporal Prediction**: This retrospective check evaluates ranking concordance against the CISA KEV snapshot frozen on 2026-10-13. Input features (CVSS, EPSS, KEV flags) were not point-in-time reconstructed at the initial historical disclosure date of each vulnerability. Hence, these metrics demonstrate retrospective concordance with known threats, not forward temporal predictive accuracy.
2. **Information Overlap / Feature Leakage Disclosure**: The VRS scoring engine directly incorporates an exploitation component ($K \in \{0, 1\}$) and an emergency bucket override based on KEV status. Consequently, strong alignment with KEV inclusion is partially an expected consequence of scoring input design rather than purely emergent predictive ranking.
3. **Catalog Absence != Confirmed Non-Exploitation**: An unlisted status in CISA KEV denotes that a vulnerability has not been observed and cataloged through federal civilian agency reporting channels. It must NOT be interpreted as confirmed non-exploitation or as a negative ground-truth label.
4. **Catalog Date != First Exploitation Date**: The `dateAdded` field represents the administrative date CISA added the CVE to the KEV catalog under BOD 22-01 mandates, not the date of initial threat actor discovery or weaponization.
5. **Sample Size & Curated Benchmark Limitations ($N=41$)**: The benchmark evaluates 39 real CVEs selected across diverse risk archetypes plus 2 synthetic edge cases. While representative of varied severity and exposure tiers, performance on this curated sample does not guarantee identical precision over uncurated enterprise corpora with thousands of uncataloged vulnerabilities.
6. **Synthetic Test Case Exclusions**: Records `CVE-2024-99991` and `CVE-2024-99992` are non-existent identifiers preserved exclusively to test missing-data engine behaviors. They are strictly excluded from all empirical ranking evaluation.
