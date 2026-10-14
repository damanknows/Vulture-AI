# Expanded Benchmark Evaluation (500 Real CVE Records)

**Dataset**: `data/benchmark/cves_500.csv` (500 unique real CVEs)  
**CISA KEV Exploited Total**: 25 confirmed active exploits in benchmark ($N_{\text{KEV}} = 25$)  
**Author-Curated SSVC Labels**: 39 records (original benchmark subpopulation)  
**Unlabeled Public CVEs**: 461 records (sampled from official CVE List V5)  

## 1. Retrospective CISA KEV Concordance Across Prioritization Schemes

Evaluates the ability of each prioritization scheme to surface confirmed exploited vulnerabilities from a 500-vulnerability backlog.

| Prioritization Method | Precision@5 | Recall@5 | Precision@10 | Recall@10 | Precision@15 | Recall@15 | Precision@20 | Recall@20 | Precision@25 | Recall@25 |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **CVSS-only** | 1.0000 (5/5) | 0.2000 (5/25) | 0.7000 (7/10) | 0.2800 (7/25) | 0.7333 (11/15) | 0.4400 (11/25) | 0.5500 (11/20) | 0.4400 (11/25) | 0.4400 (11/25) | 0.4400 (11/25) |
| **EPSS-only** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) | 0.9500 (19/20) | 0.7600 (19/25) | 0.8800 (22/25) | 0.8800 (22/25) |
| **KEV-first** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) | 1.0000 (20/20) | 0.8000 (20/25) | 1.0000 (25/25) | 1.0000 (25/25) |
| **Combined Baseline** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) | 1.0000 (20/20) | 0.8000 (20/25) | 1.0000 (25/25) | 1.0000 (25/25) |
| **VRS Proposed (vrs-v1)** | 1.0000 (5/5) | 0.2000 (5/25) | 1.0000 (10/10) | 0.4000 (10/25) | 1.0000 (15/15) | 0.6000 (15/25) | 1.0000 (20/20) | 0.8000 (20/25) | 1.0000 (25/25) | 1.0000 (25/25) |

> **Key Empirical Finding**: In a 500-vulnerability backlog, **CVSS-only achieves only 44.0% recall at depth 25** (11/25 exploits captured), failing to prioritize 14 actively weaponized vulnerabilities. By contrast, threat-intelligence-aware scoring (**VRS Proposed**, **Combined Baseline**, and **KEV-first**) achieves **100% recall at depth 25** (25/25 exploits captured), surfacing all known exploited vulnerabilities in the first 25 positions.

## 2. VRS Score Distribution on 500 CVEs

- **Total Scored Findings**: 500 / 500 (100%)
- **VRS Score Range**: 17.44 to 100.00 (Mean: 36.40)
- **Urgent Bucket Findings**: 25 (all active KEV matches)
- **Standard Bucket Findings**: 475

## 3. Methodological Disclaimers & Limitations

1. **Tied Performance at Top Cutoffs**: VRS Proposed, Combined Baseline, and KEV-first achieve identical precision and recall for depths $K \le 25$ because all three prioritize KEV-listed items into the top tier. VRS does not claim superiority over EPSS-only or the Combined baseline at these cutoffs.
2. **Retrospective Check vs. Temporal Prediction**: The evaluation checks ranking concordance against the CISA KEV snapshot frozen on 2026-10-13, not forward predictive ability. Features were not point-in-time reconstructed at vulnerability publication.
3. **Absence != Non-Exploitation**: Absence from CISA KEV indicates unobserved in federal civilian reporting, NOT confirmed non-exploitation.
4. **No Label Fabrication**: The 461 newly sampled CVEs do not have manual SSVC labels. SSVC correlation metrics apply strictly to the 39 original labeled records.
