# DATA_PROVENANCE.md

Vulture-AI ICCI 2026 Revision — Complete Dataset Provenance and Artifact Tracking

**Last Updated**: 2026-11-26 | **Audit Scope**: All benchmark datasets, threat intelligence feeds, and experimental artifacts

---

## Overview

This document comprehensively documents every dataset, intelligence feed, and experimental artifact in the Vulture-AI repository. Each entry specifies:

- **Name**: Dataset identifier
- **Source**: Origin (NVD, FIRST, CISA, synthetic, human-curated)
- **Collection Date**: When data was gathered (if applicable)
- **Record Count**: Number of items
- **Record Type**: CVEs, vulnerability records, threat feeds
- **Composition**: Real vs. synthetic records
- **Provenance**: Data lineage and transformations
- **Known Issues**: Limitations, gaps, biases
- **Validation**: Checksums, reproducibility notes

---

## Primary Benchmark Datasets

### 1. Curated Reference Benchmark (41 CVEs)

| Property | Value |
|----------|-------|
| **File Path** | `data/benchmark/cves.csv` |
| **Source** | Author-curated + NVD + FIRST EPSS + CISA KEV |
| **Collection Date** | 2026-10-14 (snapshot frozen) |
| **Total Records** | 41 |
| **Real CVEs** | 39 |
| **Synthetic Records** | 2 (CVE-2024-99991, CVE-2024-99992) |
| **SHA-256 Hash** | `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e` |
| **SHA-256 Verification** | ✅ Verified in HOTFIX_REPORT.md and generate_data.py |

**Record Composition**:

| Tier | Label | Count | Real | Synthetic | Description |
|------|-------|-------|------|-----------|---|
| Act | 3 | 15 | 15 | 0 | Immediate emergency remediation; mass KEV exploitation on perimeter |
| Attend | 2 | 12 | 12 | 0 | High urgency; public weaponized or KEV+local vector |
| Track | 1 | 8 | 8 | 0 | Standard patch cycle; high/medium severity without public exploit |
| Defer | 0 | 6 | 4 | 2 | Low priority, client-side, non-exploitable, or missing data |
| **TOTAL** | — | 41 | 39 | 2 | — |

**Real CVE Examples**:
- Rank 1: CVE-2021-44228 (Log4Shell) - CVSS 10.0, EPSS 0.99999, KEV=1
- Rank 2: CVE-2023-34362 (MOVEit RCE) - CVSS 9.8, EPSS 0.99934, KEV=1
- Rank 36: CVE-2018-15473 (OpenSSH enumeration) - CVSS 5.3, EPSS 0.98631, KEV=0
- Rank 40–41: CVE-2024-99991, CVE-2024-99992 (synthetic edge cases)

**Synthetic Records**:
- **CVE-2024-99991**: Missing CVSS (test missing-data handling) | EPSS=empty, KEV=0 | Label=Defer
- **CVE-2024-99992**: Missing EPSS (test fallback policy) | CVSS=6.5, KEV=0 | Label=Defer
- **Rationale**: Evaluate edge-case scoring behavior when authoritative data unavailable

**Data Columns**:
```csv
cve_id,cvss,epss,kev,exposure,asset_criticality,reference_priority,independent_label,source_timestamp,source_reference,description
CVE-2021-44228,10.0,0.99999,1,1.0,1.0,1,Act,2026-10-14T00:00:00Z,...
...
CVE-2024-99991,,,0,0.5,0.5,40,Defer,2026-10-14T00:00:00Z,SYNTHETIC-EDGE-CASE...
CVE-2024-99992,6.5,,0,0.5,0.5,41,Defer,2026-10-14T00:00:00Z,SYNTHETIC-EDGE-CASE...
```

**Data Provenance Chain**:

```
NVD v2.0 (CVSS base scores, CVE descriptions)
    ↓
FIRST EPSS API (2026-10-13 snapshot; rolling 30-day exploit probability)
    ↓
CISA KEV catalog (version 2026.10.13; confirmed in-the-wild exploitation)
    ↓
Author manual enrichment:
  - Network exposure (N): assigned based on attack vector (perimeter=1.0, internal=0.3)
  - Asset criticality (A): assigned based on affected component type (DC=1.0, workstation=0.2)
  - Reference priority: SSVC decision tree mapping
  - independent_label: 4-tier rubric (Act/Attend/Track/Defer)
    ↓
Final CSV: data/benchmark/cves.csv (SHA-256 verified)
```

**Known Issues**:
- ✅ Construct circularity: Reference labels derived from SSVC rubric which uses same features (KEV, EPSS, N, A) as VRS
- ✅ Selection bias: "Hall of fame" CVEs (Log4Shell, MOVEit, etc.) not representative of enterprise long-tail
- ✅ Environmental feature assignment: N and A manually assigned to archetypal deployment profiles, not live telemetry
- ✅ Small size: N=41 limited statistical power; confidence intervals needed
- ✅ Synthetic records at tail: CVE-2024-999xx positioned at ranks 40–41; minimal impact on top-tier metrics

**Validation**:
```bash
$ cd <repo-root>
$ python generate_data.py
# Output: "41 records validated (39 real + 2 synthetic); SHA-256: 27979cc0..."
```

---

### 2. Expanded Corpus (500 CVEs)

| Property | Value |
|----------|-------|
| **File Path** | `data/benchmark/cves_500.csv` |
| **Source** | Curated 39 CVEs + 461 newly sampled from CVEProject/cvelistV5 |
| **Collection Date** | 2026-10-14 (sampling with seed=42) |
| **Total Records** | 500 |
| **Real CVEs** | 500 (all real, no synthetic) |
| **KEV-listed** | 25 (5.0%) |
| **Unlabeled** | 461 (newly added, no reference priority assigned) |
| **SHA-256 Hash** | `009c8566f1fd...` (prefix; full hash in cves_500_manifest.json) |

**Composition**:
- **Rows 1–39**: Curated benchmark CVEs (labeled with reference priority)
- **Rows 40–500**: 461 real public CVEs deterministically sampled (seed=42) from:
  - `CVEProject/cvelistV5/cves/2023/0xxx/` (various 2023 CVE batches)
  - `CVEProject/cvelistV5/cves/2024/0xxx/` (various 2024 CVE batches)

**Data Provenance Chain**:

```
CVEProject/cvelistV5 public repository (GitHub)
    ↓
Deterministic sampling (seed=42, 461 records from restricted domain)
    ↓
Merge with curated 39 CVEs → 500 total
    ↓
FIRST EPSS API query for all 500 (cached 2026-10-13)
    ↓
CISA KEV membership check (catalog version 2026.10.13)
    ↓
Final CSV: data/benchmark/cves_500.csv
    ↓
Manifest: data/benchmark/cves_500_manifest.json (provenance signed)
```

**KEV Status**:
- **25 KEV-listed** (5.0% of 500):
  - 25 from curated baseline (all 25 of original 39 that are KEV-listed)
  - 0 from 461 newly sampled (by definition of corpus construction: "None of the 461 added records matched the CISA KEV snapshot used in this experiment")
- **475 non-KEV-listed** (95.0% of 500):
  - 14 from curated baseline
  - 461 from new samples

**Known Issues**:
- ✅ **Non-independence concern**: Rows 1–39 are both labeled (for 41-CVE benchmark) and included in 500-CVE corpus
  - Mitigation: 461 newly added records are explicitly unlabeled; only 39 curated have reference priority
  - Recommendation: Create held-out 461-CVE set (excluding labeled 39) for independent validation
- ✅ **KEV snapshot selection bias**: Version 2026.10.13 chosen; none of 461 new samples in that snapshot
  - This is by-design constraint (to show scale testing without label data contamination)
  - However, using different KEV snapshot dates would yield different proportions
- ✅ **Restricted domain sampling**: Only 2023/0xxx and 2024/0xxx included
  - Excludes pre-2023 CVEs (older but still active in enterprises)
  - Excludes 2024-10+ CVEs (newer, potentially rising threat)
- ✅ **EPSS drift**: EPSS probabilities collected 2026-10-13; will drift if recomputed at later date
  - Frozen snapshot ensures reproducibility; note that real EPSS values change continuously

**Validation**:
```bash
$ python -c "
import csv
with open('data/benchmark/cves_500.csv') as f:
    rows = list(csv.DictReader(f))
    assert len(rows) == 500, f'Expected 500 rows, got {len(rows)}'
    kev_count = sum(1 for r in rows if r['kev'] == '1')
    labeled_count = sum(1 for r in rows if r['independent_label'] != '')
    print(f'500 CVEs verified: {kev_count} KEV-listed, {labeled_count} labeled')
"
# Output: 500 CVEs verified: 25 KEV-listed, 39 labeled
```

---

## Threat Intelligence Feeds

### 3. FIRST EPSS Cache (500 CVEs)

| Property | Value |
|----------|-------|
| **File Path** | `data/external/epss_cache_500.json` |
| **Source** | FIRST EPSS API v2.0 (https://api.first.org/data/v1/epss) |
| **Query Date** | 2026-10-13 |
| **Cache TTL** | 24 hours (cached at collection time) |
| **Total Records** | 500 (one entry per CVE in cves_500.csv) |
| **Data Format** | JSON array of EPSS scores |

**Sample Entry**:
```json
{
  "cve": "CVE-2021-44228",
  "epss": 0.99999,
  "percentile": 0.9988,
  "date": "2026-10-13"
}
```

**Data Quality**:
- **Coverage**: 99.8% (499/500 CVEs have EPSS scores; 1 missing)
- **Precision**: Floating-point scores to 5 decimal places
- **Staleness**: 11+ days old as of 2026-11-26; EPSS rolls continuously

**Known Issues**:
- ✅ **Temporal drift**: EPSS probabilities represent rolling 30-day forecast; requerying later will yield different values
- ✅ **API rate limits**: FIRST EPSS API has rate limiting; bulk queries may fail (mitigated with disk caching)
- ✅ **Missing EPSS**: 1 CVE in 500-corpus lacks EPSS score; handled by default=0.0 policy

**Validation**:
```python
import json
with open('data/external/epss_cache_500.json') as f:
    data = json.load(f)
    assert len(data) == 500
    assert all('epss' in record for record in data if record['epss'] is not None)
    print(f"EPSS cache: {len(data)} records validated")
```

---

### 4. CISA KEV Provenance

| Property | Value |
|----------|-------|
| **File Path** | `data/benchmark/cisa_kev_provenance.json` |
| **Source** | CISA Known Exploited Vulnerabilities catalog (official JSON) |
| **Catalog URL** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **Snapshot Date** | 2026-10-13 |
| **Total CVEs in KEV** | 1,087 (global catalog) |
| **CVEs in 41-benchmark** | 25 KEV-listed (61% of real 39 CVEs) |
| **CVEs in 500-corpus** | 25 KEV-listed (5.0% of 500 total) |

**Data Format**:
```json
{
  "cveID": "CVE-2021-44228",
  "vendorProject": "Apache",
  "product": "Log4j",
  "vulnerabilityName": "Apache Log4j2 JNDI Features Does Not Protect Against Adversarial JNDI Requests",
  "dateAdded": "2021-12-10",
  "shortDescription": "...",
  "knownRansomwareCampaignUse": "Yes",
  "knownMalwareUse": "Yes"
}
```

**KEV Snapshot Characteristics**:
- **Coverage**: 1,087 confirmed in-the-wild exploitations documented
- **Recency**: Regularly updated by CISA (new additions weekly)
- **Reliability**: Authoritative source for federal compliance (BOD 22-01)

**Known Issues**:
- ✅ **Catalog lag**: CVEs confirmed exploited may take weeks to appear in KEV
- ✅ **Retrospective labeling**: KEV status is a *property of the snapshot*, not forward prediction
- ✅ **Selection bias toward critical**: KEV overrepresents perimeter exploits; underrepresents internal/client-side flaws

---

## Experimental Results Artifacts

### 5. Main Comparison Results (41-CVE Benchmark)

| Property | Value |
|----------|-------|
| **File Path** | `experiments/results/metrics.json` |
| **Generated By** | `experiments/compute_metrics.py` |
| **Evaluation Date** | 2026-10-14 (locked) |
| **Methods Evaluated** | CVSS-only, EPSS-only, KEV-first, Combo, VRS |
| **Metrics** | NDCG@5/10/15, Precision@10, Recall@10, Spearman ρ |

**Sample Output**:
```json
{
  "CVSS-only": {
    "ndcg_5": 0.8062,
    "ndcg_10": 0.7563,
    "ndcg_15": 0.7855,
    "precision_10": 0.6000,
    "recall_10": 0.4000,
    "spearman_rho": 0.7357
  },
  "VRS Proposed (vrs-v1)": {
    "ndcg_5": 1.0000,
    "ndcg_10": 1.0000,
    "ndcg_15": 1.0000,
    "precision_10": 1.0000,
    "recall_10": 0.6667,
    "spearman_rho": 0.9488
  }
}
```

**Data Quality**:
- ✅ Deterministic: Results identical across repeated runs
- ✅ Reproducible: `experiments/run_vrs.py` can regenerate

---

### 6. Ablation Study Results (41-CVE Benchmark)

| Property | Value |
|----------|-------|
| **File Path** | `experiments/results/ablation.json` |
| **Generated By** | `experiments/run_ablation.py` |
| **Variants Tested** | 5 (Full, No EPSS, No KEV, No Context, No Bucket Override) |
| **Ablation Methodology** | Proportional weight renormalization after feature removal |

**Ablation Findings**:

| Variant | Spearman ρ | Δρ vs. Full | Key Finding |
|---------|------------|------|---|
| VRS (Full Model) | 0.9488 | — | Baseline |
| VRS (No EPSS) | 0.9575 | +0.0087 | Paradoxically improves (EPSS emphasizes scanning, hurts SSVC alignment) |
| VRS (No KEV) | 0.9451 | -0.0037 | Minor degradation; urgent bucket not critical for Spearman |
| VRS (No Context) | 0.8782 | -0.0706 | Major degradation; environmental context adds 7% ρ improvement |
| VRS (No Bucket Override) | 0.9535 | +0.0047 | Slight improvement; bucket override enforces policy compliance at cost of raw ranking correlation |

**Data Quality**:
- ✅ Weights renormalized (Σw_i = 1.0 maintained)
- ✅ Deterministic tie-breaking preserved
- ⚠️ Ceiling effects visible: NDCG@10 and P@10 identical for Full, No EPSS, No Bucket

---

### 7. 500-CVE Policy Concordance Results

| Property | Value |
|----------|-------|
| **File Path** | `experiments/results/expanded_500_results.json` |
| **Generated By** | `experiments/generate_benchmark_500.py` → evaluation on 500-CVE corpus |
| **Evaluation Type** | Retrospective policy-concordance vs. CISA KEV (25 items) |
| **Metrics** | Precision@K, Recall@K at K∈{10, 20, 25} |

**Results**:

| Method | P@10 | R@10 | P@25 | R@25 |
|--------|------|------|------|------|
| CVSS-only | 0.70 | 0.28 | 0.44 | 0.44 |
| EPSS-only | 1.00 | 0.40 | 0.88 | 0.88 |
| KEV-first | 1.00 | 0.40 | 1.00 | 1.00 |
| Combined Baseline | 1.00 | 0.40 | 1.00 | 1.00 |
| **VRS Proposed** | **1.00** | **0.40** | **1.00** | **1.00** |

**Structural Ceiling Effect**:
- All threat-aware methods (KEV-first, Combo, VRS) tie at R@25=1.0 because they directly incorporate KEV status
- This is *policy-concordance validation*, not predictive superiority
- CVSS-only degrades severely (R@25=0.44) because it lacks threat intelligence

**Data Quality**:
- ✅ Deterministic evaluation
- ⚠️ Retrospective only; not forward prediction
- ⚠️ Structural ceiling: methods with KEV signal achieve perfect recall by design

---

### 8. RAG Evaluation Results

| Property | Value |
|----------|-------|
| **File Path** | `experiments/results/rag_eval.json` |
| **Evaluation Type** | Deterministic MockLLM + live Llama-3.1-8B |
| **Test Cases** | 41 benchmark records + 5 adversarial injection patterns |

**MockLLM Results**:
```json
{
  "schema_valid": 41,
  "schema_violations": 0,
  "injection_blocked": 5,
  "injection_blocked_rate": 1.0,
  "numeric_grounding_failed": 0
}
```

**Live Llama-3.1-8B Results** (temperature=0.0):
```json
{
  "benchmark_records": 41,
  "schema_valid": 41,
  "numeric_grounding_passed": 39,
  "numeric_grounding_failed": 2,
  "grounding_pass_rate": 0.9512,
  "adversarial_banners": 5,
  "injections_blocked": 5,
  "injection_block_rate": 1.0
}
```

**Failures Analyzed**:
- **Record 15** (CVE-2023-20198): LLM rounded CVSS 10.0 → "9.9–10.0 range"; validator flagged numeric mismatch (tolerance ±0.01)
- **Record 28** (CVE-2018-15473): LLM omitted EPSS; validator flagged missing grounding claim

**Data Quality**:
- ✅ Schema validation deterministic (Pydantic enforcement)
- ⚠️ Live LLM evaluation not fully deterministic (temperature=0.0 but model variations exist)
- ⚠️ Small test set (5 adversarial patterns insufficient for comprehensive injection resistance claims)

---

## Manuscript and Paper Artifacts

### 9. LaTeX Manuscript

| Property | Value |
|----------|-------|
| **File Path** | `paper/manuscript.tex` |
| **Format** | IEEE IEEEtran double-blind conference submission |
| **Page Count** | 6 pages (compressed format with microtype, tight spacing) |
| **Bibliography** | `paper/references.bib` (25+ entries, verified academic sources) |
| **Figures** | Empirical ranking comparison plot (Figure 1) |
| **Tables** | Main results (Table 1), ablation (Table 2), 500-CVE policy (Table 3) |
| **Compilation** | PDFLaTeX; clean build with zero warnings |

**PDF Output**:
```
File: paper/manuscript.pdf
Size: 465,344 bytes
SHA-256: [computed on demand]
Compilation Status: ✅ Clean (no errors, no warnings)
```

**Citation Accuracy**:
- 25 bibliography entries verified (DOIs, page numbers, author names)
- Academic sources (NVD, FIRST, CISA, IEEE, ACM, arXiv)
- Coverage: 2019–2026 publications

**Known Issues**:
- ✅ Missing CVSS v4.0 and EPSS v2 recent literature (2024–2025)
- ✅ Limited RAG security literature coverage (rapidly evolving field)

---

## Reproducibility and Validation Artifacts

### 10. Reproducibility Manifest

| Property | Value |
|----------|-------|
| **File Path** | `experiments/results/reproducibility_manifest.json` |
| **Purpose** | Complete provenance for reproduction |
| **Contents** | Software versions, seed values, snapshot timestamps, file checksums |

**Sample Manifest**:
```json
{
  "vulture_ai_version": "0.2.0",
  "python_version": "3.10.12",
  "dependencies": {
    "numpy": "1.24.3",
    "scipy": "1.11.4",
    "pydantic": "2.5.0",
    "requests": "2.31.0"
  },
  "random_seed": 42,
  "epss_snapshot_date": "2026-10-13",
  "kev_snapshot_date": "2026-10-13",
  "benchmark_41_cves_sha256": "27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e",
  "benchmark_500_cves_sha256": "009c8566f1fd...",
  "execution_timestamp": "2026-10-14T12:00:00Z",
  "platform": "Linux"
}
```

---

## Synthetic and Edge-Case Data

### 11. Synthetic Edge-Case Records

| CVE ID | Reason | CVSS | EPSS | KEV | Label | Rank | Purpose |
|--------|--------|------|------|-----|-------|------|---------|
| **CVE-2024-99991** | Missing CVSS (no NVD entry) | NULL | 0.0 | 0 | Defer | 40 | Test missing-data fallback (vrs_unavailable bucket) |
| **CVE-2024-99992** | Missing EPSS (API failure simulation) | 6.5 | NULL | 0 | Defer | 41 | Test missing EPSS fallback (default=0.0) |

**Validation**:
- ✅ Explicitly marked as synthetic in CSV (`source_reference` column contains "SYNTHETIC")
- ✅ Positioned at tail of ranking (ranks 40–41) to minimize metric impact
- ✅ Fallback policies correctly applied in risk_engine.py

**Impact on Results**:
- **41-CVE metrics (K≤10)**: Negligible (synthetic records never enter top-10)
- **39-CVE metrics (excluding synthetic)**: Spearman ρ reduces from 0.9488 to 0.9433 (<0.006 delta)
- **Recommendation**: Report both; emphasize minimal synthetic impact

---

## Data Quality Assessment

### Overall Provenance Evaluation

| Dimension | Assessment | Evidence | Concerns |
|-----------|------------|----------|----------|
| **Source Authenticity** | ✅ VERIFIED | NVD v2.0, FIRST EPSS, CISA KEV are authoritative sources | None; official APIs and catalogs used |
| **Data Completeness** | ⚠️ PARTIAL | 39/41 real CVEs fully sourced; 2 synthetic edge cases; 500-CVE 99.8% EPSS coverage | 1 CVE missing EPSS; environmental features (N,A) manually assigned |
| **Temporal Alignment** | ⚠️ DOCUMENTED | Snapshots dated 2026-10-13; frozen for reproducibility | EPSS/KEV drift over time; replication will show variance |
| **Reproducibility** | ✅ VERIFIED | Deterministic sampling (seed=42), locked snapshots, SHA-256 checksums | Requires specific snapshot dates; newer runs will differ |
| **Synthetic Disclosure** | ✅ VERIFIED | CVE-2024-999xx explicitly marked as synthetic | Minimal; positioned at tail |
| **Construct Validity** | ⚠️ FLAGGED | Reference labels derived from SSVC using same features as VRS | **CRITICAL**: Circular reasoning; reframe as "construct consistency" |
| **Generalizability** | ⚠️ LIMITED | 41 curated "hall of fame" CVEs; 500-corpus from 2023–2024 only | Selection bias; not representative of enterprise long-tail |

---

## Recommendations for Data Improvement

### Short-term (Pre-Resubmission)

1. **Explicit Temporal Metadata**
   - Add columns to CSV: `epss_snapshot_date`, `kev_snapshot_date`, `cvss_version`
   - Document: "EPSS dated 2026-10-13; KEV dated 2026-10-13; CVSS v3.1 base scores"

2. **Environmental Feature Justification**
   - Document basis for N and A assignments (e.g., "perimeter-facing service → N=1.0 per SSVC exposure criteria")
   - Provide mapping table: service type → (N, A) values

3. **Bootstrap Confidence Intervals**
   - Recompute all metrics with 95% CIs (1,000 resamples)
   - Report overlapping CIs to disclose statistical uncertainty

4. **Independent Label Validation**
   - Recruit 3 security experts to independently label 41 CVEs per SSVC rubric
   - Measure inter-rater agreement (κ)
   - Report both author and independent consensus

### Medium-term (Post-Acceptance Revision)

5. **Long-Tail Enterprise Validation**
   - Collect real SOC triage data (N≥100 CVEs) from enterprise partners
   - Re-evaluate VRS against *actual analyst triaging decisions*
   - Measure: correlation with live SOC priorities, time-to-remediation impact

6. **Temporal Stability Study**
   - Collect EPSS/KEV snapshots at monthly intervals (3–6 months)
   - Re-evaluate VRS on same benchmark with different snapshots
   - Measure: ranking stability (Kendall τ), metric sensitivity

7. **Vector Database Integration**
   - Migrate to embedding-based evidence retrieval (SentenceTransformer)
   - Evaluate: retrieval quality (precision, recall) vs. current dual-mode
   - Measure: scalability to 10K+ CVEs

---

## Data Governance and Ethics

### Dataset Availability

| Dataset | Access | License | Restrictions |
|---------|--------|---------|---|
| **41-CVE Benchmark** | Public (included in repo) | Apache 2.0 | None; can be redistributed |
| **500-CVE Corpus** | Public (included in repo) | Apache 2.0 | None; generated from public CVEProject |
| **EPSS Snapshots** | Cached locally; query FIRST API for fresh | FIRST terms of use | No commercial restrictions |
| **KEV Catalog** | Cached locally; query CISA feeds for fresh | Public domain (CISA) | None; freely available |
| **Manuscript** | Double-blind submission (anonymized) | IEEE/ICCI | Standard conference copyright |

### Ethics and Bias Disclosure

- ✅ **Selection Bias**: 41-CVE benchmark curated toward "critical exploits"; not representative of full CVE distribution
- ✅ **Construct Circularity**: Reference labels derived from SSVC using same features as VRS; reframe as alignment study
- ✅ **Information Asymmetry**: VRS has access to environmental context (N, A) unavailable to pure-vulnerability baselines
- ✅ **Retrospective Evaluation**: 500-CVE results are policy-concordance checks, not forward prediction
- ✅ **LLM Scope Limitation**: Guardrail evaluation limited to tested patterns; frontier model robustness unproven
- ✅ **Temporal Drift**: EPSS/KEV values change; reproduction will differ from frozen snapshots

---

## Summary Checklist

- [x] All benchmark sources documented (NVD, FIRST, CISA, synthetic)
- [x] Data collection dates and snapshots timestamped
- [x] Record composition (real vs. synthetic) disclosed
- [x] SHA-256 checksums provided for reproducibility
- [x] Data provenance chain documented
- [x] Known issues and limitations cataloged
- [x] Validation procedures specified
- [x] Confidence intervals and statistical uncertainty flagged
- [x] Ethical biases and selection constraints disclosed
- [x] Synthetic records explicitly marked and justified

**Next Steps**: 
1. Conduct independent label validation (Issue 2 from EXPERIMENT_PLAN.md)
2. Acquire historical EPSS/KEV snapshots for temporal stability study (Issue 9)
3. Create held-out 461-CVE test set for independence validation (Issue 10)
4. Extend to live SOC triage data for external validity (future work)
