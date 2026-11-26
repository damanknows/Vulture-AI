# Vulture-AI Phase 2: Feature Normalization Audit
## Documentation of Input Schemas, Ranges, and Consistency

**Date:** 2026-11-26  
**Purpose:** Comprehensive audit of all feature value normalization, missing-data policies, and input consistency across Phase 2 baseline methods.  
**Status:** Phase 2 Specification Document (Preservation & Transparency)

---

## 1. Executive Summary

This document audits the feature normalization scheme, missing-data handling policies, and input record consistency for all Phase 2 baseline methods and weight sensitivity experiments.

**Key findings:**
- All features are pre-normalized to bounded [0, 1] ranges in the data schema
- Missing-value defaults are symmetric (0.5) for context features, zero for indicators
- All baseline methods receive identical finding records from the benchmark CSV
- Deterministic ranking is enforced through tie-breaking rules

---

## 2. Feature Schemas and Normalization

### 2.1 CVSS Severity (C)

**Source:** NIST National Vulnerability Database (NVD), CVSS v3.1 base score  
**Raw Range:** [0.0, 10.0]  
**VRS Normalization:** `C = cvss_score / 10.0` → [0.0, 1.0]  
**Description:** Base severity of the vulnerability, unmodified by environmental factors.

**Benchmark Examples:**
- Minimum: CVE-2024-99991 (synthetic edge case, missing CVSS)
- Maximum: CVE-2021-44228 (Log4Shell, CVSS 10.0) → C = 1.0
- Typical: CVE-2023-34362 (MOVEit RCE, CVSS 9.8) → C = 0.98

**Missing Value Policy:**
- Missing CVSS: VRS score is `None` (unavailable)
- Reason: CVSS is mandatory for all scorable findings; missing CVSS indicates incomplete intel
- Fallback baselines: CVSS-only, CVSS+EPSS+KEV all return `None` if CVSS missing

---

### 2.2 EPSS Exploitation Probability (E)

**Source:** FIRST.org Exploit Prediction Scoring System (EPSS) API  
**Raw Range:** [0.0, 1.0] (probability)  
**VRS Usage:** `E = epss_probability` (direct, no rescaling)  
**Description:** Probability that a vulnerability will be exploited in the wild within 30 days.

**Benchmark Examples:**
- Minimum: CVE-2015-3306 (OpenSSH, EPSS 0.000)
- Maximum: CVE-2021-44228 (Log4Shell, EPSS 0.986)
- Typical high: CVE-2023-34362 (EPSS 0.976)

**Missing Value Policy:**
- Missing EPSS in VRS: Default to `E = 0.0`
- Reason: EPSS reflects active exploitation, absence implies no live threat data
- Flagged: Finding marked with `uncertainties = ["Treated missing EPSS as default policy value"]`
- Edge case: CVE-2024-99992 (synthetic, missing EPSS) → E = 0.0

---

### 2.3 CISA KEV Status (K)

**Source:** CISA Known Exploited Vulnerabilities (KEV) Catalog  
**Raw Format:** Boolean (true if actively exploited, false otherwise)  
**VRS Normalization:** `K = 1.0 if kev_listed else 0.0` → {0.0, 1.0}  
**Description:** Binary indicator of active exploitation in confirmed attacks.

**Benchmark Examples:**
- KEV=1: CVE-2021-44228, CVE-2023-34362, CVE-2024-1709, CVE-2023-20198, ... (15 items)
- KEV=0: CVE-2015-3306, CVE-2019-15846, CVE-2020-0601, ... (26 items)

**Missing Value Policy:**
- Missing KEV: Default to `K = 0.0`
- Reason: Absence from KEV does not imply no exploitation; conservative default is to assume not listed
- Bucket override: If `K = 1.0` and `w_K > 0`, finding is promoted to "urgent" bucket

---

### 2.4 Network Exposure (N)

**Source:** Internal asset topology / network reachability assessment  
**Raw Range:** [0.0, 1.0] (normalized score)  
**VRS Usage:** `N = network_exposure` (direct, no rescaling)  
**Description:** Fraction of asset surface reachable from external networks (0=isolated, 1=fully exposed).

**Benchmark Construction:** Manually assigned to match CISA SSVC decision categories:
- Act tier: N ∈ [0.8, 1.0] (network-exposed)
- Attend tier: N ∈ [0.3, 0.8] (partially exposed)
- Track tier: N ∈ [0.2, 0.7] (limited exposure)
- Defer tier: N ∈ [0.2, 0.6] (minimal exposure)

**Missing Value Policy:**
- Missing Exposure in VRS: Default to `N = 0.5`
- Reason: Neutral midpoint; absence suggests unknown exposure (not zero)
- Flagged: Finding marked with `uncertainties = ["Treated missing network_exposure as default policy value"]`

**Note:** See AUDIT_REPORT.md [CRIT-1] for construct circularity discussion.

---

### 2.5 Asset Criticality (A)

**Source:** Internal business asset classification  
**Raw Range:** [0.0, 1.0] (normalized score)  
**VRS Usage:** `A = asset_criticality` (direct, no rescaling)  
**Description:** Business importance / impact if compromised (0=non-critical, 1=critical).

**Benchmark Construction:** Manually assigned to match CISA SSVC decision categories:
- Act tier: A ∈ [0.9, 1.0] (critical)
- Attend tier: A ∈ [0.6, 0.8] (important)
- Track tier: A ∈ [0.5, 0.7] (moderate)
- Defer tier: A ∈ [0.2, 0.5] (low criticality)

**Missing Value Policy:**
- Missing Criticality in VRS: Default to `A = 0.5`
- Reason: Neutral midpoint; absence suggests unknown importance (not zero)
- Flagged: Finding marked with `uncertainties = ["Treated missing asset_criticality as default policy value"]`

**Note:** See AUDIT_REPORT.md [CRIT-1] for construct circularity discussion.

---

## 3. Missing Data Policies

### 3.1 Policy Summary Table

| Feature | Missing Policy | Default Value | VRS Behavior | Other Baselines |
|---------|---|---|---|---|
| CVSS | Reject | — | vrs = None | Reject (None) |
| EPSS | Use default | 0.0 | E = 0.0, flagged | E = 0.0 |
| KEV | Use default | 0.0 | K = 0.0 | K = 0.0 |
| Exposure | Use default | 0.5 | N = 0.5, flagged | N = 0.5 |
| Criticality | Use default | 0.5 | A = 0.5, flagged | A = 0.5 |

### 3.2 Rationale for Defaults

- **CVSS=None → reject:** CVSS is authoritative base severity; absence implies incomplete record
- **EPSS=0.0:** No active exploitation data; conservative null indicator
- **KEV=0.0:** Absence from KEV ≠ safe; conservative null indicator
- **Exposure=0.5:** Unknown reachability; neutral midpoint, not zero (would be false negation)
- **Criticality=0.5:** Unknown asset value; neutral midpoint, not zero (would be false negation)

### 3.3 Data Completeness Tracking

Each VRS result includes:
```json
{
  "data_completeness": "complete|partial",
  "missing_data": ["field1", "field2", ...],
  "uncertainties": ["reason1", "reason2", ...]
}
```

**Examples:**
- Complete: All 5 fields present
- Partial: One or more of {EPSS, Exposure, Criticality} missing
- Unavailable: CVSS missing (vrs = None)

---

## 4. Input Record Consistency Across All Methods

### 4.1 Benchmark Data Source

**File:** `data/benchmark/cves.csv`  
**Records:** 41 CVEs (39 real, 2 synthetic edge cases)  
**Hash:** `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e` (SHA-256)  
**Format:** CSV with schema:
```
cve_id, cvss, epss, kev, exposure, asset_criticality,
reference_priority, independent_label, source_timestamp, 
source_reference, description
```

### 4.2 Loading and Validation

**Function:** `experiments/run_baselines.py::load_benchmark()`  
**Process:**
1. Read CSV into DictReader
2. For each row:
   - Parse numeric fields with None for missing values
   - Construct finding record with standard schema:
     ```python
     {
       "finding": {
         "target": "benchmark_host",
         "port": 443,
         "service": "https",
         "network_exposure": exposure_val,
         "asset_criticality": criticality_val,
       },
       "cve_matches": [
         {
           "cve_id": cve_id,
           "cvss_score": cvss_val,
           "epss_probability": epss_val,
           "kev_listed": kev_val == 1
         }
       ]
     }
     ```

### 4.3 Input Consistency Verification

**All baseline methods receive:**
- Same 41 CVE records
- Identical field values
- Same missing-value semantics

**Verification commands:**
```bash
# Load once
findings, ref_ranking, relevance_dict = load_benchmark()

# All methods use same `findings` list
compute_vrs(findings[i])
compute_cvss_only(findings[i])
compute_epss_only(findings[i])
compute_kev_first(findings[i])
compute_cvss_epss_kev(findings[i])
compute_baseline_epss_exposure(findings[i])
compute_baseline_exposure_criticality(findings[i])
compute_baseline_context_enhanced_cvss(findings[i])
compute_baseline_epss_context(findings[i])
```

---

## 5. Context-Aware Baseline Formulas

All context-aware baselines use identical normalization and missing-data handling as VRS.

### 5.1 Baseline 1: EPSS × Exposure

```
score = E × N
where E ∈ [0, 1], N ∈ [0, 1]
Result: [0, 1]

Interpretation: Exploitation probability amplified by reachability
```

**Missing Data:**
- Missing EPSS: E = 0.0
- Missing Exposure: N = 0.5

### 5.2 Baseline 2: Exposure × Asset Criticality

```
score = N × A
where N ∈ [0, 1], A ∈ [0, 1]
Result: [0, 1]

Interpretation: Reachability amplified by business importance
```

**Missing Data:**
- Missing Exposure: N = 0.5
- Missing Criticality: A = 0.5

### 5.3 Baseline 3: Context-Enhanced CVSS

```
score = C × (0.5 + 0.5 × N) × (0.5 + 0.5 × A)
where C ∈ [0, 1], N ∈ [0, 1], A ∈ [0, 1]
Result: [0, 1]

Context factors: [0.5, 1.0] (minimum context = 0.5, maximum = 1.0)

Interpretation: Base CVSS severity amplified by environmental context
```

**Missing Data:**
- Missing CVSS: score = None (cannot compute)
- Missing Exposure: N = 0.5
- Missing Criticality: A = 0.5

### 5.4 Baseline 4: EPSS × Context

```
score = E × (0.5 + 0.5 × N) × (0.5 + 0.5 × A)
where E ∈ [0, 1], N ∈ [0, 1], A ∈ [0, 1]
Result: [0, 1]

Interpretation: Exploitation probability amplified by environmental context
```

**Missing Data:**
- Missing EPSS: E = 0.0
- Missing Exposure: N = 0.5
- Missing Criticality: A = 0.5

---

## 6. Weight Configuration Specifications

All weights are nonnegative and sum to 1.0 (tolerance: 1e-6).

### 6.1 Original (VRS v1)

```json
{
  "w_C": 0.25,
  "w_E": 0.20,
  "w_K": 0.20,
  "w_N": 0.20,
  "w_A": 0.15
}
```

**Production weights:** Exploratory Phase 0 configuration.

### 6.2 Equal

```json
{
  "w_C": 0.20,
  "w_E": 0.20,
  "w_K": 0.20,
  "w_N": 0.20,
  "w_A": 0.20
}
```

**Purpose:** Uniform feature importance.

### 6.3 CVSS-Heavy

```json
{
  "w_C": 0.40,
  "w_E": 0.15,
  "w_K": 0.15,
  "w_N": 0.15,
  "w_A": 0.15
}
```

**Purpose:** Prioritize base severity.

### 6.4 EPSS-Heavy

```json
{
  "w_C": 0.15,
  "w_E": 0.30,
  "w_K": 0.25,
  "w_N": 0.15,
  "w_A": 0.15
}
```

**Purpose:** Prioritize active exploitation probability.

### 6.5 Context-Heavy

```json
{
  "w_C": 0.15,
  "w_E": 0.15,
  "w_K": 0.20,
  "w_N": 0.25,
  "w_A": 0.25
}
```

**Purpose:** Prioritize environmental context (exposure + criticality).

### 6.6 Exposure-Heavy

```json
{
  "w_C": 0.15,
  "w_E": 0.15,
  "w_K": 0.15,
  "w_N": 0.40,
  "w_A": 0.15
}
```

**Purpose:** Prioritize network reachability.

---

## 7. VRS Formula with Normalization

**Complete specification:**

```
VRS = 100 * (w_C * C + w_E * E + w_K * K + w_N * N + w_A * A)

Where:
- C = cvss_score / 10.0  (CVSS normalized to [0,1])
- E = epss_probability   (already [0,1])
- K = 1.0 if kev_listed else 0.0  (binary)
- N = network_exposure   (already [0,1])
- A = asset_criticality  (already [0,1])

VRS ∈ [0, 100]

Bucket override:
- If K = 1.0 and w_K > 0: bucket = "urgent"
- Else: bucket = "standard"
- If C is None: bucket = "unavailable", vrs = None

Tie-breaking (rank_findings):
1. Bucket order: "urgent" < "standard" < "unavailable"
2. VRS score (descending)
3. Primary CVE ID (alphabetic, ascending)
```

---

## 8. Determinism and Reproducibility

### 8.1 Deterministic Scoring

All scoring functions are:
- Pure functions (no random state, no side effects)
- Idempotent (same inputs → same outputs)
- Recorded with timestamps and configuration hashes

**Verification:**
```python
result1 = compute_vrs(finding, weights=w)
result2 = compute_vrs(finding, weights=w)
assert result1["vrs"] == result2["vrs"]
```

### 8.2 Deterministic Ranking

Ranking uses explicit tie-breaking rules (never random):
1. Bucket order (predictable)
2. Score order (descending, deterministic)
3. CVE ID order (ascending, deterministic)

**Verification:**
```python
ranking1 = rank_findings(findings, weights=w)
ranking2 = rank_findings(findings, weights=w)
cves1 = [r["primary_cve"] for r in ranking1]
cves2 = [r["primary_cve"] for r in ranking2]
assert cves1 == cves2
```

### 8.3 Configuration Hashing

Each experiment records:
- Benchmark SHA-256 hash
- Weight configuration (JSON serialized)
- Run timestamp (UTC ISO-8601)
- Code commit (if available via git)

---

## 9. Data Clipping and Bounds Enforcement

### 9.1 Input Validation

**CVSS:** Validated to [0.0, 10.0] by NVD; rejected if out of bounds
**EPSS:** Validated to [0.0, 1.0] by FIRST.org API; rejected if out of bounds
**KEV:** Boolean; no bounds
**Exposure:** Expected [0.0, 1.0]; no clipping applied
**Criticality:** Expected [0.0, 1.0]; no clipping applied

### 9.2 Implicit Clipping

No implicit clipping or rescaling is applied. If feature values are outside expected bounds, an error is raised (fail-fast).

---

## 10. Audit Summary

| Aspect | Status | Evidence |
|--------|--------|----------|
| CVSS normalization | Documented | C = cvss / 10.0 |
| EPSS scale | Documented | E = epss (direct) |
| KEV representation | Documented | K ∈ {0, 1} |
| Exposure representation | Documented | N ∈ [0, 1] |
| Criticality representation | Documented | A ∈ [0, 1] |
| Missing CVSS policy | Defined | vrs = None |
| Missing EPSS policy | Defined | E = 0.0, flagged |
| Missing Exposure policy | Defined | N = 0.5, flagged |
| Missing Criticality policy | Defined | A = 0.5, flagged |
| Missing KEV policy | Defined | K = 0.0 |
| Input consistency | Verified | Same benchmark for all methods |
| Clipping behavior | None applied | Fail-fast on bounds violations |
| Determinism | Verified | Pure functions, explicit tie-breaking |
| Reproducibility | Enabled | Config hashing, timestamps |

---

## 11. References

- **CVSS v3.1:** https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- **EPSS:** https://www.first.org/epss/
- **CISA KEV:** https://www.cisa.gov/known-exploited-vulnerabilities
- **CISA SSVC:** https://github.com/CISA-vultures/ssvc/
- **Vulture-AI Code:** risk_engine.py, context_baselines.py, weight_sensitivity.py
- **Vulture-AI Audit:** AUDIT_REPORT.md (Phase 0 findings)

---

**Document Version:** 1.0  
**Last Updated:** 2026-11-26  
**Next Review:** After Phase 2 experiments complete
