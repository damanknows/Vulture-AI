# Vulture-AI Independent Annotation Protocol v1.0

## Purpose

This protocol guides independent security experts in assigning priority tiers (labels) to Common Vulnerabilities and Exposures (CVEs) **without access to VRS scores, VRS rankings, or other computational results**.

The goal is to validate that VRS produces labels aligned with expert judgment and established triage frameworks (CISA SSVC).

---

## Annotator Requirements

- **Background**: Security operations or vulnerability management professional
- **Experience**: Minimum 2 years SOC/security operations experience
- **Independence**: Must work independently; no coordination with other annotators
- **Disclosure**: Must disclose any conflicts of interest (employment, funding, consulting relationships with VRS authors)

---

## Information Available to Annotators

### Provided Data Per CVE

For each CVE, annotators will receive:

1. **CVE ID** (e.g., CVE-2021-44228)
2. **CVSS v3.1 Base Score** (severity metric from NIST NVD)
3. **EPSS Probability** (30-day exploitation likelihood from FIRST.org)
4. **CISA KEV Status** (binary: "Yes" if actively exploited in federal reporting, "No" otherwise)
5. **Brief Description** (from NVD)

### Explicitly NOT Provided

- VRS scores or VRS rankings
- Comparison to other CVEs
- Author-generated reference labels
- VRS components (N, A) or any context features
- Results from prior annotators

---

## Label Definitions

Annotators assign one of four ordinal priority tiers:

### **Act** (Urgent: Remediate Immediately)

**Criteria:**
- Confirmed active exploitation in-the-wild (CISA KEV = Yes)
  **AND**
- Either:
  - CVSS ≥ 9.0 (Critical impact) OR
  - EPSS ≥ 0.90 (Likely exploited within 30 days)
- Affects exposed, high-value systems

**Examples:**
- Log4j RCE (CVE-2021-44228, CVSS 10.0, KEV=Yes, EPSS=0.99999)
- MOVEit SQLi (CVE-2023-34362, CVSS 9.8, KEV=Yes, EPSS=0.99)

### **Attend** (High Priority: Remediate This Week)

**Criteria:**
- Either:
  - KEV listed with any CVSS ≥ 7.0
  - CVSS ≥ 9.0 without KEV (new zero-day)
  - EPSS ≥ 0.80 with CVSS ≥ 8.0
- OR
- Public weaponized exploit available with CVSS ≥ 8.0

**Examples:**
- Follina (CVE-2022-30190, CVSS 7.8, KEV=Yes, EPSS=0.99)
- XZ Utils backdoor (CVE-2024-3094, CVSS 10.0, KEV=No but new zero-day, EPSS=0.90)

### **Track** (Standard: Routine Patch Cycle)

**Criteria:**
- CVSS ≥ 7.0
- EPSS < 0.3 OR no public exploit evidence
- KEV = No
- No indication of mass exploitation or zero-day

**Examples:**
- PostgreSQL privilege escalation (CVE-2022-1552, CVSS 8.8, KEV=No, EPSS=0.16)
- Redis integer overflow (CVE-2021-32625, CVSS 7.8, KEV=No, EPSS=0.04)

### **Defer** (Low Priority: Assess for Applicability)

**Criteria:**
- CVSS < 7.0 OR
- Requires specialized conditions (e.g., local access, authentication, client-side)
- EPSS < 0.1
- KEV = No

**Examples:**
- OpenSSH user enumeration (CVE-2018-15473, CVSS 5.3, KEV=No, EPSS=0.99 ⚠️ but low impact)
- Curl cookie injection (CVE-2023-38546, CVSS 3.7, KEV=No, EPSS=0.06)

---

## Annotation Procedure

### Step 1: Review CVE Information

For each CVE:
1. Read the brief description
2. Note CVSS base score (severity)
3. Note EPSS probability (likelihood of exploitation)
4. Note KEV status (confirmed in-the-wild exploitation)

### Step 2: Independent Assessment

**WITHOUT** looking at any other CVE, any VRS output, or any reference labels:

1. Determine which category BEST describes this CVE's urgency
2. Consider: If this vulnerability existed in YOUR organization's environment, what triage tier would this belong to?
3. Document any uncertainty or mitigating factors

### Step 3: Assign Label

Select ONE label: **Act**, **Attend**, **Track**, or **Defer**

### Step 4: Confidence Rating (Optional)

Rate your confidence in this label:
- **1.0** = Very confident; clear match to category
- **0.75** = Confident; minor ambiguity
- **0.5** = Moderate confidence; significant ambiguity
- **0.25** = Low confidence; could reasonably belong to adjacent category

### Step 5: Rationale (Optional)

Briefly note any reasoning for edge cases:
- "CVSS is 7.8 (low for Act threshold) but KEV=Yes and EPSS=0.99 suggest immediate exploitation"
- "CVSS=9.8 but EPSS=0.04 suggests PoC not widely available; Attend tier"

---

## Special Cases

### Missing EPSS

If EPSS is unavailable, weight CVSS + KEV status more heavily:
- If KEV=Yes: Likely Act or Attend
- If KEV=No: Defer to CVSS and description

### Synthetic CVEs

Two CVEs in the benchmark are **synthetic edge cases** (IDs ending in 99991, 99992):
- **CVE-2024-99991**: Has no CVSS (missing data test case)
  - Treat as Track/Defer (cannot assess impact)
- **CVE-2024-99992**: Has no EPSS (missing data test case)
  - Assess using CVSS alone; consider as Track

---

## Adjudication (If Needed)

If multiple annotators disagree:

1. **Disagreement within one tier** (e.g., Act vs. Attend):
   - Major security concern; prioritize higher tier
2. **Disagreement across two tiers** (e.g., Act vs. Track):
   - Requires discussion; likely indicates edge case
3. **Unresolvable disagreement**:
   - Flag as tie; mark for expert review

Adjudication will follow majority-vote with severity-based tie-breaking (higher tier wins).

---

## Ethical and Independence Constraints

### DO:
- ✓ Assess each CVE independently
- ✓ Document uncertainty honestly
- ✓ Use provided data (CVSS, EPSS, KEV, description)
- ✓ Disclose conflicts of interest
- ✓ Ask clarifying questions about *the protocol*, not specific CVEs

### DO NOT:
- ✗ Coordinate with other annotators or look at their labels
- ✗ Access VRS scores, VRS rankings, or any computational results
- ✗ Look at author-generated reference labels
- ✗ Research the CVEs online (beyond provided data)
- ✗ Adjust labels to match expectations or prior work
- ✗ Make labels match a predetermined pattern

---

## Submission Format

Submit annotations as a JSON file following `annotation_schema.py`:

```json
{
  "schema_version": "1.0",
  "provenance_note": "These annotations are INDEPENDENT of VRS scores...",
  "annotations": [
    {
      "cve_id": "CVE-2021-44228",
      "annotator_id": "RATER_01",
      "label": "Act",
      "confidence": 1.0,
      "rationale": "KEV-listed, CVSS 10.0, EPSS 0.99999",
      "annotation_timestamp": "2026-11-26T15:00:00+00:00",
      "protocol_version": "1.0"
    }
  ]
}
```

---

## Validation Checks

Your annotations will be validated for:
- ✓ Valid CVE ID format (CVE-YYYY-NNNNN+)
- ✓ Allowed labels only (Act, Attend, Track, Defer)
- ✓ Confidence in [0.0, 1.0] if provided
- ✓ No duplicate annotations per CVE per annotator
- ✓ No VRS scores embedded in rationale
- ✓ Proper ISO-8601 timestamps

---

## Support and Questions

If you have questions about:
- **The protocol or categories**: Ask before beginning annotation
- **A specific CVE**: Consult only the provided description; ask for clarification if data is missing
- **Technical issues**: Contact the research team

---

## References

- CISA SSVC: Spring et al. (2020). Prioritizing Vulnerability Response: A Stakeholder-Specific Vulnerability Categorization (SSVC). https://certcc.github.io/ssvc/
- CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
- FIRST EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

**Protocol Version:** 1.0  
**Effective Date:** 2026-11-26  
**Next Review:** After first annotation round
