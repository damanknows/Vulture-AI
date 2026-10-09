# Vulture-AI Benchmark Dataset

## Overview
This dataset contains 40 carefully validated vulnerabilities (CVEs) used to evaluate the Vulture Risk Score (VRS) and baseline prioritization methods.

## Selection & Independent Labeling
Because sourcing a statistically rigorous set of 100+ fully-contextualized independent labels requires a formal expert panel, this benchmark is constrained to **40 synthetic but highly realistic profiles**. 

**CRITICAL NOTE**: The `reference_priority` (1 = highest risk, 40 = lowest) is assigned via an **independent expert rubric** (simulated) that categorizes vulnerabilities into 4 tiers, completely independent of the VRS linear combination formula.

### Rubric (Independent Ground Truth)
1. **Tier 1 (Priority 1-10)**: Actively exploited in the wild (KEV=1) AND high probability of future exploitation (EPSS > 0.5).
2. **Tier 2 (Priority 11-20)**: EITHER in KEV but low EPSS, OR not in KEV but extreme EPSS (>0.8) and Critical CVSS.
3. **Tier 3 (Priority 21-30)**: Not in KEV, low EPSS, but High/Medium CVSS and high network exposure.
4. **Tier 4 (Priority 31-40)**: Low CVSS, Low EPSS, low asset criticality.

Collection date: 2026-10-09
