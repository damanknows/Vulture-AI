# Response to Reviewers: Combined Letter

**Paper:** Vulture-AI: Context-Aware Vulnerability Prioritization with Guardrailed Retrieval-Augmented Generation
**Paper ID:** 144 — ICCI 2026
**Decision:** Accept After Modification

Dear Program Chairs and Reviewers,

Thank you for the review. We address all thirteen concerns recorded in the revision audit. Several of them could not be fully resolved within this revision, and for those we say so explicitly rather than claim a fix.

Two notes on scope before the point-by-point responses.

1. **Reviewer attribution.** The revision record groups the concerns by topic and severity but does not assign each to a named reviewer. The separate letters (`response_reviewer1.md`, `response_reviewer2.md`) therefore divide the concerns by topic and say so. If the program committee's original reviewer identities differ from this split, please use the combined letter and the concern numbers below.

2. **What we did not do.** We did not run new experiments that would change the reported numbers, and we did not alter the benchmark labels or the original results. Where an experiment is needed but not run, the response says so.

## Summary table

| # | Concern (short) | Status | Where addressed |
|---|---|---|---|
| 1 | Novelty vs SSVC, CVSS v4.0 | Partially addressed | Introduction, Related Work §3, Discussion |
| 2 | Circular author-generated labels | Partially addressed (disclosed; not resolved) | Methodology (benchmark), Threats |
| 3 | Baseline information asymmetry | Addressed with new baselines | Methodology (baselines), Results (Table III, context baselines), Threats |
| 4 | Unjustified VRS weights | Partially addressed | Methodology (weights), Results (weight sensitivity), Discussion |
| 5 | Guardrail evaluation scope | Addressed with a new corpus; limits remain | Results (guardrail, Table VI), Threats |
| 6 | Unclear RAG retrieval | Addressed (description corrected) | System Architecture |
| 7 | Explanation quality | Not addressed (not measured) | Results (explanation quality), Threats |
| 8 | Small benchmark; no intervals or tests | Addressed (intervals); tests limited | Results (Table II, bootstrap), Methodology |
| 9 | Temporal leakage | Addressed (disclosed); historical evaluation not done | Experimental Setup (temporal), Threats |
| 10 | 500-CVE independence | Addressed (disclosed) | Results (KEV concordance), Threats |
| 11 | Actionable metrics | Partially addressed (computed; non-discriminative) | Methodology (metrics), Results |
| 12 | Missing and incorrect references | Addressed for the verified set; some remain unverified | References, Related Work |
| 13 | CPE/Nmap matching evaluation | Not addressed (no labelled evaluation) | System Architecture, Threats |

Full detail is in the reviewer letters, the change log, and the unresolved-concerns list.
