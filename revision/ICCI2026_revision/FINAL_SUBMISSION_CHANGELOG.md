# Final Submission Changelog — Vulture-AI (ICCI 2026)

**Date:** 2026-11-27  
**File Modified:** `revision/ICCI2026_revision/manuscript_revised.tex` (backup saved to `manuscript_revised.pre_final_audit.tex`)

| Section | Change Made | Reason |
|---|---|---|
| **Abstract** | Disclosed EPSS calendar-day granularity (`date=2026-06-30` omits late-June-30 CVEs) and non-verified intraday availability; labeled bootstrap gains as *unadjusted* and *nominally significant*. | Sections 3.3 & 4 (EPSS temporal availability & nominal significance). |
| **§I (RQ1)** | Changed *"under strict point-in-time feature reconstruction"* to *"under pre-cutoff NVD feature reconstruction and day-level EPSS"*. | Section 3.3 (avoid claiming strict point-in-time availability for EPSS). |
| **§II (Table I)** | Changed VRS Temporal Info from *"Point-in-time EPSS + KEV"* to *"Day-level EPSS + KEV"*. | Section 3.3 (consistency with day-level EPSS granularity). |
| **§IV.C (EPSS & KEV)** | Removed the unsupported 6-day leakage-elimination claim; documented `date=2026-06-30` incompleteness (8/10 sampled June 30 CVEs and both June 30 positives missing); stated TEOB is not a fully verified point-in-time evaluation for EPSS. | Section 3.3 (live FIRST API check on `date=2026-06-30`). |
| **§IV.D (Bootstrap)** | Explicitly stated that CIs are unadjusted for multiple comparisons and represent exploratory *nominal* 95% significance only. | Section 4 (multiple-comparison caveat). |
| **§V.A (Results)** | Changed *"statistically significant gains"* to *"nominally significant gains (unadjusted across multiple metrics and baselines)"*. | Section 4 (nominal significance terminology). |
| **§V.B (Exploratory)** | Distinguished `P@10 (Act)` / `R@10 (Act)` (grade `= 3`, denominators 10 and 15) from `AP@10` / `AR@10` (Actionable Precision/Recall@10, grade `>= 2`, denominators 10 and 27); corrected *"places all Act/Attend items in the top 10"* to *"fills all 10 top slots with Act/Attend items (10 of 27, AR@10 = 0.3704)"*. | Section 7 (metric terminology accuracy). |
| **§VII (Limitations)** | Merged/expanded limitations to cover: (1) EPSS day-level granularity & non-verified point-in-time status, (2) unadjusted CIs & exploratory nominal significance with `P=11`, and (3) unequal missing-CVSS feature availability across the 1,244 missing-CVSS records. | Sections 3.2, 3.3, and 4. |
| **§VIII (Conclusion)** | Updated significance wording to *"nominally significant ... unadjusted for multiple comparisons"* and noted *"with calendar-day EPSS granularity"*. | Sections 3.3 & 4. |
