# Phase 2 Manuscript Changelog — Paper 144

**Date:** 2026-11-27  
**Manuscript:** `revision/ICCI2026_revision/manuscript_revised.tex` (compiled to `manuscript_revised.pdf`, 5 pages)

---

## Section-by-Section Changes

1. **Abstract:** Replaced the 41-CVE-centric summary with the 7,927-CVE TEOB evaluation (`2026-07-01T00:00:00Z` cutoff, 90-day horizon, `11` KEV additions, `VRS NDCG@10 = 0.2083`, `AP = 0.1104`); explicitly stated that TEOB reduces VRS to `0.25C + 0.20E` and does not establish superiority over `CVSS+EPSS+KEV`; retained 41-CVE exploratory summary, guardrail rates (`9/25` TPR `0.36`, FPR `0.30`), `5/5` score integrity, and unmeasured capabilities.
2. **Introduction:** Clarified the distinction between severity, exploitation likelihood, observed exploitation, asset context, and policy rules; framed contributions around auditable system integration, score-integrity boundary, and outcome-based TEOB evaluation; updated RQ1–RQ3 to center TEOB.
3. **Related Work (`\label{sec:related}`):** Added **Table I (`tab:comparison`)** comparing CVSS v4.0, FIRST EPSS, CISA KEV, SSVC, CVSS+EPSS+KEV, and VRS across 7 dimensions.
4. **System Architecture (`\label{sec:arch}`):** Preserved exact implemented behavior of `scanner.py`, `cve_matcher.py` (including top-10 keyword fallback and unmeasured accuracy), `risk_engine.py`, `retrieval.py`, `vulture_chatbot.py` (Pydantic extra-field/priority behavior + KEV floor), and `evidence_validator.py`.
5. **Methodology (`\label{sec:method}`):** Added **Section IV.B (`\label{sec:teob_method}`)** and **Section IV.C** documenting TEOB cohort selection (`8,001 -> 7,927`), backward `cvehistory/2.0` CVSS reconstruction, exact-date EPSS (`2026-07-01`), 90-day KEV horizon, unrounded tie-aware expected metrics, 1,000-iteration paired stratified bootstrap (seed `20261127`), and the effective `0.25C + 0.20E` reduction. Relegated the 41-CVE benchmark to **Section IV.D** (Secondary Exploratory Benchmark).
6. **Results (`\label{sec:results}`):**
   - Added **Table II (`tab:teob_cohort`)**: TEOB cohort and historical feature coverage.
   - Added **Table III (`tab:teob_main`)**: TEOB tie-aware ranking results (`NDCG@10`, `P@10`, `R@10`, `R@50`, `R@100`, `AP`, `Top Tie`).
   - Added **Table IV (`tab:teob_boot`)**: Paired stratified bootstrap 95% CIs.
   - Consolidated 41-CVE exploratory baselines, context baselines, and ablations into **Table V (`tab:exploratory`)** alongside **Figure 1** (`fig1.pdf`) and 500-CVE concordance summary.
   - Retained **Table VI (`tab:guard`)** (48-inspected guardrail confusion matrix) and **Table VII (`tab:integrity`)** (5-payload score integrity), and explicit disclosure that explanation quality is unmeasured (`0` rows).
7. **Discussion, Threats to Validity, Conclusion:** Emphasized negative/limiting findings (no superiority over `CVSS+EPSS+KEV`, reduced `0.25C + 0.20E` evaluation, sparse `n=11` positives, `518` CVSS v4.0-only CVEs, weak prototype guardrail, unmeasured explanation quality and CPE matching accuracy).
8. **References:** Added `\cite{nvd2023}` in Section IV.D; all 15 citations resolved against `references_revised.bib`.

## Removed or Qualified Claims
- Removed any implication that TEOB was not yet performed (`FINAL_AUDIT.md` old status).
- Qualified VRS performance on TEOB as a reduced `0.25C + 0.20E` comparison with no statistically significant gain over `CVSS+EPSS+KEV`.
- Qualified guardrail as a weak prototype safeguard (`TPR=0.36`, `FPR=0.30`).
