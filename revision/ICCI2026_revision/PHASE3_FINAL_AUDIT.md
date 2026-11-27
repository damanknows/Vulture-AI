# Phase 3 — Final Technical Consistency & Audit Report (Paper 144)

**Date:** 2026-11-27  
**Branch:** `research-v2`  
**Manuscript:** `revision/ICCI2026_revision/manuscript_revised.tex` / `manuscript_revised.pdf`

---

## 1. Missing-CVSS Audit Findings
- All 5 TEOB methods rank the exact same `7,927` CVEs (`P = 11` positives); no method excludes missing-CVSS records.
- `2` of the `11` positive KEV additions lack historical CVSS v3.x at cutoff (`CVE-2026-56290` with `EPSS = 0.00276`; `CVE-2026-8452` with `EPSS = 0.00403`).
- `CVSS-only`, `CVSS+EPSS+KEV`, and `VRS` (`unavailable` bucket) assign `None` (`-inf`) to all `1,244` missing-CVSS records, forming a `1,244`-record bottom tied block `(1244, 2, -inf)`.
- `KEV-first` assigns `0.0` to missing CVSS, merging the `1,244` missing-CVSS records with the `4` records having `CVSS = 0.0` into a `1,248`-record bottom tied block `(1248, 2, 0.0)`.
- `EPSS-only` scores all `7,927` records using their `2026-07-01` EPSS probabilities.
- **Validity:** Under `tie_aware_*` analytical expectations and paired stratified bootstrap (`seed = 20261127`), all reported metrics and 95% CIs remain valid. Now explicitly documented in §IV.C.

## 2. EPSS Temporal Availability Findings
- `date=2026-07-01` in FIRST's EPSS API is an archived daily UTC calendar-date snapshot (retrieved retrospectively on `2026-11-26T21:37:33Z`).
- FIRST typically generates daily EPSS scores around `13:30 UTC` with day-level granularity only (`YYYY-MM-DD`, no intraday timestamp). Thus, strict `2026-07-01T00:00:00Z` midnight availability **cannot be established** for EPSS.
- Because all `11` positive KEV additions occurred between `2026-07-07` and `2026-09-21` (at least 6 days later) and pre-cutoff KEVs (`<= 2026-07-01`) were excluded, no future KEV outcome leaks into EPSS. Clarified in §IV.C, `PROTOCOL.md`, and `PROVENANCE.md`.

## 3. Combined Baseline Formula & Provenance
- Verified in `risk_engine.py:174-187` and `experiments/evaluate_temporal.py:270-278`:
  $$S_{\text{comb}} = 100 \times \left(\tfrac{1}{3} C + \tfrac{1}{3} E + \tfrac{1}{3} K\right)$$
  where $C = \text{CVSS}/10$, $E \in [0,1]$ (`0.0` if EPSS missing), $K \in \{0,1\}$, and `None` if CVSS is missing.
- Study-defined composite baseline (not an existing published method); explicitly labeled `study-defined` across Table I, §IV.B, Abstract, Discussion, and Conclusion.

## 4. Circularity, LLM Constraint, & 41-CVE v1/v2 Framing Changes
- **Circularity:** Narrowed to *"avoid the specific label circularity of our author-assigned SSVC-inspired benchmark and reduce temporal leakage"*.
- **LLM constraint wording:** Replaced *"constrained LLM"* with accurate description of regex screening, evidence checks, and deterministic post-LLM enforcement of score and KEV priority floor.
- **Abstract:** Removed exploratory 41-CVE v1 headline numbers (`NDCG@10 = 1.0`, `Spearman \rho = 0.9488`).
- **v1/v2 consistency:** Distinguished v1 (`\rho=0.9488`), corrected v2 (`\rho=0.9317` vs `EPSS×Context` `0.9334`, diff `-0.002 [-0.070, 0.059]`), and TEOB (`0.25C + 0.20E`).

## 5. SSVC Provenance & Assumptions
- Vendored, cited 36-leaf adaptation of the CISA/SEI SSVC v2.0 decision tree (`Spring et al., CMU/SEI-2019-TR-005`; `CISA SSVC v2.0`) in `experiments/revision/baselines/ssvc_baseline.py` (not an unmodified official package).
- Uniformly maps all 41 records: `Exploitation` (`active` if KEV=1, `poc` if `EPSS >= 0.1`, else `none`), `Technical Impact` (`total` if `CVSS >= 9.0`), `Mission Prevalence` (from $A$), uniform defaults `Automatable=yes` and `Public Well-being=minimal`, and `Act=3, Attend=2, Track*=Track=1` with ascending CVE ID tie-breaking.

## 6. Claim-to-Evidence Audit & Evaluation Rerun Status
- **Evaluation reruns required:** None. All underlying TEOB (`teob_evaluation.json`), 41-CVE (`metrics.json`, `paired_corrected_v2.csv`, `results_ssvc.json`, `results_cvss_env.json`, `ablation.json`), sensitivity (`full_rank_results.json`), guardrail (`guardrail/metrics.json`, `score_integrity.json`), and CPE (`cpe_matching_results.json`) metrics were verified intact and unchanged.
- **Automated table audit (`manuscript_audit.py`):** **114 / 114** cells matched JSON sources, **0 failed**, **0 metrics > 1.0**.

## 7. Issues Fixed vs. Remaining Limitations
- **Fixed:** Missing-CVSS documentation, EPSS daily granularity disclosure, `CVSS+EPSS+KEV` equation and study-defined provenance, Abstract 41-CVE removal, narrowed circularity/LLM wording, anonymous author block cleanup, `TODO` removal, SSVC adaptation disclosure, and long URL wrapping.
- **Remaining unmeasured / structural limitations (`NOT_AVAILABLE` / `PENDING`):** Semantic explanation quality (HTTP 402 / no local Ollama; human spot-check `PENDING`), independent human rater agreement (`PENDING`), true CVSS v4.0 environmental scoring (`cves.csv` lacks v4.0 vectors; TEOB lacks pre-cutoff v4.0 history/context), live-network scanner-to-CVE recall, and sparse TEOB positive count (`P = 11`).

## 8. Final Scientific Validity Assessment
The revised manuscript is **scientifically defensible for ICCI 2026**: every number traces to a reproducible artifact, all statistical uncertainties (including null results vs `CVSS+EPSS+KEV`) are transparently reported, and all unmeasured capabilities are explicitly disclosed without overclaiming.
