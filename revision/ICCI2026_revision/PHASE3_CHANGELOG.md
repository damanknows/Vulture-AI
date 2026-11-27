# Phase 3 — Manuscript Changelog (Paper 144)

**Date:** 2026-11-27  
**File Modified:** `revision/ICCI2026_revision/manuscript_revised.tex`

| Section | Previous Wording / Problem | New Wording / Change | Reason | Evidence Source |
|---|---|---|---|---|
| **Author Block** | Included `Contact: contact@anonymous.institution`. | Removed placeholder contact line. | Double-blind anonymity cleanup (Phase 5). | `manuscript_revised.tex` |
| **Abstract** | Included exploratory 41-CVE v1 numbers (`NDCG@10=1.0`, `\rho=0.9488`); claimed *"without author-assigned label circularity or temporal leakage"*. | Removed 41-CVE v1 numbers; narrowed circularity wording; clarified daily EPSS `date=2026-07-01` and `study-defined` `CVSS+EPSS+KEV`. | Prioritize TEOB and avoid circular headline claims (Phases 2, 3, 4.1, 4.2). | `teob_evaluation.json`, `epss_2026-07-01.json` |
| **§I (Introduction)** | Said *"constrained LLM"*; claimed *"avoiding the circularity"*. | Replaced with accurate regex screening + evidence checks + deterministic score/KEV-floor enforcement; narrowed circularity wording. | Avoid implying semantic LLM constraints that do not exist (Phases 4.2, 4.3). | `vulture_chatbot.py`, `evidence_validator.py` |
| **§II (Table I)** | Listed `CVSS+EPSS+KEV` without noting it is study-defined. | Labeled `CVSS+EPSS+KEV (study-defined)` and noted constructed-for-study status. | Distinguish study-defined baseline from published standards (Phase 3). | `risk_engine.py:174-187` |
| **§IV.B (New)** | Missing mathematical definition of `CVSS+EPSS+KEV`. | Added Equation 2 ($S_{\text{comb}}$), normalization, and missing-CVSS behavior. | Verify and document exact baseline formula (Phase 3). | `risk_engine.py:174-187`, `evaluate_temporal.py:270-278` |
| **§IV.C (TEOB)** | Claimed strict `2026-07-01T00:00:00Z` cutoff without clarifying EPSS daily granularity or missing-CVSS policy across methods. | Clarified EPSS day-level granularity (`2026-07-01`, no intraday timestamp, earliest KEV `2026-07-07`); added explicit missing-CVSS bullet covering all 5 methods. | Accurate temporal and missing-data documentation (Phases 1, 2). | `evaluate_temporal.py`, `teob_manifest.json`, `epss_2026-07-01.json` |
| **§V.B & Table V** | SSVC description could be read as official package; `Track*=Track=1` not in footnote. | Clarified vendored, cited CISA/SEI SSVC v2.0 adaptation with uniform defaults and `Track*=Track=1` in text and footnote. | Accurate SSVC provenance and assumptions (Phase 6). | `ssvc_baseline.py`, `results_ssvc.json` |
| **§VI & §VIII** | Did not consistently label `study-defined` `CVSS+EPSS+KEV`; Discussion lacked explicit v1/v2 distinction in one place. | Labeled `study-defined` `CVSS+EPSS+KEV`; contrasted v1 (`0.9488`) and v2 (`0.9317`) vs `EPSS×Context` (`0.9334`). | Consistent framing across Discussion and Conclusion (Phases 3, 4.4). | `paired_corrected_v2.csv`, `metrics.json` |
| **§VII (Limitations)** | Contained `(TODO: future work)`. | Replaced with `remain unmeasured and are left for future work.` | Remove manuscript-facing `TODO` (Phase 5). | `manuscript_revised.tex` |
| **Preamble** | Long URL in ref `[6]` overflowed column margin. | Added `\def\UrlBreaks{\do\/\do-\do_\do.}`. | Clean IEEE column wrapping (Phase 9). | `manuscript_revised.pdf` |
