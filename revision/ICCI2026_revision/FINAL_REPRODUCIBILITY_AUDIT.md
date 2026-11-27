# Final Reproducibility & Manuscript Audit Report (Paper 144)

**Date:** 2026-11-27  
**Branch:** `research-v2`  
**Anonymized Artifact URL:** `https://anonymous.4open.science/r/Vulture-AI`

---

## 1. Artifacts Generated & Verified
- **TEOB (Frozen Primary Benchmark):** `data/benchmark/temporal/teob_2026-07-01_90d.csv` (SHA-256 `94c7b4cab13daccb5dbe3abdebe6bf4d17f7643bfe0036316dfb792359e07794`), `teob_manifest.json`, `experiments/revision/teob_evaluation.json`, `teob_evaluation.md`.
- **41-CVE Exploratory Reproduction:** `experiments/results/reproducibility_manifest.json`, `baselines.json`, `ablation.json`, `metrics.json`, `figures/fig1.pdf`.
- **Additional Reviewer-Gap Artifacts:**
  - `experiments/revision/baselines/results_ssvc.json` & `ssvc_teob_infeasible.md`
  - `experiments/revision/baselines/results_cvss_env.json` & `cvss_v4_teob_infeasible.md`
  - `experiments/revision/baselines/exploratory_actionable.json`
  - `experiments/revision/sensitivity/full_rank_results.json`
  - `experiments/revision/cpe/cpe_matching_results.json` & `data/cpe_matching/labelled_banners.csv`
  - `experiments/revision/explanation/explanation_evaluation.csv` & `explanation_summary.json`
  - `experiments/revision/annotation/` (`blind_sheet.csv`, `annotation_template.csv`, `dry_run_agreement.json`) & `docs/annotation/rater_protocol.md`, `explanation_protocol.md`
  - `experiments/revision/manuscript_audit.py` & `remaining_gaps_audit.json`
- **Revised Manuscript & PDF:** `revision/ICCI2026_revision/manuscript_revised.tex`, `manuscript_revised.pdf`, `references_revised.bib`.

## 2. Checks Passed / Failed
- **`experiments/reproduce_all.py`:** Passed (exit 0).
- **`experiments/revision/manuscript_audit.py`:** **114 / 114** `.tex` table cells matched their JSON sources, **0 failed**, **0 metrics > 1.0**.
- **`experiments/audit_remaining_gaps.py`:** `all_match: true`.
- **`pytest` suite (13 modules):** **104 passed, 0 failed**.
- **`git diff --check` & `/tmp/tectonic-bin/tectonic manuscript_revised.tex`:** Passed cleanly (6 pages, 0 undefined citations).

## 3. `NOT_AVAILABLE` / `PENDING` Items (With Reasons & Matching Manuscript Disclosures)
1. **Semantic explanation quality (`NOT_AVAILABLE`):** Cerebras API returned `HTTP Error 402: Payment Required`, no local Ollama model was running (`explanation_summary.json`), and human spot-check (`docs/annotation/explanation_protocol.md`) is `PENDING`. Disclosed in Abstract, RQ3 (§I), §V.C, and §VII; 25/25 stub explanations passed `chat_with_validation` structural/evidence checks.
2. **Independent human rater agreement (`PENDING`):** `blind_sheet.csv` and `agreement.py` are verified on a synthetic dry run (`dry_run_agreement.json`), while real human rater data were not collected. Disclosed in §VII (`rater_protocol.md`).
3. **True CVSS v4.0 environmental scoring (`NOT_AVAILABLE`):** `cves.csv` lacks v4.0 vectors (Table V uses a labeled v3.1 scalar proxy); TEOB lacks pre-cutoff v4.0 history coverage and environmental context (`cvss_v4_teob_infeasible.md`). Disclosed in Table V footnote and §VII.
4. **Live-network scanner-to-CVE end-to-end recall (`NOT_AVAILABLE`):** No labelled live Nmap-XML-to-CVE ground-truth corpus exists; evaluated on 36 synthesized public Nmap-style banners (`cpe_matching_results.json`, precision `0.8387`, recall `1.0000`, F1 `0.9123`). Disclosed in §V.C and §VII.
5. **Live frontier-LLM guardrail evaluation (`NOT_AVAILABLE`):** No active API quota / local model server. Disclosed in §VII.
