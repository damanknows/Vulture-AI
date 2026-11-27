# Submission Readiness Report — Vulture-AI (ICCI 2026)

**Date:** 2026-11-27  
**Branch:** `fix/final-pass`  
**Final PDF:** `revision/ICCI2026_revision/final_submission/Vulture_AI_ICCI2026_Anonymous_Submission.pdf` (7 pages, `143,189` bytes)  
**MISMATCH count:** `0` (`183 / 183` reconciled items match in `revision/number_reconciliation.md`)  
**BLOCKED count:** `0`

---

## Hard-Gate Checklist

| Gate | Result | Evidence |
|---|---|---|
| `experiments/reproduce_all.py` exits 0 | **PASS** | Ran cleanly; 41-CVE SHA `27979cc0...` verified |
| `experiments/revision/manuscript_audit.py` exits 0 | **PASS** | `117 / 117` checks passed, `0` failed |
| `experiments/revision/reconcile_numbers.py` (`MISMATCH = 0`) | **PASS** | `183 / 183` items matched (`MISMATCH = 0`) |
| No normalized metric `> 1.0` | **PASS** | Verified in both `manuscript_audit.py` and `reconcile_numbers.py` |
| No `--` cell in any table | **PASS** | `dash_cells = 0` (`EPSS×Context` `P@10 (Act)` updated to `1.0000`) |
| No `NOT_AVAILABLE`, `PENDING`, `TODO`, `FIXME` in `.tex` | **PASS** | `grep` and `manuscript_audit.py` lint returned `0` hits |
| Clean PDF compilation (no `??`, no hiding overfull boxes, Fig. 1 present) | **PASS** | Clean build from deleted aux files; 7 pages, `0` `??` refs; only minor Table I `\resizebox` cell-internal overfulls (`5.5–15.2pt`, no hidden text) |
| Targeted test suite (`pytest`) | **PASS** | `14 / 14` passed (`test_manuscript_audit.py`, `test_remaining_gaps_audit.py`, `test_temporal_benchmark.py`) |
| Citation integrity (`revision/citation_audit.md`) | **PASS** | All `18` cited entries have verified DOIs or stable URLs |
| Double-blind local tree (`revision/anonymity_report.md`) | **PASS** | Local tree & PDF metadata clean; re-publish `anonymous.4open.science/r/Vulture-AI` recommended for git history anonymization |

---

## Numbers Changed in This Final Pass

| Location | Old Value | New Value | Deciding JSON Key Path |
|---|---|---|---|
| Table V (`tab:exploratory`), `EPSS×Context`, `P@10 (Act)` | `--` | `1.0000` | `experiments/revision/statistics/statistical_report.json -> observed_metrics["EPSS×Context"]["precision@10_act"]` |
| Table IV (`tab:teob_boot`), `CVSS-only / KEV-first` | Merged row | Split into separate `CVSS-only` and `KEV-first` rows (`+0.1765`, `+0.2193`, `+0.0845`) | `experiments/revision/verify_kevfirst.json -> paired_bootstrap_vrs_minus_baseline.{CVSS-only,KEV-first}` (`teob_evaluation.json`) |

*(Note: Abstract `EPSS-only` `NDCG@10 = 0.0948` and Table IV `CVSS+EPSS+KEV` `AP diff = +0.0177` already matched `experiments/revision/teob_evaluation.json` and were confirmed via `revision/verify_epss_only.json` and `revision/verify_comb_ap.json`.)*

---

## Verdict
**READY** (local manuscript, numbers, PDF, and upload package pass all hard gates; user should confirm the 7-page ICCI 2026 portal limit and verify/re-publish `https://anonymous.4open.science/r/Vulture-AI` in the 4open.science dashboard).
