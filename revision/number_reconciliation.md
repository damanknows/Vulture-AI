# Number Reconciliation Report

**Source TeX:** `revision/ICCI2026_revision/manuscript_revised.tex`  
**Total cells/claims checked:** 174  
**MISMATCH count:** 1

## Explicit Reconciliation Checklist

1. **Abstract `EPSS-only (0.0948, 0.0449)` vs Table III `EPSS-only` `NDCG@10` (`0.0948`):** Both are `0.0948` (**MATCH**). Deciding JSON key: `experiments/revision/teob_evaluation.json -> metrics.EPSS-only.ndcg@10 = 0.0948`.
2. **Previous LaTeX `+0.0177` vs `+0.0377` for `CVSS+EPSS+KEV` AP diff (Table IV):** Current `.tex` has `+0.0177` (**MATCH**). Deciding JSON key: `experiments/revision/teob_evaluation.json -> paired_stratified_bootstrap_vrs_minus_baseline.CVSS+EPSS+KEV.average_precision.observed_diff = 0.0177` (so `+0.0177` is authoritative; `+0.0377` is unsupported).
3. **Any normalized metric cell exceeding `1.0`:** `0` violations (`None` found; integer counts/ties such as `8001`, `7927`, `63`, `TP=9`, `5/5` are counts, not `[0,1]` metrics).
4. **Any cell shown as `--`:** **1 MISMATCH found** in Table V (`tab:exploratory`), row `EPSS×Context`, column `P@10 (Act)`: `.tex` has `--`, whereas `experiments/revision/statistics/statistical_report.json -> observed_metrics["EPSS×Context"]["precision@10_act"] = 1.0` (`1.0000`). **Decision rule:** JSON wins (recompute command if needed: `python3 -m experiments.revision.statistics.statistical_analysis`).
5. **OCR/PDF formatting artifacts (`10000` vs `1.0000`, `0.0048` vs `0.0948`):** In the `.tex` source, all values use four decimal places (`1.0000`, `0.0948`). Any `10000` or `0.0048` reading in PDF extraction/OCR would be a rendering/OCR artifact of `\resizebox` scaling, not a source value mismatch.

## MISMATCH Summary

- **Table V (tab:exploratory) | EPSS×Context | P@10 (Act)**: TeX=`--` vs JSON=`1.0000` (`experiments/revision/statistics/statistical_report.json -> observed_metrics.EPSS×Context.precision@10_act`). Decision rule: **JSON wins**; regenerate Table V row from JSON.

## Full Reconciliation Table

| Table | Row | Column | TeX Value | JSON File | JSON Key Path | JSON Value | Status |
|---|---|---|---|---|---|---|---|
| Table II (tab:teob_cohort) | NVD June 2026 published CVEs | Count | `8001` | `data/benchmark/temporal/teob_manifest.json` | `stats.nvd_total` | `8001` | **MATCH** |
| Table II (tab:teob_cohort) | Excluded: Rejected / Pre-cutoff KEV | Rejected / Pre-cutoff KEV | `59 / 15` | `data/benchmark/temporal/teob_manifest.json` | `stats.excluded_rejected / excluded_kev_at_cutoff` | `59 / 15` | **MATCH** |
| Table II (tab:teob_cohort) | Eligible TEOB cohort | Eligible total | `7927` | `data/benchmark/temporal/teob_manifest.json` | `stats.eligible_total` | `7927` | **MATCH** |
| Table II (tab:teob_cohort) | Observed 90-day KEV additions (y=1) | Positives (%) | `11 (0.139%)` | `data/benchmark/temporal/teob_manifest.json` | `stats.positives_within_horizon (rate)` | `11 (0.139%)` | **MATCH** |
| Table II (tab:teob_cohort) | Not observed in KEV during horizon (y=0) | Negatives (%) | `7916 (99.861%)` | `data/benchmark/temporal/teob_manifest.json` | `stats.negatives_not_observed (rate)` | `7916 (99.861%)` | **MATCH** |
| Table II (tab:teob_cohort) | EPSS available (date=2026-07-01) | EPSS available | `7927` | `data/benchmark/temporal/teob_manifest.json` | `stats.epss_available` | `7927` | **MATCH** |
| Table II (tab:teob_cohort) | CVSS v3.x available at cutoff | CVSS available | `6683` | `data/benchmark/temporal/teob_manifest.json` | `sum(unchanged,no_change,reconstructed)` | `6683` | **MATCH** |
| Table II (tab:teob_cohort) | \quad Unchanged / No post-cutoff CVSS change | Unchanged / No change | `823 / 5704` | `data/benchmark/temporal/teob_manifest.json` | `unchanged_since_cutoff / no_post_cutoff_cvss_change` | `823 / 5704` | **MATCH** |
| Table II (tab:teob_cohort) | \quad Reconstructed from cvehistory | Reconstructed | `156` | `data/benchmark/temporal/teob_manifest.json` | `stats.cvss_status_counts.reconstructed_from_cvehistory` | `156` | **MATCH** |
| Table II (tab:teob_cohort) | CVSS missing (post-cutoff added / v4.0-only) | Missing CVSS | `726 / 518` | `data/benchmark/temporal/teob_manifest.json` | `added_after_cutoff_excluded / missing_in_nvd` | `726 / 518` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | NDCG@10 | `0.0317` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.ndcg@10` | `0.0317` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | P@10 | `0.0317` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.precision@10` | `0.0317` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | R@10 | `0.0289` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.recall@10` | `0.0289` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | R@50 | `0.1443` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.recall@50` | `0.1443` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | R@100 | `0.2148` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.recall@100` | `0.2148` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | AP | `0.0259` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.average_precision` | `0.0259` | **MATCH** |
| Table III (tab:teob_main) | CVSS-only | Top Tie | `63` | `experiments/revision/teob_evaluation.json` | `tie_summary.CVSS-only.top_block_size` | `63` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | NDCG@10 | `0.0948` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.ndcg@10` | `0.0948` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | P@10 | `0.1000` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.precision@10` | `0.1000` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | R@10 | `0.0909` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.recall@10` | `0.0909` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | R@50 | `0.1818` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.recall@50` | `0.1818` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | R@100 | `0.1818` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.recall@100` | `0.1818` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | AP | `0.0449` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.average_precision` | `0.0449` | **MATCH** |
| Table III (tab:teob_main) | EPSS-only | Top Tie | `1` | `experiments/revision/teob_evaluation.json` | `tie_summary.EPSS-only.top_block_size` | `1` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | NDCG@10 | `0.0317` | `experiments/revision/teob_evaluation.json` | `metrics.KEV-first.ndcg@10` | `0.0317` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | P@10 | `0.0317` | `experiments/revision/teob_evaluation.json` | `metrics.KEV-first.precision@10` | `0.0317` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | R@10 | `0.0289` | `experiments/revision/teob_evaluation.json` | `metrics.KEV-first.recall@10` | `0.0289` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | R@50 | `0.1443` | `experiments/revision/teob_evaluation.json` | `metrics.KEV-first.recall@50` | `0.1443` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | R@100 | `0.2148` | `experiments/revision/teob_evaluation.json` | `metrics.KEV-first.recall@100` | `0.2148` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | AP | `0.0259` | `experiments/revision/teob_evaluation.json` | `metrics.KEV-first.average_precision` | `0.0259` | **MATCH** |
| Table III (tab:teob_main) | KEV-first | Top Tie | `63` | `experiments/revision/teob_evaluation.json` | `tie_summary.KEV-first.top_block_size` | `63` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | NDCG@10 | `0.1795` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.ndcg@10` | `0.1795` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | P@10 | `0.2000` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.precision@10` | `0.2000` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | R@10 | `0.1818` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.recall@10` | `0.1818` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | R@50 | `0.3636` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.recall@50` | `0.3636` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | R@100 | `0.3636` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.recall@100` | `0.3636` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | AP | `0.0928` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.average_precision` | `0.0928` | **MATCH** |
| Table III (tab:teob_main) | CVSS+EPSS+KEV | Top Tie | `1` | `experiments/revision/teob_evaluation.json` | `tie_summary.CVSS+EPSS+KEV.top_block_size` | `1` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | NDCG@10 | `0.2083` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).ndcg@10` | `0.2083` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | P@10 | `0.2000` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).precision@10` | `0.2000` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | R@10 | `0.1818` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).recall@10` | `0.1818` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | R@50 | `0.3636` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).recall@50` | `0.3636` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | R@100 | `0.3636` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).recall@100` | `0.3636` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | AP | `0.1104` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).average_precision` | `0.1104` | **MATCH** |
| Table III (tab:teob_main) | VRS (default N,A=0.5) | Top Tie | `1` | `experiments/revision/teob_evaluation.json` | `tie_summary.VRS (default context=0.5).top_block_size` | `1` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | ndcg@10 | Obs. Diff | `+0.1765` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.ndcg@10.observed_diff` | `+0.1765` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | ndcg@10 | 95% CI | `[-0.0484, 0.4737]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.ndcg@10.ci_95` | `[-0.0484, 0.4737]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | ndcg@10 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.ndcg@10.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | recall@50 | Obs. Diff | `+0.2193` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.recall@50.observed_diff` | `+0.2193` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | recall@50 | 95% CI | `[0.0152, 0.4684]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.recall@50.ci_95` | `[0.0152, 0.4684]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | recall@50 | Sig. | `Yes` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.recall@50.significant_95` | `Yes` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | average_precision | Obs. Diff | `+0.0845` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.average_precision.observed_diff` | `+0.0845` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | average_precision | 95% CI | `[-0.0029, 0.3204]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.average_precision.ci_95` | `[-0.0029, 0.3204]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS-only | average_precision | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS-only.average_precision.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | EPSS-only | ndcg@10 | Obs. Diff | `+0.1135` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.EPSS-only.ndcg@10.observed_diff` | `+0.1135` | **MATCH** |
| Table IV (tab:teob_boot) | EPSS-only | ndcg@10 | 95% CI | `[0.0000, 0.2593]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.EPSS-only.ndcg@10.ci_95` | `[0.0000, 0.2593]` | **MATCH** |
| Table IV (tab:teob_boot) | EPSS-only | ndcg@10 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.EPSS-only.ndcg@10.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | EPSS-only | average_precision | Obs. Diff | `+0.0655` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.EPSS-only.average_precision.observed_diff` | `+0.0655` | **MATCH** |
| Table IV (tab:teob_boot) | EPSS-only | average_precision | 95% CI | `[0.0089, 0.1982]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.EPSS-only.average_precision.ci_95` | `[0.0089, 0.1982]` | **MATCH** |
| Table IV (tab:teob_boot) | EPSS-only | average_precision | Sig. | `Yes` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.EPSS-only.average_precision.significant_95` | `Yes` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | ndcg@10 | Obs. Diff | `+0.0288` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.ndcg@10.observed_diff` | `+0.0288` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | ndcg@10 | 95% CI | `[0.0000, 0.1541]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.ndcg@10.ci_95` | `[0.0000, 0.1541]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | ndcg@10 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.ndcg@10.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | precision@10 | Obs. Diff | `+0.0000` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.precision@10.observed_diff` | `+0.0000` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | precision@10 | 95% CI | `[0.0000, 0.0000]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.precision@10.ci_95` | `[0.0000, 0.0000]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | precision@10 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.precision@10.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@10 | Obs. Diff | `+0.0000` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@10.observed_diff` | `+0.0000` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@10 | 95% CI | `[0.0000, 0.0000]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@10.ci_95` | `[0.0000, 0.0000]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@10 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@10.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@50 | Obs. Diff | `+0.0000` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@50.observed_diff` | `+0.0000` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@50 | 95% CI | `[0.0000, 0.0000]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@50.ci_95` | `[0.0000, 0.0000]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@50 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@50.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@100 | Obs. Diff | `+0.0000` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@100.observed_diff` | `+0.0000` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@100 | 95% CI | `[0.0000, 0.0000]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@100.ci_95` | `[0.0000, 0.0000]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | recall@100 | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.recall@100.significant_95` | `No` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | average_precision | Obs. Diff | `+0.0177` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.average_precision.observed_diff` | `+0.0177` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | average_precision | 95% CI | `[0.0000, 0.1084]` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.average_precision.ci_95` | `[0.0000, 0.1084]` | **MATCH** |
| Table IV (tab:teob_boot) | CVSS+EPSS+KEV | average_precision | Sig. | `No` | `experiments/revision/teob_evaluation.json` | `paired_stratified_bootstrap.CVSS+EPSS+KEV.average_precision.significant_95` | `No` | **MATCH** |
| Table V (tab:exploratory) | SSVC tree | NDCG@10 | `0.6939` | `experiments/revision/baselines/results_ssvc.json` | `metrics.ndcg@10` | `0.6939` | **MATCH** |
| Table V (tab:exploratory) | SSVC tree | P@10 (Act) | `0.5000` | `experiments/revision/baselines/results_ssvc.json` | `metrics.precision@10_act` | `0.5000` | **MATCH** |
| Table V (tab:exploratory) | SSVC tree | R@10 (Act) | `0.3333` | `experiments/revision/baselines/results_ssvc.json` | `metrics.recall@10_act` | `0.3333` | **MATCH** |
| Table V (tab:exploratory) | SSVC tree | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.SSVC tree.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | SSVC tree | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.SSVC tree.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | SSVC tree | Spearman ρ | `0.6129` | `experiments/revision/baselines/results_ssvc.json` | `metrics.spearman` | `0.6129` | **MATCH** |
| Table V (tab:exploratory) | CVSS-only | NDCG@10 | `0.7563` | `experiments/results/metrics.json` | `CVSS-only.ndcg10` | `0.7563` | **MATCH** |
| Table V (tab:exploratory) | CVSS-only | P@10 (Act) | `0.6000` | `experiments/results/metrics.json` | `CVSS-only.precision10_act` | `0.6000` | **MATCH** |
| Table V (tab:exploratory) | CVSS-only | R@10 (Act) | `0.4000` | `experiments/results/metrics.json` | `CVSS-only.recall10_act` | `0.4000` | **MATCH** |
| Table V (tab:exploratory) | CVSS-only | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.CVSS-only.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | CVSS-only | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.CVSS-only.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | CVSS-only | Spearman ρ | `0.7357` | `experiments/results/metrics.json` | `CVSS-only.spearman` | `0.7357` | **MATCH** |
| Table V (tab:exploratory) | CVSS v3.1 env. proxy | NDCG@10 | `0.8380` | `experiments/revision/baselines/results_cvss_env.json` | `metrics.ndcg@10` | `0.8380` | **MATCH** |
| Table V (tab:exploratory) | CVSS v3.1 env. proxy | P@10 (Act) | `0.7000` | `experiments/revision/baselines/results_cvss_env.json` | `metrics.precision@10_act` | `0.7000` | **MATCH** |
| Table V (tab:exploratory) | CVSS v3.1 env. proxy | R@10 (Act) | `0.4667` | `experiments/revision/baselines/results_cvss_env.json` | `metrics.recall@10_act` | `0.4667` | **MATCH** |
| Table V (tab:exploratory) | CVSS v3.1 env. proxy | AP@10 | `1.0000` | `experiments/revision/baselines/results_cvss_env.json` | `metrics.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | CVSS v3.1 env. proxy | AR@10 | `0.3704` | `experiments/revision/baselines/results_cvss_env.json` | `metrics.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | CVSS v3.1 env. proxy | Spearman ρ | `0.7979` | `experiments/revision/baselines/results_cvss_env.json` | `metrics.spearman` | `0.7979` | **MATCH** |
| Table V (tab:exploratory) | EPSS-only | NDCG@10 | `0.9217` | `experiments/results/metrics.json` | `EPSS-only.ndcg10` | `0.9217` | **MATCH** |
| Table V (tab:exploratory) | EPSS-only | P@10 (Act) | `0.8000` | `experiments/results/metrics.json` | `EPSS-only.precision10_act` | `0.8000` | **MATCH** |
| Table V (tab:exploratory) | EPSS-only | R@10 (Act) | `0.5333` | `experiments/results/metrics.json` | `EPSS-only.recall10_act` | `0.5333` | **MATCH** |
| Table V (tab:exploratory) | EPSS-only | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.EPSS-only.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | EPSS-only | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.EPSS-only.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | EPSS-only | Spearman ρ | `0.8237` | `experiments/results/metrics.json` | `EPSS-only.spearman` | `0.8237` | **MATCH** |
| Table V (tab:exploratory) | KEV-first | NDCG@10 | `0.7945` | `experiments/results/metrics.json` | `KEV-first.ndcg10` | `0.7945` | **MATCH** |
| Table V (tab:exploratory) | KEV-first | P@10 (Act) | `0.7000` | `experiments/results/metrics.json` | `KEV-first.precision10_act` | `0.7000` | **MATCH** |
| Table V (tab:exploratory) | KEV-first | R@10 (Act) | `0.4667` | `experiments/results/metrics.json` | `KEV-first.recall10_act` | `0.4667` | **MATCH** |
| Table V (tab:exploratory) | KEV-first | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.KEV-first.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | KEV-first | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.KEV-first.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | KEV-first | Spearman ρ | `0.8247` | `experiments/results/metrics.json` | `KEV-first.spearman` | `0.8247` | **MATCH** |
| Table V (tab:exploratory) | CVSS+EPSS+KEV | NDCG@10 | `0.9513` | `experiments/results/metrics.json` | `CVSS+EPSS+KEV.ndcg10` | `0.9513` | **MATCH** |
| Table V (tab:exploratory) | CVSS+EPSS+KEV | P@10 (Act) | `0.9000` | `experiments/results/metrics.json` | `CVSS+EPSS+KEV.precision10_act` | `0.9000` | **MATCH** |
| Table V (tab:exploratory) | CVSS+EPSS+KEV | R@10 (Act) | `0.6000` | `experiments/results/metrics.json` | `CVSS+EPSS+KEV.recall10_act` | `0.6000` | **MATCH** |
| Table V (tab:exploratory) | CVSS+EPSS+KEV | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.CVSS+EPSS+KEV.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | CVSS+EPSS+KEV | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.CVSS+EPSS+KEV.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | CVSS+EPSS+KEV | Spearman ρ | `0.8800` | `experiments/results/metrics.json` | `CVSS+EPSS+KEV.spearman` | `0.8800` | **MATCH** |
| Table V (tab:exploratory) | EPSS×Context | NDCG@10 | `1.0000` | `experiments/revision/statistics/statistical_report.json` | `observed_metrics.EPSS×Context.ndcg@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | EPSS×Context | P@10 (Act) | `--` | `experiments/revision/statistics/statistical_report.json` | `observed_metrics.EPSS×Context.precision@10_act` | `1.0000` | **MISMATCH** |
| Table V (tab:exploratory) | EPSS×Context | R@10 (Act) | `0.6667` | `experiments/revision/statistics/statistical_report.json` | `observed_metrics.EPSS×Context.recall@10_act` | `0.6667` | **MATCH** |
| Table V (tab:exploratory) | EPSS×Context | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.EPSS×Context.AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | EPSS×Context | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.EPSS×Context.AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | EPSS×Context | Spearman ρ | `0.9334` | `experiments/revision/statistics/statistical_report.json` | `observed_metrics.EPSS×Context.spearman` | `0.9334` | **MATCH** |
| Table V (tab:exploratory) | VRS (vrs-v1) | NDCG@10 | `1.0000` | `experiments/results/metrics.json` | `VRS Proposed.ndcg10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | VRS (vrs-v1) | P@10 (Act) | `1.0000` | `experiments/results/metrics.json` | `VRS Proposed.precision10_act` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | VRS (vrs-v1) | R@10 (Act) | `0.6667` | `experiments/results/metrics.json` | `VRS Proposed.recall10_act` | `0.6667` | **MATCH** |
| Table V (tab:exploratory) | VRS (vrs-v1) | AP@10 | `1.0000` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.VRS (vrs-v1).AP@10` | `1.0000` | **MATCH** |
| Table V (tab:exploratory) | VRS (vrs-v1) | AR@10 | `0.3704` | `experiments/revision/baselines/exploratory_actionable.json` | `methods.VRS (vrs-v1).AR@10` | `0.3704` | **MATCH** |
| Table V (tab:exploratory) | VRS (vrs-v1) | Spearman ρ | `0.9488` | `experiments/results/metrics.json` | `VRS Proposed.spearman` | `0.9488` | **MATCH** |
| Table VI (tab:ablation) | VRS (full) | NDCG@5 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_full.ndcg5` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (full) | NDCG@10 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_full.ndcg10` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (full) | NDCG@15 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_full.ndcg15` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (full) | P@10 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_full.precision10_act` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (full) | R@10 | `0.6667` | `experiments/results/ablation.json` | `metrics.vrs_full.recall10_act` | `0.6667` | **MATCH** |
| Table VI (tab:ablation) | VRS (full) | Spearman ρ | `0.9488` | `experiments/results/ablation.json` | `metrics.vrs_full.spearman` | `0.9488` | **MATCH** |
| Table VI (tab:ablation) | VRS (No EPSS) | NDCG@5 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_epss.ndcg5` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No EPSS) | NDCG@10 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_epss.ndcg10` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No EPSS) | NDCG@15 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_epss.ndcg15` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No EPSS) | P@10 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_epss.precision10_act` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No EPSS) | R@10 | `0.6667` | `experiments/results/ablation.json` | `metrics.vrs_no_epss.recall10_act` | `0.6667` | **MATCH** |
| Table VI (tab:ablation) | VRS (No EPSS) | Spearman ρ | `0.9575` | `experiments/results/ablation.json` | `metrics.vrs_no_epss.spearman` | `0.9575` | **MATCH** |
| Table VI (tab:ablation) | VRS (No KEV) | NDCG@5 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_kev.ndcg5` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No KEV) | NDCG@10 | `0.9581` | `experiments/results/ablation.json` | `metrics.vrs_no_kev.ndcg10` | `0.9581` | **MATCH** |
| Table VI (tab:ablation) | VRS (No KEV) | NDCG@15 | `0.9675` | `experiments/results/ablation.json` | `metrics.vrs_no_kev.ndcg15` | `0.9675` | **MATCH** |
| Table VI (tab:ablation) | VRS (No KEV) | P@10 | `0.9000` | `experiments/results/ablation.json` | `metrics.vrs_no_kev.precision10_act` | `0.9000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No KEV) | R@10 | `0.6000` | `experiments/results/ablation.json` | `metrics.vrs_no_kev.recall10_act` | `0.6000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No KEV) | Spearman ρ | `0.9451` | `experiments/results/ablation.json` | `metrics.vrs_no_kev.spearman` | `0.9451` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Context) | NDCG@5 | `0.9250` | `experiments/results/ablation.json` | `metrics.vrs_no_context.ndcg5` | `0.9250` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Context) | NDCG@10 | `0.9513` | `experiments/results/ablation.json` | `metrics.vrs_no_context.ndcg10` | `0.9513` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Context) | NDCG@15 | `0.9130` | `experiments/results/ablation.json` | `metrics.vrs_no_context.ndcg15` | `0.9130` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Context) | P@10 | `0.9000` | `experiments/results/ablation.json` | `metrics.vrs_no_context.precision10_act` | `0.9000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Context) | R@10 | `0.6000` | `experiments/results/ablation.json` | `metrics.vrs_no_context.recall10_act` | `0.6000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Context) | Spearman ρ | `0.8782` | `experiments/results/ablation.json` | `metrics.vrs_no_context.spearman` | `0.8782` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Bucket Override) | NDCG@5 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_buckets.ndcg5` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Bucket Override) | NDCG@10 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_buckets.ndcg10` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Bucket Override) | NDCG@15 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_buckets.ndcg15` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Bucket Override) | P@10 | `1.0000` | `experiments/results/ablation.json` | `metrics.vrs_no_buckets.precision10_act` | `1.0000` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Bucket Override) | R@10 | `0.6667` | `experiments/results/ablation.json` | `metrics.vrs_no_buckets.recall10_act` | `0.6667` | **MATCH** |
| Table VI (tab:ablation) | VRS (No Bucket Override) | Spearman ρ | `0.9535` | `experiments/results/ablation.json` | `metrics.vrs_no_buckets.spearman` | `0.9535` | **MATCH** |
| Table VII (tab:guard) | Actual attack (25) | TP | `9` | `experiments/revision/guardrail/metrics.json` | `confusion_matrix.TP` | `9` | **MATCH** |
| Table VII (tab:guard) | Actual attack (25) | FN | `16` | `experiments/revision/guardrail/metrics.json` | `confusion_matrix.FN` | `16` | **MATCH** |
| Table VII (tab:guard) | Actual benign (23) | FP | `7` | `experiments/revision/guardrail/metrics.json` | `confusion_matrix.FP` | `7` | **MATCH** |
| Table VII (tab:guard) | Actual benign (23) | TN | `16` | `experiments/revision/guardrail/metrics.json` | `confusion_matrix.TN` | `16` | **MATCH** |
| Table VIII (tab:integrity) | S01 | With KEV floor | `pass` | `experiments/revision/guardrail/score_integrity.json` | `cases[0].passed` | `pass` | **MATCH** |
| Table VIII (tab:integrity) | S02 | With KEV floor | `pass` | `experiments/revision/guardrail/score_integrity.json` | `cases[1].passed` | `pass` | **MATCH** |
| Table VIII (tab:integrity) | S03 | With KEV floor | `pass` | `experiments/revision/guardrail/score_integrity.json` | `cases[2].passed` | `pass` | **MATCH** |
| Table VIII (tab:integrity) | S04 | With KEV floor | `pass` | `experiments/revision/guardrail/score_integrity.json` | `cases[3].passed` | `pass` | **MATCH** |
| Table VIII (tab:integrity) | S05 | With KEV floor | `pass` | `experiments/revision/guardrail/score_integrity.json` | `cases[4].passed` | `pass` | **MATCH** |
| Table VIII (tab:integrity) | Total | With KEV floor | `5 / 5` | `experiments/revision/guardrail/score_integrity.json` | `n_passed / n_cases` | `5 / 5` | **MATCH** |
| Abstract | VRS | NDCG@10 | `0.2083` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).ndcg@10` | `0.2083` | **MATCH** |
| Abstract | VRS | AP | `0.1104` | `experiments/revision/teob_evaluation.json` | `metrics.VRS (default context=0.5).average_precision` | `0.1104` | **MATCH** |
| Abstract | CVSS-only | NDCG@10 | `0.0317` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.ndcg@10` | `0.0317` | **MATCH** |
| Abstract | CVSS-only | AP | `0.0259` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS-only.average_precision` | `0.0259` | **MATCH** |
| Abstract | EPSS-only | NDCG@10 | `0.0948` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.ndcg@10` | `0.0948` | **MATCH** |
| Abstract | EPSS-only | AP | `0.0449` | `experiments/revision/teob_evaluation.json` | `metrics.EPSS-only.average_precision` | `0.0449` | **MATCH** |
| Abstract | CVSS+EPSS+KEV | NDCG@10 | `0.1795` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.ndcg@10` | `0.1795` | **MATCH** |
| Abstract | CVSS+EPSS+KEV | AP | `0.0928` | `experiments/revision/teob_evaluation.json` | `metrics.CVSS+EPSS+KEV.average_precision` | `0.0928` | **MATCH** |
