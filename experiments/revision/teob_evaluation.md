# TEOB Evaluation Results (`2026-07-01`, 90-day horizon)

- **Eligible CVEs:** 7927
- **Observed KEV additions (90d):** 11 (0.139%)
- **Negatives (not observed in KEV within horizon):** 7916
- **CVSS available at cutoff:** 6683 (missing: 1244)
- **EPSS available at cutoff:** 7927 (missing: 0)
- **Ranking & ties:** Unrounded float64 scores; exact analytical tie-aware expected metrics.
- **Bootstrap:** Paired stratified bootstrap (`n_boot=1000`, `n_valid=1000`, `seed=20261127`), 95% percentile CIs.
- **Context handling:** No independent historical context; EPSS x Context omitted; VRS uses N=0.5, A=0.5 defaults.

## Tie-Aware Ranking Metrics

| Method | NDCG@10 | P@10 | R@10 | R@50 | R@100 | Avg Precision | Top Tie Block |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CVSS-only | 0.0317 | 0.0317 | 0.0289 | 0.1443 | 0.2148 | 0.0259 | 63 |
| EPSS-only | 0.0948 | 0.1000 | 0.0909 | 0.1818 | 0.1818 | 0.0449 | 1 |
| KEV-first | 0.0317 | 0.0317 | 0.0289 | 0.1443 | 0.2148 | 0.0259 | 63 |
| CVSS+EPSS+KEV | 0.1795 | 0.2000 | 0.1818 | 0.3636 | 0.3636 | 0.0928 | 1 |
| VRS (default context=0.5) | 0.2083 | 0.2000 | 0.1818 | 0.3636 | 0.3636 | 0.1104 | 1 |

## Paired Stratified Bootstrap (VRS minus Baseline, 95% Percentile CI)

| Baseline | Metric | Obs Diff | 95% CI | Sig (95%) |
| --- | --- | ---: | --- | --- |
| CVSS-only | ndcg@10 | +0.1765 | [-0.0484, 0.4737] | False |
| CVSS-only | precision@10 | +0.1683 | [-0.0484, 0.4000] | False |
| CVSS-only | recall@10 | +0.1530 | [-0.0440, 0.3636] | False |
| CVSS-only | recall@50 | +0.2193 | [0.0152, 0.4684] | True |
| CVSS-only | recall@100 | +0.1488 | [-0.0644, 0.4202] | False |
| CVSS-only | average_precision | +0.0845 | [-0.0029, 0.3204] | False |
| EPSS-only | ndcg@10 | +0.1135 | [0.0000, 0.2593] | False |
| EPSS-only | precision@10 | +0.1000 | [0.0000, 0.3000] | False |
| EPSS-only | recall@10 | +0.0909 | [0.0000, 0.2727] | False |
| EPSS-only | recall@50 | +0.1818 | [0.0000, 0.4545] | False |
| EPSS-only | recall@100 | +0.1818 | [0.0000, 0.4545] | False |
| EPSS-only | average_precision | +0.0655 | [0.0089, 0.1982] | True |
| KEV-first | ndcg@10 | +0.1765 | [-0.0484, 0.4737] | False |
| KEV-first | precision@10 | +0.1683 | [-0.0484, 0.4000] | False |
| KEV-first | recall@10 | +0.1530 | [-0.0440, 0.3636] | False |
| KEV-first | recall@50 | +0.2193 | [0.0152, 0.4684] | True |
| KEV-first | recall@100 | +0.1488 | [-0.0644, 0.4202] | False |
| KEV-first | average_precision | +0.0845 | [-0.0029, 0.3204] | False |
| CVSS+EPSS+KEV | ndcg@10 | +0.0288 | [0.0000, 0.1541] | False |
| CVSS+EPSS+KEV | precision@10 | +0.0000 | [0.0000, 0.0000] | False |
| CVSS+EPSS+KEV | recall@10 | +0.0000 | [0.0000, 0.0000] | False |
| CVSS+EPSS+KEV | recall@50 | +0.0000 | [0.0000, 0.0000] | False |
| CVSS+EPSS+KEV | recall@100 | +0.0000 | [0.0000, 0.0000] | False |
| CVSS+EPSS+KEV | average_precision | +0.0177 | [0.0000, 0.1084] | False |
