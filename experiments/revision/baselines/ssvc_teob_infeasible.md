# Why the SSVC Decision-Tree Baseline Is Not Run on TEOB

The CISA/SEI Stakeholder-Specific Vulnerability Categorization (SSVC) v2.0 decision tree cannot be applied to the Temporal Exploitation Outcome Benchmark (TEOB, `data/benchmark/temporal/teob_2026-07-01_90d.csv`) without fabricating unavailable historical context:

1. **Missing Historical Mission Prevalence:** TEOB contains 7,927 public NVD CVEs with no organizational asset inventory or `asset_criticality` records as of `2026-07-01T00:00:00Z`. Setting constant default `Mission Prevalence` across all 7,927 CVEs would collapse the stakeholder dimension of SSVC.
2. **Missing Public Well-being Context:** No historical `Public Well-being` impact annotations exist for the 7,927 June 2026 CVEs.
3. **Zero Pre-Cutoff KEV (`kev_at_cutoff = 0`):** All 15 pre-cutoff KEV entries are excluded from TEOB by design, so no CVE has `"active"` exploitation via KEV at cutoff; combined with constant context defaults, SSVC would degenerate into a coarse 2- or 3-tier partition driven by `EPSS >= 0.1` and `CVSS >= 9.0` rather than a stakeholder-specific tree.

Consistent with TEOB Design Principle 5 (*"No fabricated asset context"*), SSVC is evaluated only on the exploratory 41-CVE benchmark (`experiments/revision/baselines/results_ssvc.json`), where per-finding `asset_criticality` is defined, and is omitted from TEOB.
