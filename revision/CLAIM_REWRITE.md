# Manuscript Claims Audit and Rewrites

Scope: claims in `paper/manuscript.tex` (abstract, introduction, related work, method, results, threats, conclusion). **No changes have been made to `manuscript.tex`.** The rewrites below are proposals for review.

Classification:
- **Supported**: the claim matches a verified artifact or a verified primary source.
- **Partially supported**: the core is supported, but the stated scope, wording, or a number is too broad or unverified.
- **Unsupported**: no artifact or verified source supports the claim as written.
- **Requires new experiment**: could be true, but no repository evidence exists.
- **Future work**: correctly framed as not yet done.

Evidence references use repository paths or the verified-source IDs in `VERIFIED_REFERENCES.md`.

---

## A. Abstract and introduction

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| A1 | "With over 25,000 CVEs published annually" (Intro, para 1) | Cited to `nvd2023`. The NVD page does not state this figure. (VERIFIED_REFERENCES R10) | **Unsupported** | Remove the number, or cite a verified source for a specific year. Suggested: "Vulnerability volumes have grown substantially in recent years, which makes triage necessary." |
| A2 | CVSS "measures theoretical technical impact in isolation, omitting empirical exploitation telemetry and organization-specific network exposure" (Abstract) | CVSS v4.0 and v3.1 (R1, R2) include Threat (exploit maturity) and Environmental (controls, asset importance) metric groups, which are optional consumer-applied layers. | **Partially supported** | "CVSS base scores measure intrinsic severity and do not, by themselves, reflect observed exploitation or the consumer's environment; the standard's optional Threat and Environmental groups address this but are rarely applied in practice (not verified)." Remove "omitting" and "in isolation" as absolute statements. |
| A3 | "Unconstrained models remain vulnerable to factual hallucinations and indirect prompt injections" | Greshake et al. (R12) demonstrates indirect prompt injection. Hallucination: general knowledge, not a cited source here. | **Partially supported** | Keep injection claim with R12. Cite a verified source for hallucination or drop it. |
| A4 | VRS "combines ... environmental exposure metrics with an explicit policy override" | `risk_engine.py` (code verified) | **Supported** | Keep. |
| A5 | "Quantitative ranking is strictly decoupled from ... RAG assistant" | `vulture_chatbot.py` recomputes VRS from `finding` (verified in NOVELTY_AUDIT §3) | **Supported** | Keep. |
| A6 | "designed to detect and reject tested prompt injection signatures in service banners" | Phase 4 and `evaluate_rag_live.py` banner set (5 banners); the regex sees retrieved content, not banners (Phase 4 coverage gap) | **Partially supported** | "designed to detect and reject a small set of tested prompt-injection phrases in retrieved content." Drop "service banners" unless banners are in the retrieved content (they are in the live test but not the production path). |
| A7 | "outperforming CVSS-only ($\rho=0.7357$), EPSS-only ($\rho=0.8237$), and unweighted baselines" (Abstract) | `experiments/results/metrics.json` (reproduced; the Spearman values match) | **Partially supported** | The numbers are reproduced. "Outperforming" implies a generalizable advantage. Rewrite as "agreed more closely with the author-assigned reference ranking than ...". See §B. |
| A8 | "On the 500-CVE backlog, CVSS-only prio..." (truncated in the abstract source) | `expanded_500_table.md` (reproduced) | **Partially supported** | Full text was truncated in the file read; the claim must be re-read and rewritten as retrospective concordance (see §D). |

---

## B. Prioritization performance (RQ1)

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| B1 | VRS NDCG@10 = 1.0000, P@10 (Act) = 1.0000, R@10 = 0.6667 on N=41 | `experiments/results/metrics.json` (reproduced) | **Supported as measured**; but see B2 | Keep the numbers. Qualify: "on the author-assigned reference labels." |
| B2 | VRS "achieves a perfect NDCG@10" as evidence of superiority | Ceiling effect: 15 Act records exist, so any ordering that places Act items in the top 10 gives 1.0 (manuscript itself says this in §RQ2). Phase 3 bootstrap: VRS NDCG@10 is 1.0 in 100% of 2,000 resamples. | **Partially supported** | State that the metric is at its ceiling and cannot discriminate VRS from other top-10-correct rankings. Report Spearman as the discriminating metric. |
| B3 | "VRS ... outperforming ... EPSS-only ... and KEV-first" (Spearman 0.9488 vs 0.8237, 0.8247) | Phase 3: paired bootstrap of VRS minus EPSS-only on Spearman, CI [0.048, 0.243] (excludes 0, descriptive). Versus KEV-first, the interval is not reproduced here. | **Partially supported** | "The paired bootstrap interval for Spearman excludes zero against CVSS-only and EPSS-only on the benchmark (descriptive; no p-values; n=41)." Give the intervals. Do not claim superiority over KEV-first unless the Phase 3 interval is reported. |
| B4 | "CVSS-only achieves the lowest overall ranking quality" | `metrics.json`: CVSS-only has the lowest NDCG@10 (0.7563), P@10 (0.6), and Spearman (0.7357) | **Supported** | Keep, but add the uncertainty (Phase 3 CI for CVSS-only Spearman: [0.502, 0.878]). |
| B5 | "In total, 4 of the top 10 recommendations under CVSS-only are non-emergency findings" | `metrics.json` P@10 = 0.6 implies 4 of 10 are not Act | **Supported** | Keep. |
| B6 | "CVSS ... promotes theoretical zero-days (e.g., XZ Utils CVE-2024-3094, CVSS 10.0)" | `cves.csv`: CVE-2024-3094 cvss 10.0, label Attend; not KEV | **Supported** | Note that XZ Utils is labeled Attend, not Act; the wording "theoretical zero-day" is an interpretive label. Use "a CVSS 10.0 supply-chain backdoor without KEV listing in the benchmark snapshot." |
| B7 | "Superiority of Context-Aware Prioritization" (section title) | Ablation "No Context" drops Spearman 0.9488 → 0.8782 (`ablation.json`); Phase 3 reports this as a difference | **Partially supported** | Retitle "Contribution of Environmental Context". "Superiority" is not supported as a general claim. |
| B8 | "EPSS-only matches VRS at K=5 (NDCG@5 = 1.0000)" | `metrics.json` ndcg5 EPSS-only = 1.0, VRS = 1.0 | **Supported** | Keep. |
| B9 | "VRS ... demonstrates depth robustness" | NDCG@5/10/15 are 1.0 for VRS, but the same ceiling applies (B2) | **Partially supported** | Keep only with the ceiling caveat. |

---

## C. Ablation and RQ2

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| C1 | "Environmental context ... (a drop of 0.0706; on 39 real records, from 0.9433 to 0.8597)" | Full-model value 0.9488 is in `metrics.json`; the 39-record values (0.9433, 0.8597) are cited from the repository summary | **Supported** (the 39-record values were not re-derived in this audit) | Keep, but note the 39-record value was not reproduced in Phase 3. |
| C2 | "This confirms that ... internal topology is essential for resolving operational urgency" | Ablation shows a Spearman change against the author-assigned rubric, which uses exposure and criticality as inputs (construct circularity, Threats §) | **Unsupported as stated** | "Removing context reduces agreement with the author-assigned rubric, which is built from the same context factors; this does not show operational effect." |
| C3 | "EPSS ... ablation increases Spearman (0.9575)" and the explanation "this is an artifact of alignment with our specific rubric" | `ablation.json`; the paper itself acknowledges the artifact | **Supported** (the manuscript's own caveat is accurate) | Keep the caveat. Remove any phrasing that implies EPSS is redundant in operation. |
| C4 | "in operational SOC practice, EPSS provides indispensable early warning before KEV listing occurs" | FIRST FAQ describes EPSS as a 30-day forecast; "early warning" is not stated by FIRST. No operational evidence in the repository. | **Unsupported** | "EPSS provides a forward-looking probability that is distinct from KEV's record of observed exploitation (per FIRST's description)." Drop "indispensable" and "early warning". |
| C5 | "Guaranteed KEV compliance is a mandatory operational requirement under federal directives like BOD 22-01" | BOD 22-01 is revoked and superseded by BOD 26-04 (R6); BOD 26-04 not read (R7) | **Unsupported (outdated)** | Replace with: "CISA guidance treats KEV listings as a top remediation priority. BOD 22-01, which established the catalog, has been superseded by BOD 26-04 (2026); its requirements were not reviewed for this revision." |
| C6 | "XZ Utils (CVE-2024-3094, CVSS 10.0, reference rank 16) is placed in the standard bucket behind ... Dirty Pipe ... Deactivating the bucket override ... shifting it to rank 23" | Discussed in manuscript; `ablation.json` and `baselines.json` | **Supported** (rank values per the repository; not separately recomputed here) | Keep. |
| C7 | "Ceiling effects ... mathematically yields NDCG@10 = 1.0000" | Mathematical: any top-10 with only Act items gives NDCG@10 = 1.0 under the stated gain function | **Supported** | Keep. |

---

## D. 500-CVE backlog and KEV concordance

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| D1 | "backlog scales" / "realistic enterprise backlog" (N=500) | The 500-CVE corpus is a sample of 2023–2024 CVEs from cvelistV5 (seed 42). It is not an enterprise backlog: there is no per-host or per-organization data. | **Unsupported** | "A 500-CVE corpus sampled from public CVE records; it is not an enterprise backlog and carries no per-asset context." |
| D2 | "Threat-aware methods achieve 100% recall at depth 25 ... EPSS-only reaches 88.0%" | `expanded_500_table.md` (reproduced: KEV-first, VRS R@25 = 1.00; EPSS-only R@25 = 0.88; CVSS-only = 0.44) | **Supported as measured** | Keep the numbers. Qualify as retrospective concordance. |
| D3 | "CVSS-only prioritization deteriorates severely ... omitting 14 weaponized vulnerabilities" | Derived from R@25 = 11/25 (`expanded_500_table.md`) | **Supported** | Keep. |
| D4 | "Structural ceiling ... expected consequence of policy enforcement rather than proof of predictive superiority" | The manuscript's own disclaimer; consistent with the KEV label being an input (`kev` column) | **Supported** (the disclaimer is correct) | Keep, and extend (see D5). |
| D5 | KEV labels used as the evaluation target while `kev` is also a feature | The `kev` column is both the VRS input (`K`) and the concordance label. This is an identity: a KEV-first ranking will always score perfect recall for KEV items. | **Partially supported** | State explicitly that the KEV concordance test is circular for KEV-first and the urgent bucket and is included only as a policy-consistency check. |
| D6 | "all 25 KEV-listed items stem from the curated baseline, while 461 CVEs are sampled ... none of which appeared in the KEV snapshot" | Verified: 0 of 461 added CVEs are in the feed; all 25 KEV entries are in the curated 39 (`revision/evidence/kev_consistency.json`) | **Supported** | Keep. |
| D7 | "Each record incorporates ... cached FIRST EPSS probabilities (dated 2026-10-13)" | Verified: 461/461 cache entries dated 2026-10-13 and none missing (`epss_cache_500.json`) | **Supported** | Keep. Note the 39 curated rows use the 2026-10-14 freeze. |
| D8 | "CNA-verified CVSS base scores" | Source is cvelistV5 (CVE Program) records; "CNA-verified" is not verified per record in this audit | **Partially supported** | "CVSS base scores from the cvelistV5 release `cve_2026-10-13_2300Z`." Drop "CNA-verified" unless each score's CNA is checked. |
| D9 | The 461 records' `source_timestamp` (publication date) vs 2026 features | Verified mismatch (TEMPORAL_AUDIT §3) | **Unsupported as an implicit claim** (the manuscript does not state it) | Add an explicit sentence: features are from the 2026 snapshot even though rows carry 2023–2024 publication dates. |
| D10 | **KEV flag disagreement, 4 records (headline `cves.csv`)** | Verified: CVE-2022-1292 and CVE-2019-15846 are `kev=1` but not in the feed; CVE-2021-3560 and CVE-2022-0492 are `kev=0` but in the feed (`revision/evidence/kev_consistency.json`) | **Unsupported; needs author decision** | The authors must decide the correct KEV status at the snapshot date, then re-run the headline results. Until then the manuscript should disclose the discrepancy. Not changed here (task forbids changing labels or results). |

---

## E. Guardrail and RQ3

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| E1 | "Metric Invariance: ... the quantitative VRS score remained mathematically invariant" | Phase 4: score integrity 5/5 on the real path; the score is recomputed (`vulture_chatbot.py`). The prior fix included a priority floor. | **Supported** (for the score; not for priority before Phase 4) | Keep the score claim. Add: "Priority was not invariant before a Phase 4 deterministic floor was added for KEV-listed findings." |
| E2 | "Injection Rejection on Tested Signatures ... the evidence validation filter successfully detected the prompt injection pattern" | `evaluate_rag.py` MockLLM test and Phase 4: the filter flags the tested banners (5/5 in `evaluate_rag_live.py`) | **Partially supported** | Keep "tested signatures." Add Phase 4: TPR 0.36 on the 25-attack corpus, FPR 0.30 on the 23-benign corpus. |
| E3 | "Simulated hallucinated CVSS scores (e.g., citing CVSS 4.5 for ... 9.8) were caught" | `evidence_validator.py` numeric check; tests in `test_evidence_validator.py` | **Supported** for the mock case | Keep, with "in a mock test." |
| E4 | Live Llama-3.1-8B trial: "41/41 structural validity ... 39/41 numeric grounding ... 2/41 intercepted ... 5/5 banners blocked" | `experiments/results/rag_eval.json` states `live_model_evaluated: false`. The 41/41 and 39/41 figures appear only in `revision/*.md` audit files; the live run log (`evaluate_rag_live.py` output) was not found in the repository. | **Unsupported as an artifact** | Either include the live run log with its model version, date, and settings, or remove the live-trial paragraph. Until then, state that live evaluation is "reported in the audit notes, with output not included in the artifact set." |
| E5 | "blocked 5/5 tested indirect injection banners" | The 5 banners in `evaluate_rag_live.py` are tested by a regex that matches exact phrases. Those phrases were written to match the test. | **Partially supported** (circular: the test phrases were the regex targets) | State: "the filter flags all five banner payloads, which were written with the same phrases the filter targets. Coverage of paraphrased payloads is not measured (Phase 4: paraphrases missed)." |
| E6 | "Scope Limitation" paragraph | Accurate per Phase 4 | **Supported** | Keep. |
| E7 | "Completed Work includes ... the Pydantic RAG pipeline, the evidence validator, and both the 41-CVE and 500-CVE benchmarks" | Code and artifacts exist | **Supported** | Keep. |
| E8 | "Proposed Work ... asynchronous worker queues (Celery/Redis) ... multi-operator clinical SOC trials" | Not in the repository (no Celery config found in Phase 2–4 review) | **Future work** | Keep as future work. Remove "clinical" unless a clinical setting is planned; it is not described elsewhere. |

---

## F. Threats to validity and conclusion

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| F1 | "Reference relevance grades were manually assigned by the authors" | `LABELING_PROTOCOL.md` (repo); `cves.csv` labels | **Supported** | Keep. |
| F2 | "Mapping SSVC discrete outcomes into 4-level ordinal grades introduces additional discretization subjectivity" | Accurate | **Supported** | Keep. |
| F3 | "This confirms that the observed performance gain over baselines is driven by environmental grounding rather than scoring formula artifacts" (Threats, Baseline Information Asymmetry) | The No-Context ablation matches CVSS+EPSS+KEV (0.8782 vs 0.8800). That shows context accounts for the gap on this rubric. It does not rule out formula artifacts, and the rubric itself uses context. | **Unsupported as stated** | "On this rubric, removing context brings VRS's rank correlation to the level of the vulnerability-only combo baseline. Because the rubric uses context as an input, this does not establish that the gain generalizes." |
| F4 | "Results reflect construct alignment with SSVC triage principles; independent analyst validation and operational breach prediction remain future work" | Consistent with the evidence | **Supported** | Keep. This is the most accurate claim in the paper. |
| F5 | Conclusion: "guarding generative triage assistance against tested indirect prompt injection and numerical hallucination patterns under controlled evaluation" | Consistent with Phase 4 | **Supported** | Keep. |
| F6 | Conclusion: "outperforming CVSS-only (0.7563 NDCG, 0.6000 P@10) and unweighted baselines" | Numbers reproduced; "outperforming" as in B3 | **Partially supported** | Replace with the B3 rewrite. |
| F7 | Conclusion: "Ablations confirmed environmental context adds 0.0706 in rank correlation" | Reproduced from `ablation.json` (0.9488 − 0.8782 = 0.0706) | **Supported** (on this rubric) | Add "on the author-assigned rubric." |

---

## G. Related work and citation claims

| # | Claim | Evidence | Supported? | Required rewrite |
|---|---|---|---|---|
| G1 | "Under Binding Operational Directive 22-01 ... requiring federal civilian agencies to remediate listed vulnerabilities within strict timelines (typically 14–21 days)" | BOD 22-01 is revoked (R6). Its timelines are "two weeks" for CVEs assigned after 2021 and "6 months" for earlier CVEs. "14–21 days" is not the stated timeline. | **Unsupported (outdated and misquoted)** | "CISA's BOD 22-01 (2021), since superseded by BOD 26-04 (2026), required federal agencies to remediate KEV-listed vulnerabilities within two weeks for CVEs assigned after 2021 and within six months for earlier CVEs." |
| G2 | "Jacobs et al. ... demonstrating that fewer than 5% of published CVEs ever witness observed exploitation in the wild" | The 5% figure is not in any fetched source. FIRST says KEV lists "roughly 0.5%" and EPSS observes "roughly 2.5–3%" of CVEs in a 30-day window (FAQ). CISA says "less than 4%" of all CVEs have been exploited (BOD 22-01 FAQ). | **Unsupported as attributed** | Replace with a verified figure and source: "CISA reported that fewer than 4% of CVEs had been exploited (BOD 22-01 FAQ, 2021)." Drop attribution to Jacobs et al. |
| G3 | "EPSS achieves substantially higher precision in predicting imminent threat activity than CVSS" | FIRST FAQ: "High severity scores are slightly better than random at predicting exploitation activity" and "CVSS and EPSS ... are empirically uncorrelated". The FAQ does not state a precision comparison. | **Partially supported** | "FIRST reports that CVSS base scores are only slightly better than random at predicting exploitation, while EPSS is a calibrated probability trained on exploitation data." Drop "substantially higher precision". |
| G4 | "Spring et al. developed SSVC ... categorizing ... into Track, Attend, Act" | CISA SSVC page (R8) confirms the four outcomes (Track, Track*, Attend, Act) and a 2019 SEI+CISA development; the author list and report number come from an unverified bib entry (R9) | **Partially supported** | Keep the description. Verify the citation (R9) before submission. |
| G5 | "CVSS v3.1 evaluates base metrics ... Although temporal and environmental metrics exist ... industry practice overwhelmingly relies on the base score" | Metric list verified (R2). "Overwhelmingly relies" is an unsourced practice claim. | **Partially supported** | Keep the metric description. Replace "overwhelmingly" with a sourced statement or "frequently". |
| G6 | "Greshake et al. ... (AISec 2023)" venue and pages | arXiv verified; venue and pages not confirmed (R12) | **Partially supported** | Confirm the proceedings record before submission. |
| G7 | "Lewis et al. (RAG)" | arXiv verified; NeurIPS 2020 per arXiv comments (R11) | **Supported** | Keep. |
| G8 | "Prior defensive approaches rely on secondary LLM judges or classifier fine-tuning, which incur computational overhead and remain non-deterministic" | No verified source for this characterization. Spotlighting (R14), StruQ (R15), and SecAlign (R16) differ: they are a prompt-format transformation, a fine-tuned model, and preference optimization. None is described as an LLM judge. | **Unsupported as a general claim** | Cite R14–R16 and describe each accurately. Remove the general "secondary LLM judges" claim unless a verified source for it is added. |
| G9 | "Vulture-AI instead introduces a deterministic, rule-based verification filter over the extracted evidence" (Related Work) | Accurate for `evidence_validator.py`; Phase 4 measured its limits | **Supported** as a description | Keep, but add the Phase 4 limits and cite R14–R16 as stronger alternatives not implemented here. |
| G10 | "Nmap ... unprivileged version detection" (method) | `scanner.py` (not re-audited here) | **Not audited in this revision** | Leave unchanged; outside Phase 5 scope. |
| G11 | `lyon2009nmap` cited? | The bib entry exists but is not cited in the text. | **Unsupported (orphan)** | Remove the entry or cite it where Nmap is described. |

---

## H. Summary of required actions

**Must fix before resubmission (unsupported or outdated):**
1. A1: remove the "25,000 per year" figure.
2. C5 and G1: BOD 22-01 is revoked; correct the timeline and the "current policy" framing.
3. G2: the "fewer than 5%" figure is attributed to Jacobs et al. but is not in any verified source.
4. E4: the live-LLM results have no artifact; include the run or remove the paragraph.
5. D10: the 4 KEV-flag mismatches need an author decision and disclosure.
6. F3: the "driven by environmental grounding" claim is stronger than the evidence.
7. C2 and C4: "operational" and "early warning" claims are unsupported.
8. D1: "enterprise backlog" overstates the 500-CVE corpus.

**Should fix (partially supported):**
9. A7, F6, B3: replace "outperforming" with "agreed more closely with the author-assigned labels", and report the intervals.
10. B2: label NDCG@10 as ceiling-limited.
11. B7: retitle "Superiority of ..." sections.
12. A2, G3, G5: soften absolute CVSS and EPSS statements.
13. E2, E5: state the injection-filter limits from Phase 4.
14. D5: state the KEV concordance is circular for KEV-first and the urgent bucket.
15. D8: drop "CNA-verified" unless checked.
16. G8: remove the unsourced characterization of prior defenses.

**Future work framing (correct as is or minor edit):**
17. E8: remove "clinical" unless planned.
18. The temporal limitations (TEMPORAL_AUDIT §7) must be added to Threats to Validity.

---

## I. Items not changed (per task instruction)

- No benchmark label, ranking, or original result was modified.
- `paper/manuscript.tex` was not edited. The rewrites above are proposals for review.
- The KEV flag mismatches (D10) are reported but not corrected.
