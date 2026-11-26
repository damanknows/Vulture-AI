# Novelty Audit

Audit of what can defensibly be claimed for Vulture-AI, based on the implementation (`risk_engine.py`, `vulture_chatbot.py`, `evidence_validator.py`, `context_baselines.py`, `experiments/`) and the verified sources in `VERIFIED_REFERENCES.md`.

## 1. Bottom line

Vulture-AI does **not** introduce a new vulnerability indicator, a new scoring formula family, or a new prompt-injection defense. Each input signal (CVSS, EPSS, KEV, exposure, asset criticality) and the weighted-sum form already exist in published practice or in official guidance. The defensible contribution is a **system-level integration with a separation of responsibilities**:

1. A deterministic, recomputed priority score that the language model cannot write to.
2. A deterministic post-generation check on the model's explanation, applied against the same retrieved evidence.
3. A reproducible evaluation harness that reports a constrained (curated) benchmark, a larger retrospective corpus, and the limits of each.

The novelty statement in §6 is written to this scope. Claims beyond it are not supported.

## 2. Component inventory: what already exists

| Component in VRS / Vulture-AI | Existing source | Status |
|---|---|---|
| CVSS base severity as an input | FIRST CVSS v3.1 and v4.0 (verified R1, R2) | Existing. Vulture-AI uses the numeric base score, not a v4 vector. |
| EPSS probability as an exploitation-likelihood input | FIRST EPSS (verified R3) | Existing. FIRST states EPSS "is not a complete risk score". |
| KEV listing as an exploitation-evidence input | CISA KEV (verified R5) | Existing. CISA recommends it as "an input" to a framework such as SSVC. |
| Exposure and asset-criticality as context | CVSS v4.0 Environmental metrics (CR/IR/AR, Modified Base metrics; R1); CVSS v3.1 Environmental (R2); SSVC "mission prevalence" and "public well-being impact" (R8) | Existing. These are conceptually the same context factors, in different parameterizations. |
| Weighted linear combination of indicators | Common in risk scoring. CVSS v3 and v4 formulas are themselves weighted combinations (R1, R2). | Existing practice. Not novel. |
| "KEV-first" ordering | CISA's own guidance treats KEV as the top priority (R5, R6). | Existing practice. |
| Combining CVSS + EPSS + KEV | FIRST says EPSS should be combined with CVSS and KEV and that "KEV should take precedence" (R3). | Existing guidance. The CVSS+EPSS+KEV baseline in the paper is a direct implementation of an equal-weight version. |
| Context-aware (asset-aware) prioritization | CVSS Environmental metrics (R1, R2); SSVC (R8, R9) | Existing concept. No primary source for a specific "context-aware enterprise" method was found (see VERIFIED_REFERENCES §4). |
| Pydantic-validated LLM output | general software practice | Existing. Not a research contribution. |
| Regex / keyword prompt-injection filter | general practice; the phrase list is ad hoc | Existing as a technique. Shown in Phase 4 to be easily evaded and to produce false positives. |
| Score recomputed outside the LLM | general principle of separation of duties | Existing as a design principle. Vulture-AI's implementation is an instance of it. |
| Spotlighting, StruQ, SecAlign | published defenses (R14, R15, R16) | Existing. These are stronger but different defenses. |

## 3. What is actually Vulture-AI's own

Based on the code, the following are specific to this system and can be described as contributions, with the scope stated:

1. **Integrated pipeline with recomputed authority.** `chat_with_validation` computes the authoritative VRS from the structured finding *after* the model call and overwrites any model-supplied score (`vulture_chatbot.py`, VRS block). The Phase 4 harness verified this on the real path (S01–S05). This is an engineering contribution: the separation is simple, but its specific form (recompute, do not trust, re-inject) is what the system does.
2. **A KEV priority floor.** After Phase 4, a KEV-listed (`urgent` bucket) finding cannot be displayed below `high`, regardless of model output. This is a small, deterministic rule that was added in this revision. It applies only to the urgent bucket and does not constrain non-KEV priorities. Its value is limited: it fixes one field and does not address the model's explanation.
3. **A two-bucket ordering with deterministic tie-breaks.** The sort is (urgent before standard before unavailable), then descending VRS, then ascending CVE ID (`risk_engine.rank_findings`). This is documented and reproducible. It is a specification choice, not an algorithmic advance.
4. **An evaluation harness with explicit scope.** The repository reports the 41-record curated benchmark, the 500-record retrospective corpus, and the guardrail corpus separately, with stated limits (Phases 2–4). This matters for credibility, but it is methodology, not a new method.
5. **Explicit missing-data policy.** Missing CVSS yields an "unavailable" bucket and no score; missing EPSS, exposure, and criticality use stated defaults with logged uncertainty (`risk_engine.compute_vrs`). Documented, but not unique.

## 4. What is NOT Vulture-AI's contribution

- **The indicators.** CVSS, EPSS, KEV, exposure, and criticality are external or standard. The manuscript must not present them as new.
- **The weighted-sum form.** VRS is a linear combination with exploratory weights (`w_C=0.25, w_E=0.20, w_K=0.20, w_N=0.20, w_A=0.15`). Those weights were chosen by the authors without a validation set and are described as "exploratory" in the manuscript. They are not an empirically derived result.
- **The bucket override.** Prioritizing KEV-listed items is FIRST and CISA guidance (R3, R5, R6), not a new idea.
- **The superiority over CVSS-only.** The baseline comparison shows that adding EPSS, KEV, and context changes ranking on the authors' benchmark. This is expected because the reference labels use the same inputs (construct circularity, see TEMPORAL_AUDIT §4.1 and the manuscript's Threats to Validity).
- **Injection resistance.** The regex filter is not a defense in any strong sense (Phase 4: TPR 0.36, FPR 0.30 on a 48-case inspected set, and misses on paraphrases and Unicode). The manuscript's "tested signatures" wording is accurate. "Resistance to prompt injection" is not.
- **Any claim of state-of-the-art performance.** No comparison was run against SSVC's own decision tree, CVSS v4.0 scoring, or any published ML/LLM triage system. See §5.

## 5. Comparisons that have not been run

The novelty statement cannot rest on any comparison that is not in the repository. The following are **absent** and must not be implied:

- VRS against an implementation of the **SSVC decision tree** (CISA's or the SEI Coordinator tree). The authors' reference labels are *inspired by* SSVC, so SSVC itself is not evaluated.
- VRS against **CVSS v4.0** scores (CVSS-BT or CVSS-BE). Vulture-AI uses v3-style base scores; v4.0 scores are not computed.
- VRS against **ML-based or LLM-based triage**. No such baseline was built.
- VRS against **published context-aware prioritization** methods. None were located as verified primary sources.
- VRS on **prospective or historical** data (see TEMPORAL_AUDIT §5).

These gaps are the main limit on the novelty claim. A reviewer would reasonably ask whether a SSVC decision tree fed with the same inputs performs the same way; the repository cannot answer that.

## 6. Novelty statement (proposed)

> Vulture-AI does not propose new vulnerability indicators or a new scoring family. It combines CVSS base severity, FIRST EPSS, CISA KEV status, and deployment context (network exposure and asset criticality) in a deterministic weighted score with a KEV-first ordering. Its contribution is architectural: the authoritative score is computed by a deterministic component from structured inputs and is never produced or overwritten by the language model, and a deterministic validation step checks the model's explanation against the retrieved evidence. On a curated 41-record benchmark whose reference labels are author-assigned from an SSVC-inspired rubric, the combined score agrees more closely with those labels than the single-indicator baselines we evaluated; because the labels and the score share inputs, this agreement is evidence of construct consistency, not of predictive validity. We do not claim state-of-the-art performance, and we did not compare against SSVC's decision tree, CVSS v4.0 scores, or learned triage models.

## 7. Claims to remove or soften in the manuscript

| Current wording (manuscript) | Problem | Replace with |
|---|---|---|
| "Vulture-AI, an end-to-end ... framework that couples ... with ... a deterministic scoring heuristic" | acceptable, but the "novel" reading is implied elsewhere | keep, but do not describe as a new method |
| "outperforming CVSS-only ... and unweighted baselines" | the outperformance follows from shared inputs with the reference labels | "agreed more closely with author-assigned reference labels than the single-indicator baselines; this reflects shared inputs" |
| "designed to detect and reject tested prompt injection signatures" | acceptable wording ("tested") but the abstract elsewhere reads as general | keep "tested" and state the regex scope |
| "a deterministic, rule-based verification filter" as a contribution (Related Work) | a keyword filter is not a contribution to the prompt-injection literature | describe as a practical, limited check, and cite spotlighting/StruQ/SecAlign as stronger alternatives |
| "novel" language, if present in the rest of the manuscript | not supported | remove |

## 8. Questions for the authors (not answered by this audit)

1. Is there a prior, citable use of "recomputed authoritative score overwrites model output" in LLM security or vulnerability tooling? This audit did not find one through verified sources, but absence from this search is not proof of novelty. A targeted search is needed before claiming the architectural point as new.
2. Will the authors run an SSVC decision-tree baseline with the same inputs? Without it, the claim that VRS adds value over the standard tree is untested.
3. Will the reference labels be independently re-rated? Currently they are author-assigned, which is the main threat to any agreement-based result.
