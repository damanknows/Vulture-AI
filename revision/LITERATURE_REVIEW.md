# Literature Review and Comparison Matrix

Scope: the systems and sources that Vulture-AI is compared against. Every source is listed in `VERIFIED_REFERENCES.md` with its verification status. Entries marked **not verified** are not used to support a claim here.

## 1. Vulnerability severity and threat intelligence

### 1.1 CVSS (v3.1 and v4.0)
- **Sources:** R1 (v4.0), R2 (v3.1).
- **What it measures:** Base (intrinsic severity), with optional Threat (v4.0: E; v3.1: E/RL/RC) and Environmental metrics. Supplemental metrics (v4.0) do not change the score.
- **Environmental context:** both versions include Environmental metrics that account for security controls and the importance of the asset (CVSS v3.1 §4 "Environmental Metrics"; CVSS v4.0 Environmental group, including CR/IR/AR and Modified Base metrics). **CVSS therefore does include environmental context**, as an optional consumer-applied layer.
- **Limitations stated by FIRST:** the Base score "assumes the reasonable worst-case impact across different deployed environments"; "Threat and Environmental information is available to only the end consumer".
- **Relationship to Vulture-AI:** Vulture-AI's `C` is the CVSS base number; its `N` and `A` terms are a simpler version of CVSS Environmental context. This overlap is important (see the CVSS v4.0 comparison in §7).

### 1.2 EPSS
- **Sources:** R3 (FIRST program and FAQ), R4 (methodology paper: venue unverified).
- **What it measures:** probability of observed exploitation activity in the next 30 days; daily; percentile also provided.
- **Stated limitations (FIRST FAQ):** "EPSS is not a complete risk score"; it does not account for "any context for specific instances" or "compensating controls"; it is "part of a risk calculation"; "recent exploitation activity" does not change the score.
- **Relationship to Vulture-AI:** VRS uses EPSS as `E`. FIRST's explicit statement that EPSS is not a complete risk score supports describing VRS as a composite that uses EPSS, not as EPSS-based risk.

### 1.3 CISA KEV
- **Sources:** R5 (catalog), R6 (BOD 22-01, revoked), R7 (BOD 26-04, not read).
- **What it measures:** CVEs with reliable evidence of exploitation in the wild, plus remediation guidance (CISA's three criteria).
- **Stated limitations (CISA FAQ):** absence "does not indicate ... non-exploitation"; listing "does not indicate that CISA is observing current active exploitation"; the catalog "should not be the only factor".
- **Relationship to Vulture-AI:** VRS's `K` term and urgent bucket use KEV. CISA's own guidance recommends KEV as an input to a framework such as SSVC, which supports the design and also explains why KEV-first baselines are strong on this benchmark.

## 2. Context-aware vulnerability prioritization

- **Verified sources:** the CVSS Environmental metric groups (R1, R2) and the SSVC decision values (R8, R9).
- **Not located:** a verified primary source for a specific "context-aware enterprise" prioritization method. Per the task, none is cited.
- **Relationship to Vulture-AI:** the closest verified analogues are CVSS Environmental metrics (the consumer-applied modification of CVSS) and SSVC "mission prevalence" and "public well-being impact". Vulture-AI's exposure and criticality inputs are a simplified form of the same idea.

## 3. SSVC and decision-based vulnerability management

- **Sources:** R8 (CISA SSVC page, verified), R9 (SEI report: **not verified**).
- **What it is (per CISA):** a decision-tree method producing Track, Track*, Attend, or Act from five inputs: exploitation status, technical impact, automatable, mission prevalence, public well-being impact. CISA "uses its own SSVC decision tree model" and says it "closely resembles the standard SSVC Coordinator tree".
- **Relationship to Vulture-AI:** the reference labels are SSVC-*inspired* and were assigned by the authors. Vulture-AI does not implement the SSVC tree. An SSVC-tree baseline is the most important missing comparison (see NOVELTY_AUDIT §5).

## 4. ML and LLM vulnerability triage

- **Verified sources:** EPSS (R3, R4) is itself an ML model for exploitation probability. Its methodology paper (R4) is unverified in venue.
- **Not located:** verified primary sources for LLM-based vulnerability triage or ML-based triage beyond EPSS. The manuscript's Related Work does not currently cite any such source. The revision should either add verified sources or state that the comparison is out of scope.
- **Relationship to Vulture-AI:** Vulture-AI's assistant is an LLM-based triage explanation tool. It is evaluated only for guardrail behavior (Phase 4), not for triage accuracy against an LLM baseline.

## 5. RAG security and prompt-injection defenses

- **Verified sources:** Lewis et al. (R11, RAG), Greshake et al. (R12, indirect prompt injection; venue unverified), Liu et al. (R13, benchmark), Hines et al. (R14, spotlighting), Chen et al. (R15, StruQ), Chen et al. (R16, SecAlign).
- **What they show:** indirect prompt injection is a real threat to retrieval-based systems (R12); defenses include input-channel separation (R15), provenance marking (R14), and training-time preference optimization (R16). Each reports its own evaluation; none is independently replicated here.
- **Relationship to Vulture-AI:** Vulture-AI uses a deterministic keyword filter over retrieved content (`evidence_validator.py`). Phase 4 measured its limits: 9 of 25 attacks blocked (TPR 0.36) and 7 of 23 benign items flagged (FPR 0.30) on the inspected set; it misses paraphrases and Unicode obfuscation and does not inspect the query, banners, or descriptions. The defensible position is that the filter is a narrow, auditable check and that stronger defenses (R14–R16) exist and are not implemented here.

---

## 6. Comparison matrix

Legend: **Y** = the source explicitly provides the feature (verified where cited). **P** = partial, or present only as an optional or consumer-applied layer. **N** = not provided by the source as far as verified. **?** = not verified for this comparison; no claim is made. A "N" means the source does not provide it *as far as the verified sources show*, not that the system could not be extended to do so.

| Dimension | CVSS v3.1 / v4.0 | EPSS | KEV-first | SSVC (CISA tree) | CVSS+EPSS+KEV (combo) | Context-aware prioritization (general) | ML / LLM triage | **Vulture-AI (VRS)** |
|---|---|---|---|---|---|---|---|---|
| Vulnerability-only indicators (intrinsic) | Y (Base) | N (uses CVSS as a feature, but outputs only exploitation probability) | N | N (decision uses exploitation and impact) | Y (C term) | ? | ? | Y (C term) |
| Environmental / deployment context | P (optional Environmental layer, consumer-applied) | N (FIRST: no environment context) | N | Y (mission prevalence, public well-being) | N | Y (by definition) | ? | Y (N and A terms) |
| Exploitation evidence (in the wild) | P (v4.0 Threat E; v3.1 E) | Y (forecast, not observation) | Y (confirmed in the wild) | Y (exploitation status) | Y (E and K terms) | ? | ? | Y (E and K terms) |
| Asset criticality | P (Environmental CR/IR/AR, consumer-applied) | N | N | Y (mission impact) | N | Y | ? | Y (A term, default 0.5 if missing) |
| Network exposure | P (v4.0 AV is base; Environmental Modified AV; v3.1 likewise) | N | N | P (inputs are tree-specific) | N | Y | ? | Y (N term) |
| Decision-tree logic | N (linear formula) | N (regression-type model) | N (rule-based ordering) | Y | N | ? | ? | N (linear score plus a two-bucket rule) |
| Deterministic ranking | Y (formula) | Y (daily model output) | Y | Y | Y | ? | N (generative) | Y (with explicit tie-break) |
| Generative explanation | N | N | N | N | N | ? | Y (typical) | Y (RAG assistant; separate from score) |
| Score integrity (score not writable by a model) | N/A | N/A | N/A | N/A | N/A | ? | ? | Y for the score; priority partly (Phase 4 floor) |
| Prompt-injection mitigation | N/A | N/A | N/A | N/A | N/A | ? | ? | P (keyword filter, measured limits) |
| Evaluation methodology reported | P (FIRST publishes spec; outcome evaluation not verified) | Y (held-out, published curves per FAQ) | N | N | N | ? | ? | P (author-curated labels; retrospective KEV concordance; limits stated) |

**Legend note on unsourced cells.** Cells marked as judgments in this section (not sourced to a fetched page) are: CVSS "outcome evaluation not verified"; ML/LLM "deterministic ranking: N (generative)" (a general characterization of generative output, not a source claim); and the "N" entries for SSVC and KEV-first on "Evaluation methodology", which describe these artifacts as they are used in this repository and were not separately surveyed.

### 6.1 Reading the matrix correctly

- **Context is not unique to Vulture-AI.** CVSS Environmental metrics (R1, R2) and SSVC (R8) both use deployment context. The claim is that VRS *combines* context with exploitation evidence in one linear score; it does not claim context is absent elsewhere.
- **EPSS is probabilistic, not a context score.** FIRST states it does not account for environment. Combining EPSS with context is the intended use FIRST describes ("Layer EPSS with local context").
- **KEV-first and the combo baseline are not new.** The paper's baselines implement guidance that already exists. They are useful comparators, not competing methods.
- **The matrix does not show that VRS is better.** It shows the features each system uses. Performance comparisons are in the Results section and carry the construct-circularity limits (NOVELTY_AUDIT §4).

## 7. CVSS v4.0 comparison (see also manuscript §G request)

CVSS v4.0 (R1) changes the framework in ways that matter for Vulture-AI:

**Overlaps with VRS features:**
- **Exploit maturity:** v4.0 *Threat* metric E ("Attacked", "Proof-of-Concept", "Unreported") is a consumer-supplied exploitation signal. VRS's `E` is EPSS, and VRS's `K` is KEV. v4.0 E is closest in concept to KEV plus PoC evidence, but it is a categorical value, not a probability. Vulture-AI does not use v4.0 E.
- **Environmental context:** v4.0 Environmental metrics (CR/IR/AR, Modified Base metrics including Modified AV) cover asset-importance and reachability context. VRS's `N` (exposure) and `A` (criticality) address the same ideas with continuous values.
- **Supplemental metrics:** v4.0 Automatable, Recovery, and Provider Urgency are extrinsic attributes that do not change the score. VRS does not use them. Automatable is close to SSVC's "automatable" input, which CISA lists (R8).

**Distinctions:**
- **Score type.** v4.0 produces a severity score (CVSS-B/BT/BE/BTE). VRS produces a priority score that includes EPSS and KEV, which CVSS does not contain. Combining CVSS-BE with EPSS and KEV is a different method from VRS, and it has not been evaluated here.
- **Attack Requirements (AT) and User Interaction levels** are v4.0 base metrics that VRS does not use. The benchmark's `cvss` column is a v3-style base score, so v4 AT/UI are not represented in the data.
- **Safety** (MSI:S, MSA:S) is a v4.0 environmental value for human-safety impact. VRS has no safety input.
- **Environmental metrics are optional** in v3.1 and always included with "Not Defined" defaults in v4.0. VRS uses fixed defaults (`N=0.5`, `A=0.5`) when context is missing, with a logged uncertainty; this is a documented but different policy.

**Implication for the manuscript:** the claim should be that VRS uses a v3-style base score plus EPSS, KEV, and simplified context. It should not state that VRS is "v4.0-compatible", and it should not say that CVSS "lacks environmental context" (it does not).

## 8. Gaps the literature review cannot close

1. No verified SSVC decision-tree implementation was evaluated.
2. No verified ML- or LLM-triage baseline was located or built.
3. The EPSS and Greshake venues are unverified.
4. BOD 26-04 (current federal directive) was identified but not read.
5. The SEI SSVC report could not be retrieved, so its exact citation is unverified.
