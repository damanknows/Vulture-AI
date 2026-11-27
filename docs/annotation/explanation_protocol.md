# Human Spot-Check Protocol for Explanation Quality

**Status:** `PENDING` (no human rater scores collected yet)

## 1. Sampling
- Draw a deterministic stratified sample of **10 items** from the 25 evaluated explanations in `experiments/revision/explanation/explanation_evaluation.csv` (seed `20261127`, balanced across Act/Attend/Track/Defer).

## 2. Raters & Blinding
- **Two independent SOC-analyst raters** (blind to VRS weights and to the LLM-judge scores) evaluate each explanation against its retrieved evidence record.

## 3. Rubric (1–5 Ordinal Scale)
1. **Factual consistency:** All stated CVE IDs, CVSS, EPSS, and KEV facts match the retrieved evidence.
2. **Evidence grounding:** No unsupported claims or fabricated remediation constraints.
3. **Actionability:** Remediation steps are concrete and useful for a SOC analyst.
4. **Clarity:** Clear, concise, and free of contradictions.

## 4. Inter-Rater Agreement
- Compute **quadratic-weighted Cohen's $\kappa$** (or two-way random-effects ICC) between the two human raters and between the human consensus and the LLM judges (`qwen-3.8-27b`, `gpt-oss-120b`).
- Record human ratings in `experiments/revision/guardrail/explanation_evaluation.csv` without altering automated judge logs.
