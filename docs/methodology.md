# Vulture-AI Research & Evaluation Methodology

## 1. Vulture Risk Score (VRS) Formulation

The Vulture Risk Score is a deterministic linear weighting model normalized to a 0–100 scale:

$$\text{VRS} = 100 \times \left( w_C \cdot C + w_E \cdot E + w_K \cdot K + w_N \cdot N + w_A \cdot A \right)$$

### Default Weights (`vrs-v1`)
* $w_C = 0.25$: Normalized CVSS base score ($C = \text{cvss} / 10.0$)
* $w_E = 0.20$: FIRST EPSS probability ($E \in [0.0, 1.0]$)
* $w_K = 0.20$: CISA KEV status ($K \in \{0.0, 1.0\}$)
* $w_N = 0.20$: Network exposure ($N \in [0.0, 1.0]$)
* $w_A = 0.15$: Asset criticality ($A \in [0.0, 1.0]$)

$$\sum w_i = 0.25 + 0.20 + 0.20 + 0.20 + 0.15 = 1.00$$

### Categorical Bucket Policy
When `use_buckets=True`, findings listed in CISA KEV ($K = 1.0$ and $w_K > 0$) are assigned `bucket = "urgent"`, placing them in front of standard findings regardless of minor continuous score differences. Findings with missing CVSS are assigned `bucket = "unavailable"`, sorting behind all scored findings.

### Deterministic Tie-Breaking
When comparing findings, ties are broken deterministically:
1. Bucket tier (`"urgent"` > `"standard"` > `"unavailable"`)
2. Continuous numerical VRS score (descending)
3. Primary CVE identifier (alphabetical ascending, e.g. `CVE-2021-...` before `CVE-2023-...`)

---

## 2. Baseline Models

1. **CVSS-only**: Ranked strictly by CVSS base score descending. Missing CVSS ranks last.
2. **EPSS-only**: Ranked strictly by EPSS probability descending. Missing EPSS ranks last.
3. **KEV-first**: CISA KEV listed vulnerabilities ($1.0$) sort before unlisted items ($0.0$), with secondary sorting by CVSS base score.
4. **CVSS + EPSS + KEV (Equal Combination)**: Unweighted linear combination ($\frac{1}{3} C + \frac{1}{3} E + \frac{1}{3} K$).
5. **VRS Proposed (`vrs-v1`)**: The proposed model combining all 5 features with KEV urgent bucket override.

---

## 3. Ablation Methodology: Proportional Renormalization

To avoid ad-hoc or arbitrary manual weight redistributions during ablation, remaining active weights are proportionally rescaled to sum strictly to $1.0$:

$$w_j' = \frac{w_j}{\sum_{k \notin \text{ablated}} w_k}$$

### Evaluated Ablation Conditions
1. **Full VRS**: Baseline default weights.
2. **No EPSS** ($w_E = 0$): $w_C = 0.3125, w_K = 0.25, w_N = 0.25, w_A = 0.1875$.
3. **No KEV** ($w_K = 0$): $w_C = 0.3125, w_E = 0.25, w_N = 0.25, w_A = 0.1875$.
4. **No Environmental Context** ($w_N = 0, w_A = 0$): $w_C = 0.3846, w_E = 0.3077, w_K = 0.3077$.
5. **No Bucket Override** (`use_buckets=False`): Full weights evaluated purely by continuous score without the categorical KEV bucket override.

---

## 4. Evaluation Metrics

* **NDCG@K ($K \in \{5, 10, 15\}$)**: Normalized Discounted Cumulative Gain with exponential graded relevance:
  $$\text{DCG@K} = \sum_{i=1}^K \frac{2^{rel_i} - 1}{\log_2(i + 1)}, \quad \text{NDCG@K} = \frac{\text{DCG@K}}{\text{IDCG@K}}$$
* **Precision@K & Recall@K**: Evaluated at two decision thresholds:
  - Emergency Action ($\tau = 3$, Act tier, $N_{\text{relevant}} = 15$)
  - Actionable ($\tau = 2$, Act or Attend tiers, $N_{\text{relevant}} = 27$)
* **Spearman Rank Correlation ($\rho$)**: Monotonic correlation between predicted rank order and reference priority, computed using fractional mid-ranks for ties.
