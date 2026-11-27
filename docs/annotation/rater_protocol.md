# Independent Rater Annotation Protocol (SSVC-Inspired Rubric)

**Status:** `PENDING` (annotation infrastructure complete; real independent rater data not yet collected)

## 1. Blinding Rules
- Raters receive **only** `experiments/revision/annotation/blind_sheet.csv` (`cve_id`, `description`) and `annotation_template.csv`.
- Raters must **not** be shown VRS scores, CVSS/EPSS/KEV values from `cves.csv`, or author-assigned `reference_priority` / `independent_label` grades.
- Raters work independently without discussing items prior to submitting their CSVs.

## 2. SSVC-Inspired Grading Rubric (`0`–`3`)
- **3 — Act:** Immediate/emergency remediation warranted (e.g., remote pre-auth RCE or actively exploited high-impact flaw).
- **2 — Attend:** Prompt scheduled remediation warranted (significant impact or plausible exploitation).
- **1 — Track:** Monitor and remediate in standard maintenance cycle (limited impact or high exploitation prerequisites).
- **0 — Defer:** Low urgency / informational / insufficient applicability evidence.

## 3. Confidence Scale (`1`–`5`)
- `1`: Guessing / insufficient description
- `3`: Moderate confidence
- `5`: High confidence

## 4. Agreement Computation
- Run `python3 -m experiments.revision.annotation.agreement rater_1.csv rater_2.csv ... --out agreement_results.json` to compute pairwise Cohen's $\kappa$, quadratic-weighted $\kappa$, percent agreement, confusion matrix, and Fleiss' $\kappa$ (for $\ge 3$ raters).
