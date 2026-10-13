# Vulture-AI: Conference Submission Hotfix & Verification Report

**Date**: 2026-10-14  
**Target Venue**: IEEE ICCI 2026  
**Auditor**: Senior Cybersecurity Research Engineer  
**Branch**: `research-v2`  
**Status**: Completed & Verified  

---

## 1. Executive Summary

This report documents the targeted audit and hotfixes applied to the Vulture-AI repository to prepare the manuscript and experimental artifact suite for double-blind submission to IEEE ICCI 2026 under a strict deadline.

All fixes strictly adhere to the project constraints:
- **No architectural rebuilding**: The core risk scoring engine and RAG pipeline were preserved.
- **Zero data fabrication**: Real public vulnerability records were preserved; synthetic edge cases were explicitly disclosed rather than concealed.
- **Honest scientific framing**: Claims of "independent ground truth" were corrected to heuristic construct alignment with an SSVC-inspired triage rubric.
- **Full reproducibility**: All experiments re-executed deterministically, SHA-256 checksums updated, and LaTeX manuscript recompiled.

---

## 2. Audited Areas & Applied Fixes

### Priority 1: Benchmark Integrity & Provenance
* **Investigation of CVE-2024-99991 & CVE-2024-99992**:
  - Found: These two identifiers are not registered in the NIST NVD or assigned by any CVE Numbering Authority (CNA). They were inserted to evaluate missing-data policies (missing CVSS base score and missing EPSS probability, respectively).
  - Remediation: Rather than silently masquerading them as authentic public CVEs, both records were **explicitly marked as synthetic edge cases** in:
    - `data/benchmark/cves.csv` (source reference and description fields updated)
    - `data/benchmark/README.md` (prominent synthetic record disclosure banner)
    - `generate_data.py` (updated verification counts and output summary)
    - `paper/manuscript.tex` (abstract, methodology, and threats to validity)
  - Composition: Exactly **39 verified public CVEs** + **2 synthetic missing-data edge cases** = 41 total records.
* **Integrity Hash**:
  - Updated SHA-256 hash: `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`.
  - Replaced all stale MD5 references in `paper/manuscript.tex` and `experiments/config.json`.

### Priority 2: Scientific Validity & Claim Calibration
* **Ground-Truth Circularity Correction**:
  - Corrected wording claiming "independent ground truth". The reference labels derive from a manual application of the CISA SSVC decision tree. Because SSVC decisions are informed by exploitation telemetry (KEV, EPSS) and exposure—the same features evaluated by VRS—correlation with SSVC reflects **heuristic construct alignment**, not empirical proof of breach prevention.
  - Updated section title from *"Independent Ground-Truth Labeling"* to *"Reference Labeling via SSVC-Inspired Rubric"*.
  - Disclosed that environmental metrics ($N$: Network Exposure, $A$: Asset Criticality) reflect archetypal reference deployment profiles (edge gateway vs. internal server), not live organizational network telemetry.
* **Metric Difference Clarification**:
  - Replaced percentage claims (e.g., "7.1% gain") with exact absolute delta ("absolute increase of 0.0706 in Spearman rank correlation").

### Priority 3: Evaluation Completeness & Depth Sensitivity
* **Multi-Budget Evaluation**:
  - Evaluated rankings at $K=5$, $K=10$, and $K=15$ in `experiments/compute_metrics.py`, `experiments/make_tables.py`, and `paper/manuscript.tex`.
  - **Ceiling Effects Explained**: Because the dataset contains 15 Tier 1 (Act) records, any ordering of the top 10 positions containing only Tier 1 items achieves $\text{NDCG@10} = 1.0000$ and $\text{P@10} = 1.0000$. This explains why multiple variants (Full VRS, No EPSS, No Bucket Override) achieve identical top-10 scores.
  - **Depth Separation ($K=15$)**: At $K=15$, deeper budget evaluation reveals divergence:
    - VRS Proposed: $\text{NDCG@15} = 1.0000$
    - VRS (No KEV): $\text{NDCG@15} = 0.9675$
    - VRS (No Context): $\text{NDCG@15} = 0.9130$
    - EPSS-only: $\text{NDCG@15} = 0.8878$
    - CVSS-only: $\text{NDCG@15} = 0.7855$
* **EPSS Ablation Dynamics**:
  - Documented why removing EPSS slightly increases Spearman correlation ($\rho = 0.9575$ vs. $0.9488$): EPSS models rolling 30-day exploitation likelihood, assigning high probabilities to high-volume automated scanning noise (e.g. OpenSSH user enumeration `CVE-2018-15473`, EPSS 0.986) which SSVC classifies as *Defer* (rank 36). Ablating EPSS allows CVSS technical impact and exposure to push this finding further down, improving rank alignment with the SSVC rubric.

### Priority 4: Reproducibility & Test Coverage
* **Unit Testing**:
  - Created `tests/test_benchmark.py` (7 tests) verifying:
    - Zero duplicate CVE identifiers
    - Score ranges: CVSS $\in [0, 10]$, EPSS $\in [0, 1]$, KEV $\in \{0, 1\}$, exposure/criticality $\in [0, 1]$
    - Correct missing-data handling for `CVE-2024-99991` (vrs=None, bucket='unavailable') and `CVE-2024-99992` (EPSS=0.0 default, uncertainty flagged)
    - Rejection of invalid inputs and duplicates by validator
* **MockLLM Labeling**:
  - Explicitly labeled `evaluate_rag.py` and `tests/test_evidence_validator.py` as using deterministic offline MockLLM fixtures.
  - Added scope limitation in Section 4.3 and Threats to Validity noting that live red-teaming against frontier commercial models is deferred to future work.
* **Deterministic Seeds**:
  - Enforced `random.seed(42)` in `experiments/evaluate_rag.py`.

---

## 3. Verified Experimental Results Summary

### Comparative Baseline Performance ($N=41$)
| Method | NDCG@5 | NDCG@10 | NDCG@15 | P@10 (Act) | R@10 (Act) | Spearman ($\rho$) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| CVSS-only | 0.8062 | 0.7563 | 0.7855 | 0.6000 | 0.4000 | 0.7357 |
| EPSS-only | 1.0000 | 0.9217 | 0.8878 | 0.8000 | 0.5333 | 0.8237 |
| KEV-first | 0.8062 | 0.7945 | 0.8407 | 0.7000 | 0.4667 | 0.8247 |
| CVSS+EPSS+KEV | 0.9250 | 0.9513 | 0.9373 | 0.9000 | 0.6000 | 0.8800 |
| **VRS Proposed (vrs-v1)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.6667** | **0.9488** |

### VRS Ablation Study ($N=41$)
| Variant | NDCG@5 | NDCG@10 | NDCG@15 | P@10 (Act) | R@10 (Act) | Spearman ($\rho$) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| VRS (Full Model) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 | 0.9488 |
| VRS (No EPSS) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 | 0.9575 |
| VRS (No KEV) | 1.0000 | 0.9581 | 0.9675 | 0.9000 | 0.6000 | 0.9451 |
| VRS (No Context) | 0.9250 | 0.9513 | 0.9130 | 0.9000 | 0.6000 | 0.8782 |
| VRS (No Bucket Override) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 | 0.9535 |

---

## 4. Verification Checklists & Commands

1. **Benchmark Integrity Check**:
   ```bash
   python generate_data.py
   # Outcome: [PASS] 41 records validated (39 real public + 2 synthetic edge cases)
   # SHA-256: 27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e
   ```

2. **Automated Test Suite**:
   ```bash
   pytest -v
   # Outcome: 55 passed, 1 skipped (test_full_pipeline requires network/root nmap)
   ```

3. **Complete Experiment Pipeline**:
   ```bash
   python experiments/reproduce_all.py
   # Outcome: All baselines, ablations, metrics, tables, and manifest generated
   ```

4. **Manuscript PDF Compilation**:
   ```bash
   cd paper && pdflatex -interaction=nonstopmode manuscript.tex && bibtex manuscript && pdflatex -interaction=nonstopmode manuscript.tex && pdflatex -interaction=nonstopmode manuscript.tex
   # Outcome: manuscript.pdf compiled successfully (6 pages, IEEE double-blind format)
   ```

---

## 5. Submission Risks & Open Limitations

1. **Construct Circularity (Documented in Threats to Validity)**:
   - Evaluated against SSVC-derived labels. Because SSVC incorporates KEV, EPSS, and exposure, strong alignment reflects consistency with federal triage guidelines rather than independent predictive validation against enterprise incident logs. Reviewers will accept this when honestly stated, as now done in Sections 3.2, 4.1, and 5.1.
2. **MockLLM Guardrail Evaluation**:
   - The RAG guardrail evaluation in `evaluate_rag.py` uses a deterministic MockLLM fixture. It demonstrates that the architecture and validator correctly detect injection payloads and enforce numerical parity, but does not provide an empirical hallucination benchmark across live foundation models. This is now explicitly disclosed as a scope limitation in Section 4.3.
3. **Manual Push Required**:
   - The git remote uses HTTPS without stored credentials in the container environment. The changes must be committed locally and pushed manually by the user (`git push origin research-v2`).
