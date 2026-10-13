# Vulture-AI: Comprehensive Research Audit, Hotfix & Restructuring Report

**Date**: 2026-10-14  
**Target Venue**: 7th International Conference on Computing and Informatics (ICCI 2026)  
**Branch**: `research-v2`  
**Evaluation Target**: Curated 41-Record Benchmark & Reproducibility Pipeline  
**Status**: Completed, Tested & Fully Verified  

---

## 1. Executive Summary

This report documents the end-to-end repository audit, scientific calibration, modular restructuring, and quality hardening applied to the **Vulture-AI** codebase. The primary objective was to transform the existing repository into a clean, reproducible, research-grade artifact suite suitable for double-blind submission to IEEE ICCI 2026.

All tasks were executed under strict peer-review and reproducible-science constraints:
* **Zero Fabrication**: No CVE data, rankings, metrics, citations, or tool outputs were invented.
* **Preserved Functionality**: The core deterministic risk engine, Nmap scanning pipeline, RAG guardrails, and historical results were preserved.
* **Rigorous Scientific Honesty**: Claims of "independent ground truth" were corrected to heuristic construct alignment with a CISA SSVC-inspired reference rubric.
* **Complete Reproducibility**: Unified end-to-end execution (`reproduce_all.py`), updated SHA-256 provenance hashes, and verified 6-page double-blind IEEE manuscript compilation.

---

## 2. Categorized Audit Checklist & Applied Fixes

| Severity | Component / Path | Evidence / Identified Issue | Applied Fix | Verification Command | Status |
|:---|:---|:---|:---|:---|:---:|
| **CRITICAL** | `data/benchmark/cves.csv`, `paper/manuscript.tex`, `README.md` | Contradiction between documentation claiming "41 real CVEs" vs non-existent IDs (`CVE-2024-99991`, `CVE-2024-99992`). | Explicitly identified and marked the 2 synthetic missing-data edge cases across all datasets, READMEs, scripts, and manuscript (39 real + 2 synthetic = 41 total). | `python generate_data.py` | **FIXED** |
| **CRITICAL** | `paper/manuscript.tex`, `README.md`, `REPRODUCIBILITY.md` | Methodological circularity: reference labels derived from SSVC share underlying features with VRS, yet were described as "independent ground truth". | Qualified labels as an author-curated reference rubric; disclosed construct circularity/alignment in methodology and threats to validity; disclaimed breach prediction. | Inspect Sections 3.2, 4.1, 5.1 of manuscript | **FIXED** |
| **HIGH** | `requirements.txt` | Incomplete dependencies: missing `numpy`, `scipy`, `matplotlib`, `pydantic`, `requests`, `pytest`; duplicate `flask-cors`. | Completely updated `requirements.txt` with versioned, non-redundant dependencies across runtime, scientific metrics, and testing. | `pip install -r requirements.txt` | **FIXED** |
| **HIGH** | `cve_matcher.py` | Fragile import hack: popped `"scanner"` from `sys.modules` and imported from `vulmap-pro`, coupling root to external subproject and `sqlalchemy`. | Embedded self-contained service normalization, CPE 2.3 URI builder, and CVSS parser directly in `cve_matcher.py`, completely removing `vulmap-pro` coupling. | `pytest tests/test_cve_matcher.py` | **FIXED** |
| **HIGH** | `experiments/evaluate_rag.py`, `rag_eval.json` | Mock schema mismatch: mock returned `reason` instead of `explanation`, causing Pydantic validation failure; `rag_eval.json` referenced old synthetic CVEs. | Rewrote mock to match `ChatbotResponse` schema; verified offline injection refusal and missing evidence handling; documented MockLLM fixture with explicit metadata. | `python experiments/evaluate_rag.py` | **FIXED** |
| **HIGH** | `paper/manuscript.tex`, `experiments/make_tables.py` | Ceiling effects at $K=10$ obscured model separation; misleading "7.1% gain" phrasing in manuscript. | Implemented multi-budget reporting ($K \in \{5, 10, 15\}$); added `multi_budget.tex`; corrected "7.1% gain" to exact absolute delta ("0.0706 increase in Spearman $\rho$"). | `python experiments/make_tables.py` | **FIXED** |
| **MEDIUM** | Root files & `data/benchmark/` | Checksum inconsistencies: stale MD5 hash `ab2b5f12...` and old SHA-256 hash `e2a3419a...` cited in documentation. | Computed and synchronized authoritative SHA-256 hash (`27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`) across all documentation and manifests. | `python generate_data.py` | **FIXED** |
| **MEDIUM** | Project Packaging & Automation | Missing `pyproject.toml`, outdated `Makefile`, and missing automated CI pipeline. | Created `pyproject.toml`, expanded `Makefile` with comprehensive research targets, and added `.github/workflows/tests.yml` for multi-version Python CI. | `make test`, `make reproduce` | **FIXED** |
| **MEDIUM** | Repository Governance & Docs | Missing `LICENSE`, `CITATION.cff`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.env.example`, and supplementary research docs. | Created complete governance suite and 6 dedicated architectural/methodological reference files in `docs/`. | Inspect `docs/`, `CITATION.cff` | **FIXED** |
| **LOW** | `experiments/evaluate_rag.py` | Missing random seed for sample selection. | Enforced `random.seed(42)` for deterministic reproducible sampling. | `python experiments/evaluate_rag.py` | **FIXED** |

---

## 3. Verified Experimental Results Summary

*All results reflect exact outputs generated by `experiments/reproduce_all.py` against the 41-record benchmark ($N=41$):*

### Comparative Baseline Performance
| Method | NDCG@5 | NDCG@10 | NDCG@15 | P@10 (Act) | R@10 (Act) | P@10 (Actionable) | R@10 (Actionable) | Spearman ($\rho$) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **CVSS-only** | 0.8062 | 0.7563 | 0.7855 | 0.6000 | 0.4000 | 1.0000 | 0.3704 | 0.7357 |
| **EPSS-only** | 1.0000 | 0.9217 | 0.8878 | 0.8000 | 0.5333 | 1.0000 | 0.3704 | 0.8237 |
| **KEV-first** | 0.8062 | 0.7945 | 0.8407 | 0.7000 | 0.4667 | 1.0000 | 0.3704 | 0.8247 |
| **CVSS+EPSS+KEV** | 0.9250 | 0.9513 | 0.9373 | 0.9000 | 0.6000 | 1.0000 | 0.3704 | 0.8800 |
| **VRS Proposed (`vrs-v1`)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.6667** | **1.0000** | **0.3704** | **0.9488** |

### VRS Ablation Study (Proportional Renormalization Policy)
| Variant | Active Weights ($w_C, w_E, w_K, w_N, w_A$) | Bucket Policy | NDCG@5 | NDCG@10 | NDCG@15 | P@10 (Act) | R@10 (Act) | Spearman ($\rho$) |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **VRS (Full Model)** | `0.25, 0.20, 0.20, 0.20, 0.15` | Urgent Enabled | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 | 0.9488 |
| **VRS (No EPSS)** | `0.3125, 0.00, 0.25, 0.25, 0.1875` | Urgent Enabled | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 | 0.9575 |
| **VRS (No KEV)** | `0.3125, 0.25, 0.00, 0.25, 0.1875` | Urgent Disabled | 1.0000 | 0.9581 | 0.9675 | 0.9000 | 0.6000 | 0.9451 |
| **VRS (No Context)** | `0.3846, 0.3077, 0.3077, 0.00, 0.00` | Urgent Enabled | 0.9250 | 0.9513 | 0.9130 | 0.9000 | 0.6000 | 0.8782 |
| **VRS (No Buckets)** | `0.25, 0.20, 0.20, 0.20, 0.15` | Score-Only | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6667 | 0.9535 |

---

## 4. Verification Checklists & Commands Actually Executed

1. **Benchmark Schema & Provenance**:
   ```bash
   python generate_data.py
   # Outcome: [PASS] 41 records validated (39 real public + 2 synthetic edge cases)
   # SHA-256: 27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e
   ```

2. **Automated Test Suite**:
   ```bash
   pytest -v
   # Outcome: 55 passed, 1 skipped (test_full_pipeline skipped; requires network/root nmap)
   ```

3. **End-to-End Reproducibility Pipeline**:
   ```bash
   python experiments/reproduce_all.py
   # Outcome: Baselines, ablations, metrics, LaTeX tables, plots, and manifest generated successfully
   ```

4. **Deterministic RAG Guardrail Evaluation**:
   ```bash
   python experiments/evaluate_rag.py
   # Outcome: Prompt injection neutralized, missing evidence handled, schema validated
   ```

5. **Manuscript PDF Compilation**:
   ```bash
   cd paper && pdflatex -interaction=nonstopmode manuscript.tex && bibtex manuscript && pdflatex -interaction=nonstopmode manuscript.tex && pdflatex -interaction=nonstopmode manuscript.tex
   # Outcome: manuscript.pdf compiled cleanly (6 pages, 465,344 bytes, IEEE double-blind format)
   ```

6. **Submission Reproducibility Package**:
   ```bash
   tar -czvf /tmp/vulture_ai_reproducibility.tar.gz \
       --exclude-vcs \
       --exclude='*.pyc' \
       --exclude='*__pycache__*' \
       --exclude='*.pytest_cache*' \
       --exclude='*data/cache*' \
       --exclude='*data/raw/nmap/*.xml' \
       --exclude='*paper/*.aux' \
       --exclude='*paper/*.log' \
       --exclude='*paper/*.out' \
       --exclude='*paper/*.bbl' \
       --exclude='*paper/*.blg' \
       --exclude='*venv*' \
       --exclude='*.env' \
       --exclude='*.tar.gz' \
       . && mv /tmp/vulture_ai_reproducibility.tar.gz ./vulture_ai_reproducibility.tar.gz
   # SHA-256: 201e0c39fea5a80243c32feb0b2031cad99e37797426a89f712ffbaa842def97 (Size: ~1.8 MB)
   ```

7. **Whitespace & Diff Verification**:
   ```bash
   git diff --check
   # Outcome: 0 whitespace errors or formatting defects
   ```

---

## 5. Final Directory Structure

```
Vulture-AI/
├── .env.example                               # Documented environment variable template
├── .github/
│   └── workflows/
│       └── tests.yml                          # Multi-version CI workflow (Python 3.10, 3.11)
├── .gitignore                                 # Clean ignore rules for caches, secrets, and builds
├── app.py                                     # Flask REST API server with target allowlist
├── AUDIT_REPORT.md                            # Comprehensive research methodology audit report
├── CHANGELOG.md                               # Version history adhering to Keep a Changelog
├── CITATION.cff                               # Machine-readable academic citation metadata
├── CONTRIBUTING.md                            # Development workflow and research ethics guide
├── cve_matcher.py                             # Self-contained CPE 2.3 normalizer and CVE matcher
├── data/
│   └── benchmark/
│       ├── cves.csv                           # 41-record benchmark dataset (39 verified + 2 synthetic)
│       └── README.md                          # Dataset card and synthetic record disclosure
├── docs/
│   ├── architecture.md                        # System architecture, functional modules, and diagrams
│   ├── dataset_card.md                        # Dataset schema, threat tiers, and source feeds
│   ├── limitations.md                         # Detailed threats to validity, circularity, and ceiling effects
│   ├── methodology.md                         # VRS formulation, ablation policies, and metric math
│   ├── reproducibility.md                     # Step-by-step deterministic reproduction guide
│   └── threat_model.md                        # Threat model: injection vectors, SSRF defense, guardrails
├── evaluate_rag.py                            # Root deterministic RAG assistant demonstration
├── evidence_validator.py                      # Regex prompt injection filter and numeric float validator
├── experiments/
│   ├── compute_metrics.py                     # Multi-budget NDCG and mid-rank Spearman computation
│   ├── config.json                            # Verified experiment settings, weights, and SHA-256 hash
│   ├── evaluate_rag.py                        # Deterministic RAG guardrail evaluation runner
│   ├── make_tables.py                         # Publication LaTeX tables and empirical ranking scatter plots
│   ├── metrics.py                             # Pure metric calculation functions (scipy tie-corrected)
│   ├── reproduce_all.py                       # Unified end-to-end experiment reproduction runner
│   ├── results/
│   │   ├── ablation.json                      # Per-variant ablated rankings under proportional rescaling
│   │   ├── baselines.json                     # Per-record baseline model predictions
│   │   ├── figures/ranking_comparison.png     # Empirical ranking comparison scatter plot
│   │   ├── metrics.json                       # Machine-readable multi-budget metric outputs
│   │   ├── metrics_table.md                   # Markdown comparison tables (K=10 and multi-budget)
│   │   ├── rag_eval.json                      # Deterministic RAG evaluation results
│   │   ├── reproducibility_manifest.json      # Environment versions, weights, and execution manifest
│   │   └── tables/                            # LaTeX comparison tables (main, multi-budget, ablation)
│   ├── run_ablation.py                        # Proportional weight ablation runner
│   └── run_baselines.py                       # Baseline prioritization model runner
├── generate_data.py                           # Benchmark integrity checker and SHA-256 validator
├── HOTFIX_REPORT.md                           # This comprehensive hotfix report
├── LICENSE                                    # Copyright notice and license selection advisory
├── Makefile                                   # Automation targets (test, reproduce, paper, clean)
├── paper/
│   ├── IEEEtran.cls                           # Official IEEE conference LaTeX document class
│   ├── IEEEtran.bst                           # IEEEtran BibTeX bibliography style
│   ├── manuscript.pdf                         # Compiled 6-page double-blind IEEE conference paper
│   ├── manuscript.tex                         # Complete LaTeX paper source (anonymous metadata)
│   ├── README.md                              # Compilation guide & double-blind transition notes
│   └── references.bib                         # Verified academic bibliography
├── pyproject.toml                             # Modern Python packaging metadata and tool configurations
├── pytest.ini                                 # Pytest execution configuration
├── README.md                                  # Complete research-grade project README (17 sections)
├── requirements.txt                           # Versioned, non-redundant dependencies
├── requirements-lock.txt                      # Locked dependency versions for exact environment replication
├── retrieval.py                               # Structured evidence formatter and lookup engine
├── risk_engine.py                             # Deterministic VRS scoring engine and tie-break sorter
├── scanner.py                                 # Nmap execution wrapper with allowlist enforcement
├── SECURITY.md                                # Vulnerability reporting and responsible disclosure policy
├── tests/
│   ├── integration/test_end_to_end.py         # Full pipeline integration test (network marked)
│   ├── test_api_failure.py                    # NVD API error and network outage resilience tests
│   ├── test_app.py                            # Flask API route tests
│   ├── test_benchmark.py                      # Benchmark schema, score bound, and edge-case tests
│   ├── test_cve_matcher.py                    # CPE matching, caching, and enrichment tests
│   ├── test_evidence_validator.py             # Attribution, numeric parity, and injection detection tests
│   ├── test_metrics.py                        # Metric validation, tied mid-ranks, and hand calculations
│   ├── test_missing_epss.py                   # Missing EPSS graceful degradation tests
│   ├── test_retrieval.py                      # Exact and hybrid retrieval tests
│   ├── test_risk_engine.py                    # VRS determinism, KEV overrides, and boundary tests
│   ├── test_scanner.py                        # Target allowlist rejection and timeout tests
│   └── test_stale_intel.py                    # Cache TTL and stale threat intelligence tests
├── threat_intel.py                            # NVD v2.0, FIRST EPSS, and CISA KEV fetchers
├── vulture_ai_reproducibility.tar.gz          # Standalone clean reproduction archive
└── vulture_chatbot.py                         # LiteLLM router and Pydantic schema validation envelope
```

---

## 6. Open Actions for Repository Owner

1. **Formal License Applied**:
   - `LICENSE` has been updated to the official **Apache License 2.0** text, with `pyproject.toml` and `README.md` consistently synchronized.
2. **Security Contact Configuration**:
   - `SECURITY.md` directs vulnerability reporters to GitHub Security Advisories. If an institutional security email is desired, it should be configured in repository settings.
3. **Double-Blind Anonymity**:
   - The manuscript (`paper/manuscript.tex` and `paper/manuscript.pdf`) is currently formatted as double-blind anonymous (`\author{\IEEEauthorblockN{Anonymous Author(s)}}` with PDF author metadata set to `Anonymous Author(s)`). Once accepted or when submitting to a single-blind track, real author affiliations should be unmasked.
4. **Git Remote Push**:
   - In accordance with safety policies, commits must be pushed manually by the owner:
     ```bash
     git push origin research-v2
     ```
