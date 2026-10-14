# Vulture-AI Final Manuscript Finalization & Reproducibility Audit Report
**Conference**: IEEE ICCI 2026 (Double-Blind Track)  
**Date**: 2026-10-14  
**Git Branch**: `research-v2`  
**Base Commit**: `4ff99a1e1998b9f7f2b326d4ab54687873092899`  

---

## 1. Executive Summary
This audit confirms that the Vulture-AI research manuscript (`paper/manuscript.tex`), compiled artifact (`paper/manuscript.pdf`), dataset documentation, and figures have been brought to full submission readiness for IEEE ICCI 2026. All experimental claims, dataset composition details, scoring formulas, threat models, and limitations strictly reflect verified code and artifacts in the repository.

---

## 2. Evidence Map & Integrity Verification

### 2.1 Benchmark Datasets & Source Caches
| Dataset / Source Artifact | Verified Records | SHA-256 Checksum | Integrity Status |
| :--- | :---: | :--- | :--- |
| `data/benchmark/cves.csv` | 41 (39 real, 2 synthetic) | `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e` | **Intact & Frozen** |
| `data/benchmark/cves_enriched.csv` | 41 (39 real, 2 synthetic) | `666e040f01a491e58a9bf345a81e0a74d9deca1591f72f800872c5336bab9ff7` | **Intact** |
| `data/benchmark/cves_500.csv` | 500 (all unique real CVEs) | `009c8566f1fdc4ed38b453deb351025019adac1942c5c5c2c52c822f856129ef` | **Intact** |
| `data/benchmark/cves_500_enriched.csv` | 500 (25 CISA KEV positives) | `24dc74c14d4fd36ec3c3cd023cbd68072a454195ec37bacb368fe5955efe9517` | **Intact** |
| `data/benchmark/cves_500_manifest.json` | 500 records manifest | `80061f98fd979ec2ca1879df5db50ad8a06c58d6b63845fa9b34a86f5443cd7d` | **Intact** |
| `data/external/epss_cache_500.json` | 461 cached API entries | `a24c6b7d012ec8d86e0b1156b0843faca9cc826613fb892faa00e7cc484fa415` | **Intact (Score Date: 2026-10-13)** |
| `data/external/known_exploited_vulnerabilities.json` | 1,741 catalog records | `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28` | **Intact (Version: 2026.10.13)** |

### 2.2 Reconciled Experimental Metrics
1. **Curated Reference Benchmark ($N=41$, 39 Real + 2 Synthetic)**:
   - **VRS Proposed (vrs-v1)**: NDCG@5 = 1.0000, NDCG@10 = 1.0000, NDCG@15 = 1.0000, P@10 (Act) = 1.0000, R@10 (Act) = 0.6667 (theoretical maximum: $10/15$), Spearman $\rho = 0.9488$.
   - **CVSS-only**: NDCG@10 = 0.7563, P@10 (Act) = 0.6000, R@10 (Act) = 0.4000, Spearman $\rho = 0.7357$.
   - **EPSS-only**: NDCG@10 = 0.9217, P@10 (Act) = 0.8000, R@10 (Act) = 0.5333, Spearman $\rho = 0.8237$.
   - **KEV-first**: NDCG@10 = 0.7945, P@10 (Act) = 0.7000, R@10 (Act) = 0.4667, Spearman $\rho = 0.8247$.
   - **CVSS+EPSS+KEV (Combo)**: NDCG@10 = 0.9513, P@10 (Act) = 0.9000, R@10 (Act) = 0.6000, Spearman $\rho = 0.8800$.
   - **Ablation (No Context)**: Spearman $\rho$ drops to 0.8782 (absolute decrease of 0.0706), demonstrating that environmental exposure ($N$) and asset criticality ($A$) resolve fine-grained priority beyond vulnerability-only metrics.
2. **Expanded Backlog ($N=500$, $N_{\text{KEV}}=25$)**:
   - **CVSS-only**: Deteriorates to 44.0% recall at depth 25 (11/25 exploits captured), failing to prioritize 14 weaponized vulnerabilities in its top 25 positions.
   - **EPSS-only**: Achieves 88.0% recall at depth 25 (22/25 exploits captured).
   - **Threat-Aware Policies (VRS Proposed, Combined Baseline, KEV-first)**: Achieve 100.0% recall at depth 25 (25/25 exploits captured).

---

## 3. Critical Scientific Corrections Applied

1. **Dataset Construction vs. Natural Prevalence**:
   - Disclosed that the 500-CVE corpus is a constructed evaluation corpus combining 39 curated reference records (25 KEV-listed) with 461 deterministically sampled records from a restricted 2023–2024 domain (`cves/2023/0xxx` and `cves/2024/0xxx`), none of which matched the KEV snapshot.
   - Removed all assertions claiming that the 5.0% KEV proportion represents a natural empirical exploitation base rate or reproduces findings from Jacobs et al.
2. **Disentangled Jacobs et al. Citation**:
   - Retained the citation of Jacobs et al. (`jacobs2021epss`) strictly for the empirical fact that fewer than 5% of published CVEs exhibit wild exploitation in global telemetry.
   - Explicitly distinguished broad telemetry-observed exploitation from administrative catalog listing in CISA KEV.
3. **Structural Ceiling & Policy Concordance**:
   - Explicitly documented that because VRS (via its urgent bucket override), KEV-first, and Combined Baseline directly incorporate KEV status in prioritization while KEV membership serves as the evaluation ground truth, achieving 100% recall at depth 25 is an expected structural consequence of policy enforcement rather than independent predictive superiority.
4. **Data Provenance & Snapshot Transparency**:
   - Accurately documented that EPSS scores were drawn from a local cache (`data/external/epss_cache_500.json`, score date `2026-10-13`) rather than live runtime API queries.
   - Disclosed that absence from CISA KEV denotes unobserved in federal civilian reporting channels, not confirmed non-exploitation.
5. **Figure Modernization & Orphan Resolution**:
   - Implemented `experiments/make_figures.py` producing a publication-grade, dual-panel vector graphic (`paper/manuscript.pdf` embeds `experiments/results/figures/ranking_and_recall.pdf`).
   - Panel (a) illustrates empirical rank alignment on the curated benchmark ($N=41$), and Panel (b) illustrates retrospective Recall@K trajectories on the expanded backlog ($N=500$).
   - Resolved orphan figure status by citing and discussing both subpanels directly in Section V.A and Section V.C.

---

## 4. Verification & Validation Commands

| Verification Step | Command | Result / Exit Code |
| :--- | :--- | :--- |
| **Git Diff Check** | `git diff --check` | **Clean (Exit code 0, 0 whitespace/conflict warnings)** |
| **Automated Test Suite** | `pytest -v` | **80 passed, 1 skipped in 1.11s (Exit code 0)** |
| **Figure Generation** | `python3 experiments/make_figures.py` | **Exit code 0 (Generated vector PDF & 300-DPI PNG)** |
| **Table Generation** | `python3 experiments/make_tables.py` | **Exit code 0** |
| **LaTeX Compilation** | `cd paper && pdflatex -interaction=nonstopmode manuscript.tex` | **Exit code 0 (Compiled to exactly 6 pages)** |
| **Page Count Verification** | `pdfinfo paper/manuscript.pdf \| grep Pages` | **`Pages: 6` (Strictly IEEE conference compliant)** |

---

## 5. Modified Files in Working Tree
No files were committed or pushed. The modified files in the working tree are:
- `README.md`
- `data/benchmark/README.md`
- `docs/dataset_card.md`
- `docs/FINAL_MANUSCRIPT_AUDIT.md` (this report)
- `experiments/make_figures.py` (reproducible plotting script)
- `experiments/results/figures/ranking_and_recall.pdf` (vector figure)
- `experiments/results/figures/ranking_and_recall.png` (high-res raster figure)
- `paper/manuscript.tex` (final updated manuscript source)
- `paper/manuscript.pdf` (compiled 6-page submission PDF)
- `paper/manuscript.aux`, `paper/manuscript.log` (LaTeX build metadata)
