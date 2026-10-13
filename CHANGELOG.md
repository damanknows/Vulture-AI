# Changelog

All notable changes to the Vulture-AI project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-14 - Academic Research Submission Release

### Added
- Curated 41-record benchmark dataset (`data/benchmark/cves.csv`) comprising 39 verified public CVE records and 2 synthetic missing-data edge cases.
- Deterministic evaluation pipeline reporting NDCG@5, NDCG@10, NDCG@15, and mid-rank tie-corrected Spearman rank correlation.
- Proportional weight renormalization policy for ablation experiments ($w_j' = w_j / \sum_{k \neq \text{ablated}} w_k$).
- Architectural ablation evaluating continuous scoring without the categorical KEV bucket override (`use_buckets=False`).
- Multi-budget depth sensitivity analysis ($K \in \{5, 10, 15\}$).
- Unit test suite (`tests/test_benchmark.py`) validating zero duplicate CVEs, score bounds, and missing data policies.
- GitHub Actions CI workflow (`.github/workflows/tests.yml`) for automated multi-version Python testing.
- Comprehensive governance and documentation suite in `docs/` (`architecture.md`, `methodology.md`, `dataset_card.md`, `limitations.md`, `reproducibility.md`, `threat_model.md`).

### Changed
- Replaced synthetic `CVE-2024-100xx` generator with strict schema and SHA-256 integrity checker (`generate_data.py`).
- Completely decoupled `cve_matcher.py` from `vulmap-pro`, making service normalization and CPE building self-contained.
- Corrected scientific claims: replaced "independent ground truth" with CISA SSVC-inspired reference rubric.
- Updated all dataset checksums to SHA-256 (`27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`), deprecating stale MD5 references.
- Replaced "7.1% gain" relative phrasing with exact absolute increase of 0.0706 in Spearman rank correlation.
- Explicitly documented MockLLM offline testing fixtures in `evaluate_rag.py` and `tests/test_evidence_validator.py`.

### Fixed
- Fixed missing dependencies in `requirements.txt` (`numpy`, `scipy`, `matplotlib`, `pydantic`, `requests`, `pytest`).
- Resolved duplicate CVE identifier risk and missing-data handling assertions in test suite.
- Fixed schema parsing in `experiments/evaluate_rag.py` to match `ChatbotResponse`.

## [0.1.0] - 2026-08-25 - Initial Prototype Release
- Initial network scanner prototype, Flask API, and proof-of-concept VRS scoring formula.
