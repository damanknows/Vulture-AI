# Contributing to Vulture-AI

Thank you for your interest in contributing to Vulture-AI. We welcome contributions that improve scientific rigor, algorithmic efficiency, test coverage, and documentation.

## Code of Conduct & Research Integrity

All contributors are expected to uphold the highest standards of scientific honesty:
- **No data fabrication**: Never invent vulnerability metrics, synthetic CVE IDs, or false experimental improvements.
- **Explicit labeling**: Distinguish verified public intelligence from synthetic or mocked test fixtures.
- **Reproducibility**: All algorithmic changes to ranking or scoring must be accompanied by updated deterministic tests.

## Development Workflow

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feat/your-improvement
   ```
2. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the complete test suite:
   ```bash
   make test
   ```
4. Verify benchmark schema and SHA-256 integrity:
   ```bash
   make benchmark-check
   ```
5. If modifying ranking logic or ablations, re-run experiments and verify artifacts:
   ```bash
   make reproduce
   ```

## Pull Request Guidelines

- Include regression tests for any bug fixes.
- Ensure all automated GitHub Actions checks pass.
- Maintain documentation integrity: update relevant documentation in `docs/` and `README.md` if interfaces or metrics change.
