# ICCI 2026 Submission Checklist

## Formatting & IEEE Compliance
- [ ] **Template**: Verify IEEEtran is used with the `[conference]` option.
- [ ] **Page Limit**: Ensure manuscript does not exceed the ICCI 2026 page limit (usually 6-8 pages).
- [ ] **Anonymity**: Ensure authors are listed as "Anonymous Authors" and "Anonymous Institute" if double-blind review is required.
- [ ] **Columns**: Verify text is perfectly balanced on the final page (`\IEEEtriggeratref` or `flushend` package).

## Content & Figures
- [ ] **Missing Results**: Replace all `\todo{insert result: ...}` placeholders in `paper/manuscript.tex` with actual prose analyzing the tables.
- [ ] **Circular Evaluation Disclosure**: Add a paragraph to Section VII (Threats to Validity) disclosing that the synthetic dataset labels were generated using a rubric based on the same input features, limiting generalizability.
- [ ] **Random Seed**: Add `random.seed(42)` to `generate_data.py` and regenerate `cves.csv` so the data is frozen.

## Reproducibility Artifacts
- [ ] **Dependencies**: `requirements.lock` generated and committed.
- [ ] **Makefile**: `make test`, `make experiments`, `make tables`, and `make paper` all execute without errors.
- [ ] **Dataset**: Ensure `data/benchmark/cves.csv` is committed to git so reviewers don't have to run the generator.

## Final Submission
- [ ] Compile final `manuscript.pdf`.
- [ ] Zip repository into `vulture-ai-reproducibility.zip` (excluding `.git`, `__pycache__`, and large environment folders).
- [ ] Upload PDF and ZIP to the ICCI 2026 submission portal.
