# Vulture-AI Reproduction Guide

## Requirements
* **Python**: 3.10, 3.11, 3.12, or 3.14
* **Packages**: Defined in `requirements.txt`
* **LaTeX (optional)**: `pdflatex` and `bibtex` (required only for building `manuscript.pdf`)

## Step-by-Step Reproduction

### 1. Environment Setup
```bash
git clone https://github.com/damanknows/Vulture-AI.git
cd Vulture-AI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Benchmark Integrity Check
Verify that the benchmark file is unaltered and matches the authoritative SHA-256 hash:
```bash
python generate_data.py
# Or via Makefile:
make benchmark-check
```
**Expected Output**:
- Record Count: 41 records (39 real public CVEs + 2 synthetic missing-data edge cases)
- SHA-256 Hash: `27979cc0029e3d383dc4380c5ab991c4774d15539f5f3058f9ffb7f007416b5e`

### 3. Run Automated Tests
Execute the offline test suite (55 tests):
```bash
pytest -v
# Or via Makefile:
make test
```

### 4. Execute Full Experimental Pipeline
Run the unified experiment runner to reproduce all baseline rankings, ablation variants, metrics, and manifest:
```bash
python experiments/reproduce_all.py
# Or via Makefile:
make reproduce
```
This executes:
1. `experiments/run_baselines.py` -> `experiments/results/baselines.json`
2. `experiments/run_ablation.py` -> `experiments/results/ablation.json`
3. `experiments/compute_metrics.py` -> `experiments/results/metrics.json`, `experiments/results/metrics_table.md`
4. `experiments/make_tables.py` -> `experiments/results/tables/main_comparison.tex`, `multi_budget.tex`, `ablation.tex`, `ranking_comparison.png`
5. Records environment metadata -> `experiments/results/reproducibility_manifest.json`

### 5. Run RAG Guardrail Evaluation
```bash
python experiments/evaluate_rag.py
```
Output saved to `experiments/results/rag_eval.json`.

### 6. Compile Conference Paper (PDF)
```bash
make paper
# Or directly:
cd paper && pdflatex -interaction=nonstopmode manuscript.tex && bibtex manuscript && pdflatex -interaction=nonstopmode manuscript.tex && pdflatex -interaction=nonstopmode manuscript.tex
```
Generates `paper/manuscript.pdf` (6 pages, IEEE double-blind format).
