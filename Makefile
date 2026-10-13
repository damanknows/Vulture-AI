# Vulture-AI Research & Engineering Automation Makefile
# =======================================================

PYTHON ?= python3
PIP ?= pip
PYTEST ?= pytest

.PHONY: all help install install-dev test test-unit test-integration benchmark-check experiments reproduce tables paper clean

help:
	@echo "Vulture-AI Research & Engineering Commands:"
	@echo "  make install           Install core runtime dependencies"
	@echo "  make install-dev       Install runtime and development dependencies"
	@echo "  make test              Run all offline test suites (unit + metrics + benchmark)"
	@echo "  make test-integration  Run integration tests (requires network/scanner)"
	@echo "  make benchmark-check   Validate benchmark schema and SHA-256 hash"
	@echo "  make reproduce         Run unified end-to-end experimental reproduction"
	@echo "  make experiments       Run individual baseline, ablation, and RAG experiments"
	@echo "  make tables            Regenerate publication LaTeX tables and figures"
	@echo "  make paper             Compile IEEE conference manuscript PDF"
	@echo "  make clean             Remove caches, test files, and generated build artifacts"

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

benchmark-check:
	PYTHONPATH=. $(PYTHON) generate_data.py

test:
	PYTHONPATH=. $(PYTEST) tests/ -m "not integration" -v

test-unit:
	PYTHONPATH=. $(PYTEST) tests/test_*.py -v

test-integration:
	PYTHONPATH=. $(PYTEST) tests/integration/ -v

reproduce:
	PYTHONPATH=. $(PYTHON) experiments/reproduce_all.py

experiments:
	PYTHONPATH=. $(PYTHON) experiments/run_baselines.py
	PYTHONPATH=. $(PYTHON) experiments/run_ablation.py
	PYTHONPATH=. $(PYTHON) experiments/compute_metrics.py
	PYTHONPATH=. $(PYTHON) experiments/evaluate_rag.py
	PYTHONPATH=. $(PYTHON) experiments/make_tables.py

tables:
	PYTHONPATH=. $(PYTHON) experiments/make_tables.py

paper:
	cd paper && pdflatex -interaction=nonstopmode manuscript.tex && bibtex manuscript && pdflatex -interaction=nonstopmode manuscript.tex && pdflatex -interaction=nonstopmode manuscript.tex

clean:
	rm -rf data/cache/*
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
	rm -f paper/*.aux paper/*.log paper/*.out paper/*.bbl paper/*.blg
