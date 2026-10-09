# Reproducibility Guide

## Environment Setup
- Python: 3.14.7
- OS: Linux
- Dependencies: See `requirements.lock` (generate via `pip freeze > requirements.lock`)
- Models: `ollama/llama3.2`

## Required Environment Variables
- `NVD_API_KEY`: Your NVD API key (allows 50 req/30s instead of 5 req/30s).
- `VULTURE_ALLOWED_TARGETS`: Comma-separated allowlist for Nmap (e.g., `127.0.0.1`).
- `OLLAMA_API_BASE`: If Ollama is remote, default is `http://localhost:11434`.

## Benchmark Snapshot
- Collection Date: 2026-10-09
- Size: 40 CVEs
- Generation command: `python generate_data.py`

## Running Experiments
1. **Baselines**: `python experiments/run_baselines.py`
2. **VRS (vrs-v1)**: `python experiments/run_vrs.py`
3. **RAG Evaluation**: `python experiments/evaluate_rag.py`
4. **Ablation**: `python experiments/run_ablation.py`
5. **Generate Tables**: `python experiments/make_tables.py`
*(Or simply run `make experiments` and `make tables`)*
