.PHONY: test experiments tables paper clean freeze

test:
	PYTHONPATH=. pytest tests/ -m "not integration"

experiments:
	PYTHONPATH=. python experiments/run_baselines.py
	PYTHONPATH=. python experiments/run_vrs.py
	PYTHONPATH=. python experiments/evaluate_rag.py
	PYTHONPATH=. python experiments/run_ablation.py

tables:
	PYTHONPATH=. python experiments/make_tables.py

paper:
	cd paper && pdflatex manuscript.tex && bibtex manuscript || true && pdflatex manuscript.tex && pdflatex manuscript.tex

clean:
	rm -rf data/cache/*
	rm -rf experiments/results/*.json
	rm -rf experiments/results/tables/*.tex
	rm -rf experiments/results/figures/*.png
	rm -rf paper/*.aux paper/*.log paper/*.out paper/*.bbl paper/*.blg paper/*.pdf

freeze:
	pip freeze > requirements.lock
