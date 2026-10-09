# Paper Compilation Guide

## Building the PDF
Ensure you have `pdflatex` and `bibtex` installed (e.g. `texlive-full` on Ubuntu).
Run the following from the root directory:
```bash
make paper
```
Alternatively, from the `paper/` directory:
```bash
pdflatex manuscript.tex
bibtex manuscript
pdflatex manuscript.tex
pdflatex manuscript.tex
```

## Pre-Submission Checklist
- [ ] Fill in `\todo{insert result: explain NDCG@10 from main_comparison.tex}` with numerical analysis of the main comparison.
- [ ] Fill in `\todo{insert result: explain the zero impact of KEV weight due to policy override}` with the explanation from the ablation study.
- [ ] Add real author names and affiliations.
- [ ] Ensure `results/tables/*.tex` are properly formatted for page width.
