# Paper Compilation Guide

This directory contains the IEEE-format conference manuscript for Vulture-AI submitted to IEEE ICCI 2026.

## Building the PDF

Ensure you have `pdflatex` and `bibtex` installed (e.g., `texlive-latex-base`, `texlive-fonts-recommended`, `texlive-latex-extra` on Debian/Ubuntu).

From the root directory:
```bash
make paper
```

Or directly from the `paper/` directory:
```bash
pdflatex -interaction=nonstopmode manuscript.tex
bibtex manuscript
pdflatex -interaction=nonstopmode manuscript.tex
pdflatex -interaction=nonstopmode manuscript.tex
```

The compiled output will be generated at `paper/manuscript.pdf` (6 pages, IEEE double-column format).

## Double-Blind Review Notice

For initial review, the paper is configured for **double-blind submission**:
- Author names and institutional affiliations are blinded (`Anonymous Author(s)`).
- PDF document metadata is anonymized via `\hypersetup`.
- Repository and code references are blinded or linked to the anonymized reproducibility package.
- All benchmark metrics, tables, and ablation figures match the exact frozen artifacts in `experiments/results/`.

## Camera-Ready Transition (Post-Acceptance)

Upon acceptance:
1. Replace `Anonymous Author(s)` in `paper/manuscript.tex` with official author names, affiliations, and email addresses.
2. Update the corresponding `\hypersetup` author metadata.
3. Unmask acknowledgments or grant numbers if applicable.
4. Add the public GitHub repository URL.
