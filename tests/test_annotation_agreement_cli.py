"""Unit tests for blind annotation sampler and inter-rater agreement calculator."""

import csv
from pathlib import Path

from experiments.revision.annotation.agreement import compute_agreement, fleiss_kappa
from experiments.revision.annotation.sample_for_annotation import generate_blind_annotation_files
import numpy as np


def test_blind_sheet_has_no_vrs_or_grade_leakage(tmp_path: Path):
    blind = tmp_path / "blind.csv"
    tmpl = tmp_path / "tmpl.csv"
    items = generate_blind_annotation_files(blind_path=blind, template_path=tmpl)
    assert len(items) == 20
    with open(blind, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["cve_id", "description"]
        rows = list(reader)
        assert len(rows) == 20
    with open(tmpl, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["rater_id", "cve_id", "grade", "confidence", "notes"]


def test_agreement_pairwise_and_fleiss(tmp_path: Path):
    r1 = tmp_path / "r1.csv"
    r2 = tmp_path / "r2.csv"
    r3 = tmp_path / "r3.csv"
    r1.write_text("rater_id,cve_id,grade,confidence,notes\nr1,C1,3,5,\nr1,C2,2,4,\nr1,C3,1,3,\nr1,C4,0,4,\n", encoding="utf-8")
    r2.write_text("rater_id,cve_id,grade,confidence,notes\nr2,C1,3,5,\nr2,C2,2,4,\nr2,C3,2,3,\nr2,C4,0,4,\n", encoding="utf-8")
    r3.write_text("rater_id,cve_id,grade,confidence,notes\nr3,C1,3,5,\nr3,C2,2,4,\nr3,C3,1,3,\nr3,C4,0,4,\n", encoding="utf-8")
    rep = compute_agreement([r1, r2, r3], is_synthetic_dry_run=True)
    assert rep["n_raters"] == 3
    assert rep["n_common_items"] == 4
    assert rep["pairwise"]["r1_vs_r2"]["percent_agreement"] == 0.75
    assert -1.0 <= rep["pairwise"]["r1_vs_r2"]["cohens_kappa"] <= 1.0
    assert -1.0 <= rep["fleiss_kappa"] <= 1.0
    assert fleiss_kappa(np.array([[3, 0, 0, 0], [0, 3, 0, 0]])) == 1.0
