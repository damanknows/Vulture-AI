"""Unit tests for manuscript_audit.py."""

from experiments.revision.manuscript_audit import run_manuscript_audit


def test_manuscript_audit_all_cells_pass():
    ok, checks = run_manuscript_audit()
    assert len(checks) >= 90
    assert ok is True, f"Failed cells: {[c for c in checks if not c[4]]}"
