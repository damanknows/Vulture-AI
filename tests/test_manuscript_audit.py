"""Unit tests for manuscript_audit.py."""

import subprocess
import sys
from pathlib import Path

from experiments.revision.manuscript_audit import run_manuscript_audit


def test_manuscript_audit_all_cells_pass():
    ok, checks = run_manuscript_audit()
    assert len(checks) >= 90
    assert ok is True, f"Failed cells: {[c for c in checks if not c[4]]}"


def test_manuscript_audit_fails_on_pending_status_string(tmp_path: Path):
    real_tex = Path("revision/ICCI2026_revision/manuscript_revised.tex").read_text(encoding="utf-8")
    fake_tex = tmp_path / "fake.tex"
    fake_tex.write_text(real_tex + "\n% PENDING\n", encoding="utf-8")
    ok, checks = run_manuscript_audit(tex_path=fake_tex)
    assert ok is False
    lint_failures = [c for c in checks if c[0] == "lint" and not c[4]]
    assert len(lint_failures) == 1
    proc = subprocess.run(
        [sys.executable, "-c", f"import sys; from pathlib import Path; from experiments.revision.manuscript_audit import run_manuscript_audit; ok, _ = run_manuscript_audit(Path({str(fake_tex)!r})); sys.exit(0 if ok else 1)"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
