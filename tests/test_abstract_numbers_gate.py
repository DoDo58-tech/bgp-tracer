"""Tests for the abstract and introduction number gate.

``scripts/check_abstract_numbers.py`` fails when a number quoted in the
abstract or the introduction drifts from the artefact that produced it.
These tests exercise the gate itself: that it passes on the current
tree, and that it actually fails when the paper and the artefact
disagree.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "check_abstract_numbers.py"


def run():
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )


def test_gate_passes_on_current_tree():
    proc = run()
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_gate_fails_on_a_drifted_abstract_number(tmp_path):
    """Corrupting a quoted number must fail the gate."""
    src = PROJECT_ROOT / "docs" / "paper" / "main.tex"
    text = src.read_text()
    drifted = text.replace("$9.7\\%$ to $0.7\\%$", "$99.7\\%$ to $0.7\\%$")
    assert drifted != text, "the paper no longer contains the expected string"

    bad = tmp_path / "main.tex"
    bad.write_text(drifted)
    # The gate reads from the paper directory, so point it at a tree
    # whose main.tex has been replaced.
    paper = tmp_path / "paper"
    paper.mkdir()
    (paper / "main.tex").write_text(drifted)
    (paper / "section1_intro.tex").write_text(
        (PROJECT_ROOT / "docs" / "paper" / "section1_intro.tex").read_text())

    env = dict(os.environ)
    env["BGP_TRACER_PAPER_DIR"] = str(paper)
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), env=env,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not found" in proc.stdout or "mismatch" in proc.stdout


def test_gate_reports_a_missing_artefact():
    """A missing artefact must fail the gate, not silently pass."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_abstract_numbers", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    try:
        mod.load("definitely_not_a_real_artefact.json")
    except SystemExit as exc:
        assert "missing artefact" in str(exc)
    else:
        raise AssertionError("expected a SystemExit for a missing artefact")
