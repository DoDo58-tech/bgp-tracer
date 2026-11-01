"""Tests for the paper/artefact number cross-check.

``scripts/check_paper_numbers.py`` derives each headline number from the
artefact that produced it and looks for it in the paper source.  These
tests exercise the gate itself: that it passes on the current tree, and
that it fails when a number is missing from the paper.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "check_paper_numbers.py"


def run():
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT),
    )


def test_gate_passes_on_current_tree():
    proc = run()
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_gate_reports_a_missing_number(tmp_path):
    """Removing a headline number from the paper must fail the gate."""
    import shutil

    paper = tmp_path / "paper"
    shutil.copytree(PROJECT_ROOT / "docs" / "paper", paper)
    target = paper / "section6_evaluation.tex"
    text = target.read_text()
    drifted = text.replace("Empty traffic buckets        & 37",
                            "Empty traffic buckets        & 38")
    assert drifted != text, "the paper no longer contains the expected string"
    target.write_text(drifted)

    env = dict(os.environ)
    env["BGP_TRACER_PAPER_DIR"] = str(paper)
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), env=env,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "MISS" in proc.stdout


def test_percent_uses_exact_rounding():
    """A rate of 0.1225 must print as 12.3%, not 12.2%."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_paper_numbers", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod.percent(0.1225) == "12.3%"
    assert mod.percent(0.03) == "3.0%"
    assert mod.percent(0.07) == "7.0%"
    assert mod.percent(0.0067) == "0.7%"
