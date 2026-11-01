"""Tests for the agent-section provenance gate.

``scripts/check_agent_paper_numbers.py`` fails when a number quoted in
the paper drifts from the artefact that produced it. These tests exercise
the gate itself: that it passes on the current tree, and that it actually
fails when the paper and the artefact disagree.

The gate searches the whole paper rather than one file, because a table
may live in the agent section or in the appendix.  A drift test therefore
copies the whole paper directory and corrupts one file inside it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "check_agent_paper_numbers.py"
PAPER = PROJECT_ROOT / "docs" / "paper"


def run(tex: Path, paper_dir: Path | None = None):
    env = dict(os.environ)
    if paper_dir is not None:
        env["BGP_TRACER_PAPER_DIR"] = str(paper_dir)
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--tex", str(tex)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), env=env,
    )


def drifted_paper(tmp_path: Path, filename: str, mutate):
    """Copy the paper, corrupt one file in the copy, return the copy."""
    paper = tmp_path / "paper"
    shutil.copytree(PAPER, paper)
    target = paper / filename
    text = target.read_text()
    changed = mutate(text)
    assert changed != text, "the mutation did not change the paper"
    target.write_text(changed)
    return paper


def test_gate_passes_on_current_tree():
    proc = run(PAPER / "section5b_agents.tex")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_gate_passes_on_the_appendix():
    """The appendix carries the ablation table and must be gated too."""
    proc = run(PAPER / "appendix.tex")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_gate_fails_on_a_drifted_number(tmp_path):
    """Corrupting a quoted number must fail the gate."""
    paper = drifted_paper(
        tmp_path, "section5b_agents.tex",
        lambda t: t.replace("$41{,}668$", "$99{,}999$"),
    )
    proc = run(paper / "section5b_agents.tex", paper)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "mismatch" in proc.stdout or "not found" in proc.stdout


def test_gate_fails_on_a_drifted_ground_truth_number(tmp_path):
    """The ground-truth table must be provenance-checked too.

    The three-arm table is the load-bearing claim of the agent section,
    so a hand-edited cell has to fail the gate exactly like the older
    latency and token medians do.
    """
    paper = drifted_paper(
        tmp_path, "section5b_agents.tex",
        lambda t: re.sub(
            r"(Full agent\s+& \$\d+/\d+\$ \(\$0\.\d+\$\))",
            "Full agent     & $25/99$ ($0.66$)",
            t, count=1,
        ),
    )
    proc = run(paper / "section5b_agents.tex", paper)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "gt_agent_full.json" in proc.stdout


def test_gate_fails_on_a_drifted_ablation_number(tmp_path):
    """The component-ablation table lives in the appendix and is gated."""
    paper = drifted_paper(
        tmp_path, "appendix.tex",
        lambda t: t.replace(
            "Multi-round reasoning & $0.647$",
            "Multi-round reasoning & $0.999$",
        ),
    )
    proc = run(paper / "appendix.tex", paper)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "component_ablation_summary.json" in proc.stdout


def test_gate_fails_when_an_artefact_is_missing():
    """A missing artefact must fail the gate, not silently pass."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_agent_paper_numbers", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    try:
        mod.load("definitely_not_a_real_artefact.json")
    except SystemExit as e:
        assert "missing artefact" in str(e)
    else:
        raise AssertionError("expected a SystemExit for a missing artefact")
