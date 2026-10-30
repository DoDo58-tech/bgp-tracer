"""Test the paper verification aggregator.

``scripts/verify_paper.py`` runs every paper-facing gate in one place.
This test checks that the aggregator exists, that every gate it names is
a script that is present, and that the aggregator itself passes on the
current tree.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "verify_paper.py"


def test_every_named_gate_exists():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_paper", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod.GATES, "the aggregator must name at least one gate"
    for name, cmd in mod.GATES:
        gate = Path(cmd[1])
        assert gate.exists(), f"gate {name!r} names a missing script: {gate}"
        assert gate.suffix == ".py", f"gate {name!r} is not a Python script"


def test_aggregator_passes_on_current_tree():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), timeout=600,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "all" in proc.stdout and "passed" in proc.stdout


def test_aggregator_reports_a_failing_gate():
    """A gate that fails must make the aggregator fail."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_paper", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    failing = (mod.GATES[0][0], [sys.executable, "-c", "raise SystemExit(1)"])
    original = mod.GATES
    try:
        mod.GATES = [failing]
        assert mod.main() == 1
    finally:
        mod.GATES = original
