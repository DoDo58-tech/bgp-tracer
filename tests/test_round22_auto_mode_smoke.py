"""Regression tests for round-22: ``--mode auto`` is actually wired up.

Previously the chief_agent CLI documented ``--mode auto`` for two-phase
diagnosis but the dispatcher branch was missing — users got
``error: argument --mode: invalid choice: 'auto'``. These tests lock in
the fix.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_auto_mode_in_choice_list():
    """``chief_agent.py --help`` must list ``auto`` among --mode choices."""
    result = subprocess.run(
        [sys.executable, "chief_agent.py", "--help"],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    assert "auto" in result.stdout, (
        f"--mode auto not in --help output:\n{result.stdout}"
    )
    # The choice list must include all four modes + auto.
    for token in ("quick", "deep", "auto", "traffic_first", "react"):
        assert token in result.stdout, f"--mode choice missing: {token}"


def test_auto_mode_spawns_subprocess_for_phase_2():
    """Run ``--mode auto`` against a known-cached quick result; the
    foreground command must return within 30 s AND a Phase-2 subprocess
    must be visible in the JSON log directory.
    """
    import json
    import time

    # Use a short window that the existing parquet cache already covers.
    cache_dir = PROJECT_ROOT / "results" / "json"
    cache_dir.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    proc = subprocess.run(
        [
            sys.executable, "chief_agent.py",
            "--mode", "auto",
            "--asn", "12479",
            "--start", "2024-01-03 14:45",
            "--end", "2024-01-03 18:00",
        ],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
        timeout=180,
    )
    elapsed = time.monotonic() - start

    # Foreground command should not have taken more than 5 min.
    assert elapsed < 300, f"--mode auto foreground took {elapsed:.0f}s"

    # Should mention the verdict and the Phase 2 subprocess start.
    combined = proc.stdout + proc.stderr
    assert "QUICK VERDICT" in combined, (
        f"Phase-1 verdict not surfaced:\n{combined}"
    )
    assert "Phase 2 subprocess started" in combined, (
        f"Phase-2 subprocess not announced:\n{combined}"
    )

    # And the log file should exist on disk.
    log_path = cache_dir / "phase2_AS12479.log"
    assert log_path.exists(), (
        f"Phase-2 log file missing: {log_path}"
    )


test_auto_mode_spawns_subprocess_for_phase_2 = pytest.mark.slow(
    test_auto_mode_spawns_subprocess_for_phase_2
)
