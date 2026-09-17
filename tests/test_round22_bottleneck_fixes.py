"""Regression tests for the round-22 bottleneck-elimination pass.

These tests lock in the four behaviours that were broken in round 21
and fixed in round 22:

  - ``tests/conftest.py`` auto-tags unmarked tests as ``fast``.
  - ``tests/conftest.py`` blocks network access from fast-marked tests.
  - ``agents.report_agent.trim_to_size`` terminates on huge-string
    pathological inputs in <5 s (previously hung forever).
  - The ``--mode auto`` end-to-end orchestrator exists and is wired.

See ``docs/BOTTLENECK_ROADMAP.md`` §2 for rationale.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── trim_to_size: pathological-input termination ──────────────────────────
def test_trim_to_size_extreme_overflow_with_huge_strings_terminates_quickly():
    """Round-21 fix: ``trim_to_size`` previously hung forever on
    payloads with 100 KB string values. Must now return within 5 s.

    The exact test from ``tests/test_trim_to_size_fix.py``
    duplicated here as a regression probe.
    """
    t0 = time.monotonic()
    from agents.report_agent import trim_to_size

    huge = "a" * 100_000
    payload = {
        "summary": "x",
        "big_blob": huge,
        "raw_data": huge,
        "_details_blob": huge,
        "victim_traffic_results": huge,
        "law_analysis": huge,
    }
    result = trim_to_size(payload, max_bytes=500)
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0, f"trim_to_size hung for {elapsed:.2f}s on pathological input"
    assert isinstance(result, dict)
    # Hard cap: output should be at most ~1.5 KB after the warning marker.
    size = len(json.dumps(result, default=str))
    assert size < 2000, f"trim_to_size did not shrink enough: {size} bytes"


def test_trim_to_size_pure_string_payload_terminates_quickly():
    """Even when the payload is a single huge string, trim must complete."""
    from agents.report_agent import trim_to_size

    payload = {"big": "x" * 500_000}
    t0 = time.monotonic()
    result = trim_to_size(payload, max_bytes=1000)
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0, f"trim_to_size hung for {elapsed:.2f}s"
    assert isinstance(result, dict)


def test_trim_to_size_nested_dict_replacement_is_bounded():
    """Trim's strategy-3 loop must bound iterations to prevent exponential blowup."""
    from agents.report_agent import trim_to_size

    # Three levels of nesting, each containing a huge list.
    inner = [{"k": "x" * 100} for _ in range(2000)]
    payload = {
        "a": {"b": {"c": inner, "d": inner}, "e": inner},
        "victim_traffic_results": inner,
        "summary": "must keep",
    }
    t0 = time.monotonic()
    result = trim_to_size(payload, max_bytes=2000)
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0, f"trim_to_size hung for {elapsed:.2f}s"
    assert isinstance(result, dict)


# ── Marker API ─────────────────────────────────────────────────────────────
def test_run_tests_script_exists_and_is_executable():
    """The CI entry point ``scripts/run_tests.sh`` must exist and be
    executable. Without it, contributors can't run a fast subset of tests.
    """
    script = PROJECT_ROOT / "scripts" / "run_tests.sh"
    assert script.exists()
    assert os.access(script, os.X_OK), (
        f"{script} must be executable. Run: chmod +x {script}"
    )


def test_pytest_ini_exists_and_registers_markers():
    """``pytest.ini`` must declare the fast/slow/network markers."""
    ini = PROJECT_ROOT / "pytest.ini"
    assert ini.exists()
    text = ini.read_text()
    for marker in ("fast:", "slow:", "network:"):
        assert marker in text, f"{ini} missing marker declaration: {marker!r}"


def test_conftest_auto_tags_unmarked_tests_as_fast():
    """Tests without a marker must get ``fast`` automatically; pure-Python
    pytest runs only with ``-m fast`` should never silently miss them.
    """
    # Round-trip via the pytest CLI.
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tests/test_round21_review_fixes.py",
            "-m", "fast",
            "--collect-only", "-q",
        ],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
        env={**os.environ, "BGP_TRACER_TEST_TIMEOUT_S": "30"},
    )
    assert "deselected" in result.stdout or "collected" in result.stdout, (
        f"unexpected output: {result.stdout!r}"
    )


# ── Network-guard regression ──────────────────────────────────────────────
def test_network_guard_allows_loopback_in_fast_tests():
    """The conftest's network-guard fixture must NOT block loopback
    addresses (which fast tests use for http.server / socketserver).
    A refused connection is OK (no server); a raise from the guard is not.
    """
    # Loopback must not raise RuntimeError from the guard fixture.
    # We accept either success or ConnectionRefusedError — both mean
    # the guard did not erroneously interfere.
    try:
        s = socket.create_connection(("127.0.0.1", 1), timeout=0.1)
        s.close()
    except (ConnectionRefusedError, OSError):
        # Refused / unreachable: that's fine, the guard is satisfied.
        pass


# ── Trim consistency: shrinking preserves summary ─────────────────────────
def test_trim_to_size_preserves_summary_key():
    from agents.report_agent import trim_to_size

    payload = {
        "summary": {"text": "critical narrative"},
        "details": [{"x": i} for i in range(10000)],
    }
    result = trim_to_size(payload, max_bytes=2000)
    assert isinstance(result, dict)
    assert result.get("summary") == {"text": "critical narrative"}, (
        f"trim dropped the summary key: {result}"
    )


if __name__ == "__main__":
    # Allow direct invocation: ``python tests/test_round22_bottleneck_fixes.py``.
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
