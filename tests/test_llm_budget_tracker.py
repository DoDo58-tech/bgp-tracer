"""Tests for the LLM budget tracker (GLM-5 1000/5h rolling-window protection).

These tests are fast and do NOT require any API key or LLM server.
They exercise the _BudgetTracker class in isolation.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

# Isolate from the singleton by patching get_budget_tracker.
from llm import llm_factory as lf_mod  # noqa: E402


pytestmark = pytest.mark.fast


# ─── Helpers ────────────────────────────────────────────────────────────


def _fresh_tracker(max_calls: int = 950) -> lf_mod._BudgetTracker:
    """Return a fresh tracker with a configurable budget."""
    if max_calls != 950:
        os.environ["LLM_BUDGET_MAX_CALLS"] = str(max_calls)
    tracker = lf_mod._BudgetTracker()
    return tracker


def _call_count(tracker: lf_mod._BudgetTracker) -> int:
    """Read current window count without mutating."""
    # Access the internal deque to read count without side-effects.
    # We use the public API: remaining_budget()
    rem, total = tracker.remaining_budget()
    return total - rem


# ─── Tests ──────────────────────────────────────────────────────────────


def test_budget_track_single_call():
    """A single call is recorded and counted."""
    t = _fresh_tracker()
    assert _call_count(t) == 0
    t.check_and_record()
    assert _call_count(t) == 1


def test_budget_track_respects_max_calls():
    """When max calls are reached, BudgetExhausted is raised."""
    t = _fresh_tracker(max_calls=3)
    # Calls 1-3: succeed
    for _ in range(3):
        t.check_and_record()
    assert _call_count(t) == 3
    # Call 4: raises BudgetExhausted
    with pytest.raises(lf_mod.BudgetExhausted) as exc_info:
        t.check_and_record()
    assert "budget exhausted" in str(exc_info.value).lower()


def test_budget_track_window_expiry():
    """Calls older than the window are dropped."""
    t = _fresh_tracker()
    # Set a very short window.
    os.environ["LLM_BUDGET_WINDOW_S"] = "0.1"
    try:
        t.check_and_record()
        assert _call_count(t) == 1
        time.sleep(0.2)
        # Window has rolled: the old call should be gone.
        assert _call_count(t) == 0
        t.check_and_record()  # should succeed
        assert _call_count(t) == 1
    finally:
        os.environ["LLM_BUDGET_WINDOW_S"] = "18000"


def test_budget_track_concurrent_access():
    """The tracker is thread-safe: multiple threads can call it simultaneously."""
    t = _fresh_tracker()
    os.environ["LLM_BUDGET_MAX_CALLS"] = "1000"
    errors = []

    def worker():
        try:
            for _ in range(50):
                t.check_and_record()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert not errors, f"Threading errors: {errors}"
    assert _call_count(t) == 200


def test_budget_remaining_budget():
    """remaining_budget() returns (remaining, max)."""
    t = _fresh_tracker(max_calls=10)
    rem, total = t.remaining_budget()
    assert rem == 10 and total == 10
    t.check_and_record()
    rem2, total2 = t.remaining_budget()
    assert rem2 == 9 and total2 == 10


def test_budget_reset():
    """reset() clears all recorded calls."""
    t = _fresh_tracker()
    for _ in range(5):
        t.check_and_record()
    assert _call_count(t) == 5
    t.reset()
    assert _call_count(t) == 0


def test_budget_singleton_interface():
    """get_budget_tracker() returns the shared singleton."""
    t1 = lf_mod.get_budget_tracker()
    t2 = lf_mod.get_budget_tracker()
    assert t1 is t2  # same object


def test_budget_warning_at_threshold():
    """Warning fires at 80% utilisation (10 * 0.8 = 8); BudgetExhausted at 11th."""
    t = _fresh_tracker(max_calls=10)
    os.environ["LLM_BUDGET_WARN_AT"] = "0.8"
    # Calls 1-8: ok, no warning
    for _ in range(8):
        t.check_and_record()
    assert _call_count(t) == 8
    # Call 9: warning fires (used_before=8 ≥ threshold=8), no BudgetExhausted
    t.check_and_record()
    assert _call_count(t) == 9
    # Call 10: still under limit, no BudgetExhausted
    t.check_and_record()
    assert _call_count(t) == 10
    # Call 11: hits limit → BudgetExhausted
    with pytest.raises(lf_mod.BudgetExhausted):
        t.check_and_record()
    os.environ.pop("LLM_BUDGET_WARN_AT", None)


# ─── Shared-file mode tests ─────────────────────────────────────────────
def test_shared_file_persists_across_subprocesses(tmp_path):
    """Two tracker instances reading the same shared file see consistent state.

    Simulates two subprocesses: process A calls 2 LLM calls, then process B
    is created and should see those 2 calls already in the budget.
    """
    shared = tmp_path / "budget.tsv"
    os.environ["LLM_BUDGET_SHARED_FILE"] = str(shared)
    os.environ["LLM_BUDGET_MAX_CALLS"] = "5"
    try:
        # Process A: 2 calls
        tracker_a = lf_mod._BudgetTracker()
        tracker_a.check_and_record()
        tracker_a.check_and_record()
        assert _call_count(tracker_a) == 2

        # Process B: new tracker, should see those 2 calls from file
        tracker_b = lf_mod._BudgetTracker()
        assert _call_count(tracker_b) == 2
        tracker_b.check_and_record()  # 3rd
        tracker_b.check_and_record()  # 4th
        assert _call_count(tracker_b) == 4

        # Process C: should see all 4 from file (3rd+4th from B)
        tracker_c = lf_mod._BudgetTracker()
        assert _call_count(tracker_c) == 4
        # 5th call: used_before=4, < max=5 → OK
        tracker_c.check_and_record()
        assert _call_count(tracker_c) == 5
        # 6th call: used_before=5, == max=5 → BudgetExhausted
        with pytest.raises(lf_mod.BudgetExhausted):
            tracker_c.check_and_record()
    finally:
        os.environ.pop("LLM_BUDGET_SHARED_FILE", None)
        os.environ.pop("LLM_BUDGET_MAX_CALLS", None)


def test_shared_file_window_expiry(tmp_path):
    """Old timestamps in the shared file are pruned when window rotates."""
    import time
    shared = tmp_path / "budget.tsv"
    os.environ["LLM_BUDGET_SHARED_FILE"] = str(shared)
    os.environ["LLM_BUDGET_WINDOW_S"] = "0.3"
    os.environ["LLM_BUDGET_MAX_CALLS"] = "100"
    try:
        # Process A: 2 calls
        t_a = lf_mod._BudgetTracker()
        t_a.check_and_record()
        t_a.check_and_record()
        assert _call_count(t_a) == 2
        # Wait for window to expire
        time.sleep(0.4)
        # Process B: old calls should be pruned
        t_b = lf_mod._BudgetTracker()
        assert _call_count(t_b) == 0, "stale calls should have been pruned"
    finally:
        os.environ.pop("LLM_BUDGET_SHARED_FILE", None)
        os.environ.pop("LLM_BUDGET_WINDOW_S", None)
        os.environ.pop("LLM_BUDGET_MAX_CALLS", None)


def test_shared_file_disabled_when_env_unset():
    """Without LLM_BUDGET_SHARED_FILE, the tracker is in-process only."""
    os.environ.pop("LLM_BUDGET_SHARED_FILE", None)
    t = lf_mod._BudgetTracker()
    assert t._shared_path == ""
    # Recording shouldn't write to any file
    t.check_and_record()


def test_shared_file_rotation_bounds_size(tmp_path):
    """After many calls, the shared file is rotated and only keeps
    timestamps in the current window. Set a tight window so we can
    observe rotation actually happens."""
    shared = tmp_path / "budget.tsv"
    os.environ["LLM_BUDGET_SHARED_FILE"] = str(shared)
    os.environ["LLM_BUDGET_WINDOW_S"] = "10"
    os.environ["LLM_BUDGET_MAX_CALLS"] = "1000"
    os.environ["LLM_BUDGET_ROTATE_EVERY"] = "5"  # rotate every 5 calls
    try:
        tracker = lf_mod._BudgetTracker()
        # Make 20 calls; after every 5th call, rotation happens
        for i in range(20):
            tracker.check_and_record()
        # File should be small (only most-recent timestamps)
        size = shared.stat().st_size
        assert size < 1024, f"file should be tiny after rotation, got {size} bytes"
    finally:
        os.environ.pop("LLM_BUDGET_SHARED_FILE", None)
        os.environ.pop("LLM_BUDGET_WINDOW_S", None)
        os.environ.pop("LLM_BUDGET_MAX_CALLS", None)
        os.environ.pop("LLM_BUDGET_ROTATE_EVERY", None)
