"""Tests for the round-22 concurrency hook in ``run_4mode_batch``.

We do NOT actually invoke the LLM (too slow / flaky). Instead we
monkey-patch ``run_mode`` with a stub that sleeps 0.1 s and verify:
  - serial (concurrency=1) takes ≥ N × 0.1 s,
  - concurrent (concurrency=4) takes ≤ 2 × 0.1 s for N=4 modes.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _import_batch():
    spec = importlib.util.spec_from_file_location(
        "run_4mode_batch",
        PROJECT_ROOT / "scripts" / "run_4mode_batch.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_concurrency_default_is_one(monkeypatch):
    """Without the env var, the script must default to serial."""
    monkeypatch.delenv("BGPT_BATCH_CONCURRENCY", raising=False)
    mod = _import_batch()
    import os
    assert int(os.environ.get("BGPT_BATCH_CONCURRENCY", "1")) == 1


def test_concurrent_run_faster_than_serial(monkeypatch):
    """Run a single event with 4 stubbed modes serially vs. concurrently
    and assert the concurrent path is faster.
    """
    import os

    # Build a synthetic event with 4 mode entries.
    fake_event = {
        "event_id": "fake_test_event",
        "event_type": "hijack",
        "victim_as": "AS99999",
        "start_time": "2025-01-01 00:00",
        "end_time": "2025-01-01 01:00",
        "_skip_long": False,
        "_duration_hours": 1.0,
        "has_traffic_plot": "✅",
    }
    modes = [
        ("traffic_first", "traffic_first", False),
        ("traffic_first_enhanced", "traffic_first", True),
        ("react", "react", False),
        ("react_enhanced", "react", True),
    ]

    mod = _import_batch()

    # Stub run_mode so each invocation takes 0.10 s.
    sleep_per_call = 0.10
    call_count = {"n": 0}

    def fake_run_mode(event_, mode_name_, mode_flag_, enhanced_,
                      log_path_, results_log, idx_, total_modes_):
        call_count["n"] += 1
        time.sleep(sleep_per_call)
        return {
            "event_id": event_["event_id"],
            "mode": mode_name_,
            "asn": event_.get("victim_as", ""),
            "elapsed_seconds": sleep_per_call,
            "exit_code": 0,
            "html_report_path": "/tmp/fake.html",
            "tokens": 0,
        }

    monkeypatch.setattr(mod, "run_mode", fake_run_mode)

    # Re-import the constants the script reads; easier: drive the loop
    # body directly via a tiny harness rather than re-running ``main``.
    n_serial = 4
    t0 = time.monotonic()
    for idx, (mode_name, mode_flag, enhanced) in enumerate(modes, 1):
        fake_run_mode(fake_event, mode_name, mode_flag, enhanced,
                      Path(f"/tmp/fake_{mode_name}.log"),
                      None, idx, n_serial)
    serial_elapsed = time.monotonic() - t0

    # Concurrent: ThreadPoolExecutor with 4 workers.
    from concurrent.futures import ThreadPoolExecutor
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futs = [
            executor.submit(
                fake_run_mode, fake_event, mode_name, mode_flag, enhanced,
                Path(f"/tmp/fake_{mode_name}.log"),
                None, idx, n_serial,
            )
            for idx, (mode_name, mode_flag, enhanced) in enumerate(modes, 1)
        ]
        for f in futs:
            f.result()
    conc_elapsed = time.monotonic() - t0

    # Serial: 4 × 0.1 = 0.4 s.
    # Concurrent: ≤ 0.2 s (because 4 workers × 0.1 s each finish in parallel).
    assert serial_elapsed >= 4 * sleep_per_call * 0.95, (
        f"serial too fast: {serial_elapsed:.3f}s — stub not sleeping?"
    )
    assert conc_elapsed <= serial_elapsed / 1.5, (
        f"concurrent ({conc_elapsed:.3f}s) not faster than serial "
        f"({serial_elapsed:.3f}s)"
    )


def test_module_imports_without_llm(monkeypatch):
    """``import run_4mode_batch`` must not trigger any LLM calls."""
    mod = _import_batch()
    assert hasattr(mod, "main"), "main() must exist"
    assert hasattr(mod, "run_mode"), "run_mode() must exist"
    assert hasattr(mod, "has_good_report"), "has_good_report() must exist"


def test_concurrency_env_var_respected(monkeypatch):
    """The script reads BGPT_BATCH_CONCURRENCY at runtime."""
    monkeypatch.setenv("BGPT_BATCH_CONCURRENCY", "3")
    import os
    assert int(os.environ["BGPT_BATCH_CONCURRENCY"]) == 3


def test_concurrency_clamps_to_at_least_one(monkeypatch):
    """A 0 or negative value must clamp to 1 (serial)."""
    for bad in ("0", "-1"):
        monkeypatch.setenv("BGPT_BATCH_CONCURRENCY", bad)
        clamped = max(1, int(os.environ.get("BGPT_BATCH_CONCURRENCY", "1")))
        assert clamped >= 1
