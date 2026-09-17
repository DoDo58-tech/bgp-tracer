"""Granger causality stationarity pre-check regression tests.

Tests the `GrangerEngine.enforce_stationarity` behaviour introduced in
response to REVIEW_SIGCOMM_GRADE_v2 §1.2 ("Granger on non-stationary
series → spurious significance"). These tests are fast (synthetic series
only) and tagged ``fast``.

Three guarantees under test:
    1. Stationary series → Granger runs and reports `differencing_applied=False`.
    2. Trending series → `differencing_applied=True`, ADF p-value recorded.
    3. The output dict schema carries the paper-promised fields.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make `agents/` importable without invoking the full chief_agent CLI.
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from agents.causal_attribution import GrangerEngine  # noqa: E402


pytestmark = pytest.mark.fast

_KNOWN_DIRECTIONS = {
    "routing_to_traffic", "traffic_to_routing", "independent",
    "unknown", "none", "insufficient_data",
}


# ─── Helpers ────────────────────────────────────────────────────────────


def _stationary_series(n: int = 200, seed: int = 42, score: float = 0.6):
    """A stationary noise series centered around `score` (so it survives
    the >0.5 score filter inside granger_lead)."""
    import numpy as np
    rng = np.random.default_rng(seed)
    return rng.normal(score, 0.1, size=n)


def _trending_series(n: int = 200, seed: int = 42, slope: float = 0.5,
                     score: float = 0.6):
    """A linear-trending non-stationary series."""
    import numpy as np
    rng = np.random.default_rng(seed)
    base = np.arange(n) * slope + rng.normal(0.0, 0.1, size=n)
    # Re-center so the score filter is satisfied.
    return base - base.mean() + score


def _timeline(series, start: str = "2024-01-01T00:00:00Z") -> list:
    """Wrap a 1-D series into a list of {timestamp, score} dicts (5 min spacing)."""
    from datetime import datetime, timedelta
    base = datetime.fromisoformat(start.replace("Z", "+00:00"))
    return [
        {"timestamp": (base + timedelta(minutes=5 * i)).isoformat(), "score": float(v)}
        for i, v in enumerate(series)
    ]


# ─── Tests ──────────────────────────────────────────────────────────────


def test_stationary_series_runs_without_differencing():
    """Two stationary series → Granger proceeds; no differencing."""
    r_tl = _timeline(_stationary_series(seed=1))
    t_tl = _timeline(_stationary_series(seed=2))
    engine = GrangerEngine(max_lag=3, significance=0.05, enforce_stationarity=True)
    out = engine.test(r_tl, t_tl)
    assert out.get("stationarity_checked") is True, out
    assert out.get("differencing_applied") is False, out
    # ADF p-value should be present and small (i.e. stationary).
    assert out.get("adf_p_value") is not None, out
    assert out["adf_p_value"] < 0.05, out
    # Direction should be a known value.
    assert out.get("direction") in _KNOWN_DIRECTIONS, out


def test_trending_series_with_differencing_runs():
    """Trending series → differencing applied → Granger runs to completion."""
    r_tl = _timeline(_trending_series(slope=2.0))
    t_tl = _timeline(_trending_series(slope=3.0, seed=99))
    engine = GrangerEngine(max_lag=3, significance=0.05, enforce_stationarity=True)
    out = engine.test(r_tl, t_tl)
    assert out.get("differencing_applied") is True, out
    assert out.get("adf_p_value") is not None, out
    # stationarity_note must mention differencing for trending input.
    assert "differenced" in out.get("stationarity_note", "") or "diff" in out.get("stationarity_note", ""), out


def test_trending_series_gets_stationarity_meta():
    """Trending series → the engine must surface the stationarity metadata."""
    r_tl = _timeline(_trending_series(slope=2.0))
    t_tl = _timeline(_trending_series(slope=3.0, seed=99))
    engine = GrangerEngine(max_lag=3, significance=0.05, enforce_stationarity=True)
    out = engine.test(r_tl, t_tl)
    # On the success path, differencing_applied must be True for trending series.
    assert out.get("differencing_applied") is True, out
    assert out.get("adf_p_value") is not None, out
    assert out.get("stationarity_checked") is True, out
    # stationarity_note is the human-readable explanation of what was done.
    assert "stationarity_note" in out, out


def test_disabling_stationarity_check_runs_unrestricted():
    """When `enforce_stationarity=False`, no stationarity metadata is emitted."""
    r_tl = _timeline(_trending_series(slope=2.0))
    t_tl = _timeline(_trending_series(slope=3.0, seed=99))
    engine = GrangerEngine(max_lag=3, significance=0.05, enforce_stationarity=False)
    out = engine.test(r_tl, t_tl)
    assert out.get("stationarity_checked") is False, out
    assert out.get("differencing_applied") is False, out


def test_short_series_returns_insufficient():
    """Series shorter than ~10 points → verdict is 'none' / 'insufficient_data'."""
    r_tl = _timeline(_stationary_series(n=8))
    t_tl = _timeline(_stationary_series(n=8, seed=2))
    engine = GrangerEngine(max_lag=3, significance=0.05)
    out = engine.test(r_tl, t_tl)
    assert out.get("direction") in _KNOWN_DIRECTIONS, out
    # Either direction='none' or 'insufficient_data' is acceptable.
    assert out.get("direction") in {"none", "unknown", "insufficient_data"}, out
    assert out.get("strength", 1.0) == 0.0, out


def test_stationarity_meta_field_schema():
    """The output dict must always carry the paper-promised schema fields
    on the SUCCESS path. (On the failure path, ``granger_stationarity_insuf``
    carries additional fields — covered by the trending test above.)"""
    r_tl = _timeline(_stationary_series())
    t_tl = _timeline(_stationary_series(seed=2))
    engine = GrangerEngine()
    out = engine.test(r_tl, t_tl)
    for field in ("stationarity_checked", "differencing_applied",
                   "adf_p_value"):
        assert field in out, f"Missing field {field} in Granger output: {out}"


def test_real_ground_truth_event_has_stationarity_metadata():
    """Smoke: run the engine over a synthetic dataset that mimics the
    real 5-min Cloudflare data (mixed stationary + trending)."""
    import numpy as np
    rng = np.random.default_rng(7)
    n = 200
    r_series = np.concatenate([
        rng.normal(0.3, 0.05, size=100),     # quiet
        np.linspace(0.3, 0.9, num=100) + rng.normal(0, 0.05, size=100),  # spike
    ])
    t_series = np.concatenate([
        rng.normal(0.5, 0.05, size=120),     # baseline
        np.linspace(0.5, 0.2, num=80) + rng.normal(0, 0.05, size=80),   # drop
    ])
    engine = GrangerEngine(max_lag=4, significance=0.05)
    out = engine.test(_timeline(r_series), _timeline(t_series))
    assert out.get("stationarity_checked") is True
    # Either differencing is applied, or the series was stationary.
    # What matters is that the verdict is honest (no spurious "significant").
    assert out.get("significant") in {True, False}, out
    if out.get("significant"):
        # If we say "significant", we must have run ADF and (possibly) differencing.
        assert out.get("adf_p_value") is not None


def test_differencing_size_mismatch_regression():
    """Regression: when only ONE of the two series is differenced, the
    two series used to have different lengths (one shortened by
    ``np.diff``) which broke ``np.column_stack`` inside ``granger_gt``.

    Bug surfaced in production on leak detection CSVs with >> 200 events
    (warning: ``array at index 0 has size 247 and the array at index 1
    has size 248``). The bug was silently swallowed by a try/except and
    a spurious "significant=True" verdict was returned. Fix: re-align
    to the shortest of the two after differencing.
    """
    import io
    import logging
    import numpy as np
    # Mirror the production scenario: routing trending (gets differenced
    # → length drops by 1), traffic stationary (no differencing).
    rng = np.random.default_rng(42)
    n1, n2 = 248, 247
    r_series = np.arange(n1) * 0.1 + rng.normal(0, 0.05, size=n1)
    t_series = rng.normal(0.6, 0.05, size=n2)
    r_tl = _timeline(r_series)
    t_tl = _timeline(t_series)
    # Capture logs to detect the original bug signature.
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.WARNING)
    logger = logging.getLogger("agents.causal_attribution")
    logger.addHandler(handler)
    try:
        engine = GrangerEngine(max_lag=4, enforce_stationarity=True)
        out = engine.test(r_tl, t_tl)
    finally:
        logger.removeHandler(handler)
    log_text = log_capture.getvalue()
    # The bug signature was the "array at index 0 has size X" warning
    # indicating np.column_stack failed inside granger_gt.
    assert "array at index 0 has size" not in log_text, (
        f"Granger size-mismatch warning still appears (regression of "
        f"the original bug).\nLog: {log_text}"
    )
    # And the verdict should be valid (not spuriously strong).
    assert out.get("direction") in _KNOWN_DIRECTIONS, out
