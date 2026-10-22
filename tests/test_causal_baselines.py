"""Smoke tests for agents/causal_baselines.py.

The baselines are the comparative pillar of paper §6. They must:
  1. Return ``BaselineResult`` instances with all three fields set.
  2. Be deterministic (no LLM, no randomness).
  3. Recognise a clean routing-first lead pattern.
  4. Gracefully degrade on empty / zero-variance inputs.
  5. Match the direction convention used by HCAF
     ("routing_to_traffic" / "traffic_to_routing" / "unknown").
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.causal_baselines import (  # noqa: E402
    BASELINES,
    BaselineResult,
    baseline_attribution,
    granger_baseline,
    pearson_baseline,
    run_all_baselines,
    timestamp_distance_baseline,
)


# ── Fixtures ───────────────────────────────────────────────────────────
def _routing_burst_then_baseline(n: int = 60, burst_at: int = 20, burst_len: int = 10) -> list[dict]:
    return [
        {"timestamp": f"2026-09-29T00:{i:02d}:00Z",
         "score": 5.0 if burst_at <= i < burst_at + burst_len else 1.0}
        for i in range(n)
    ]


def _traffic_drop_then_baseline(n: int = 60, drop_at: int = 30, drop_len: int = 15) -> list[dict]:
    return [
        {"timestamp": f"2026-09-29T00:{i:02d}:00Z",
         "score": 50.0 if drop_at <= i < drop_at + drop_len else 100.0}
        for i in range(n)
    ]


# ── 1. Result shape ────────────────────────────────────────────────────
def test_baselines_return_baseline_result():
    rt = _routing_burst_then_baseline()
    tt = _traffic_drop_then_baseline()
    for name, fn in BASELINES.items():
        result = fn(rt, tt)
        assert isinstance(result, BaselineResult), f"{name} returned {type(result)}"
        assert result.method == name
        assert result.direction in ("routing_to_traffic", "traffic_to_routing", "unknown")
        assert 0.0 <= result.confidence <= 1.0


# ── 2. Determinism ─────────────────────────────────────────────────────
def test_baselines_are_deterministic():
    rt = _routing_burst_then_baseline()
    tt = _traffic_drop_then_baseline()
    first = {n: fn(rt, tt) for n, fn in BASELINES.items()}
    second = {n: fn(rt, tt) for n, fn in BASELINES.items()}
    for name in BASELINES:
        assert first[name].direction == second[name].direction, name
        assert first[name].confidence == second[name].confidence, name


# ── 3. Routing-first pattern recognition ───────────────────────────────
def test_pearson_recognises_routing_first():
    rt = _routing_burst_then_baseline()
    tt = _traffic_drop_then_baseline()
    r = pearson_baseline(rt, tt)
    assert r.direction == "routing_to_traffic", r.details
    assert r.confidence > 0.5


def test_ts_distance_recognises_routing_first():
    """When routing bursts 10 minutes before traffic drops, ts-distance
    must call it ``routing_to_traffic`` with confidence > 0."""
    rt = _routing_burst_then_baseline()
    # Traffic starts 10 minutes later, so the first routing event is
    # 10 min earlier than the first traffic event.
    tt = [
        {"timestamp": f"2026-09-29T00:{i + 10:02d}:00Z",
         "score": 50.0 if 30 <= i < 45 else 100.0}
        for i in range(60)
    ]
    r = timestamp_distance_baseline(rt, tt)
    assert r.direction == "routing_to_traffic", r.details
    assert r.confidence > 0.0


# ── 4. Empty / zero-variance graceful degradation ─────────────────────
def test_pearson_empty_returns_unknown():
    r = pearson_baseline([], [])
    assert r.direction == "unknown"
    assert r.confidence == 0.0


def test_pearson_zero_variance_returns_unknown():
    rt = [{"timestamp": "2026-09-29T00:00:00Z", "score": 1.0} for _ in range(10)]
    tt = [{"timestamp": "2026-09-29T00:00:00Z", "score": 100.0} for _ in range(10)]
    r = pearson_baseline(rt, tt)
    assert r.direction == "unknown"


def test_granger_short_series_returns_unknown():
    rt = _routing_burst_then_baseline(n=4)
    tt = _traffic_drop_then_baseline(n=4)
    r = granger_baseline(rt, tt)
    assert r.direction == "unknown"


def test_ts_distance_missing_timestamp_returns_unknown():
    rt = [{"score": 1.0} for _ in range(5)]   # no timestamp
    tt = [{"score": 50.0} for _ in range(5)]
    r = timestamp_distance_baseline(rt, tt)
    assert r.direction == "unknown"


# ── 5. Direction convention match ─────────────────────────────────────
def test_baseline_attribution_dispatch():
    """baseline_attribution must route to the named function."""
    rt = _routing_burst_then_baseline()
    tt = _traffic_drop_then_baseline()
    for name in BASELINES:
        r = baseline_attribution(name, rt, tt)
        assert r.method == name


def test_run_all_baselines_returns_every_registered_baseline():
    """run_all_baselines must return exactly the registered baseline set.

    Five baselines, not four: pc_conditional_independence was added for
    the paper's Table~\\ref{tab:hcaf-4way} comparison, which reports PC
    alongside Granger, transfer entropy, timestamp distance, and
    Pearson. Asserting against the literal set keeps this test honest
    about the current registry instead of silently accepting a new
    baseline (or missing an old one).
    """
    rt = _routing_burst_then_baseline()
    tt = _traffic_drop_then_baseline()
    results = run_all_baselines(rt, tt)
    assert set(results.keys()) == {
        "pearson",
        "granger",
        "timestamp_distance",
        "transfer_entropy",
        "pc_conditional_independence",
    }
    for r in results.values():
        assert isinstance(r, BaselineResult)


# ── 6. Unknown baseline name raises ────────────────────────────────────
def test_unknown_baseline_name_raises():
    rt = _routing_burst_then_baseline()
    tt = _traffic_drop_then_baseline()
    with pytest.raises(ValueError, match="Unknown baseline"):
        baseline_attribution("not_a_method", rt, tt)