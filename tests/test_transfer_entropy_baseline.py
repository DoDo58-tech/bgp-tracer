"""Unit tests for the Transfer Entropy baseline.

Reference: Schreiber (2000), ``Measuring Information Transfer`` Phys Rev Lett.
This baseline complements the linear Granger test by capturing
non-linear, non-Gaussian directional information flow.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from agents.causal_baselines import (  # noqa: E402
    BASELINES,
    BaselineResult,
    transfer_entropy_baseline,
)


pytestmark = pytest.mark.fast


# ─── Helpers ────────────────────────────────────────────────────────────


def _tl(n, anomaly_range, baseline=0.1, peak=1.0):
    return [
        {"timestamp": f"2026-09-29T00:{i:02d}:00",
         "score": float(peak if anomaly_range[0] <= i <= anomaly_range[1] else baseline)}
        for i in range(n)
    ]


# ─── Tests ─────────────────────────────────────────────────────────────


def test_transfer_entropy_registered_in_baselines():
    assert "transfer_entropy" in BASELINES
    assert BASELINES["transfer_entropy"] is transfer_entropy_baseline


def test_transfer_entropy_returns_baseline_result():
    routing = _tl(40, (10, 15))
    traffic = _tl(40, (16, 24), baseline=1.0, peak=0.1)
    result = transfer_entropy_baseline(routing, traffic, bins=2)
    assert isinstance(result, BaselineResult)
    assert result.method == "transfer_entropy"


def test_transfer_entropy_handles_empty_timeline():
    result = transfer_entropy_baseline([], [])
    assert result.direction == "unknown"
    assert result.confidence == 0.0


def test_transfer_entropy_handles_constant_series():
    n = 30
    routing = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": 0.5} for i in range(n)]
    traffic = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": 0.5} for i in range(n)]
    result = transfer_entropy_baseline(routing, traffic)
    assert result.direction == "unknown"


def test_transfer_entropy_handles_short_series():
    routing = [{"timestamp": "2026-09-29T00:00:00", "score": 0.5}] * 3
    traffic = [{"timestamp": "2026-09-29T00:00:00", "score": 0.5}] * 3
    result = transfer_entropy_baseline(routing, traffic)
    assert result.direction == "unknown"


def test_transfer_entropy_has_te_metrics_in_details():
    """Result details must expose the TE values for paper-grade reporting."""
    routing = _tl(60, (20, 30))
    traffic = _tl(60, (32, 42), baseline=1.0, peak=0.3)
    result = transfer_entropy_baseline(routing, traffic, bins=2)
    assert "te_routing_to_traffic" in result.details
    assert "te_traffic_to_routing" in result.details
    assert "null_mean" in result.details
    assert "null_std" in result.details
    # Both TE values must be ≥ 0 (TE is unsigned by construction).
    assert result.details["te_routing_to_traffic"] >= 0
    assert result.details["te_traffic_to_routing"] >= 0


def test_transfer_entropy_deterministic():
    """Same input must yield same output (seeded RNG)."""
    routing = _tl(50, (15, 25))
    traffic = _tl(50, (26, 36), baseline=1.0, peak=0.3)
    r1 = transfer_entropy_baseline(routing, traffic, bins=2, n_perm=50)
    r2 = transfer_entropy_baseline(routing, traffic, bins=2, n_perm=50)
    assert r1.direction == r2.direction
    assert r1.details["te_routing_to_traffic"] == r2.details["te_routing_to_traffic"]
