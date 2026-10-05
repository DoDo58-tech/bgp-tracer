"""Regression tests for two detector bugs that hid real anomalies.

BUG-R151 (`clustering.calculate_traffic_statistics`)
    Peak/trough/drop are intra-series statistics -- they compare samples of the
    current window against each other. The function nevertheless returned an
    all-zero block whenever `historical_means` was empty, so an AS without a
    usable baseline always reported a 0.0% drop even when its traffic had
    collapsed. `historical_means` is empty whenever the four historical weeks
    cannot be loaded (no API token in the environment, or no cache).

BUG-R152 (`multi_scale_baseline.MultiScaleBaseline._decide`)
    The consensus threshold used the *configured* scale count (`len(self.SCALES)`)
    rather than the number of scales that actually returned a verdict. With
    sparse history only 2 of 5 scales are available, so the rule demanded
    3 votes out of 2 possible -- detection became mathematically impossible.
    AS12479 (Orange Spain hijack) is the concrete victim.
"""
from __future__ import annotations

import numpy as np
import pytest

import config  # noqa: F401  (side effect: load_dotenv)
from detectors.traffic.clustering import calculate_traffic_statistics
from detectors.traffic.multi_scale_baseline import MultiScaleBaseline


def test_peak_trough_drop_survives_missing_baseline():
    """Without a baseline, peak/trough/drop must still be computed."""
    current = np.array([0.80, 0.81, 0.42, 0.38, 0.37, 0.55, 0.72, 0.87])
    stats = calculate_traffic_statistics(current, np.array([]))

    assert stats["data_points"] == len(current)
    assert stats["peak_value"] == pytest.approx(0.87, abs=1e-6)
    assert stats["trough_value"] == pytest.approx(0.37, abs=1e-6)
    assert stats["peak_trough_drop_pct"] == pytest.approx((0.87 - 0.37) / 0.87 * 100, abs=1e-3)


def test_peak_trough_drop_unchanged_with_baseline():
    """The fix must not alter behaviour when a baseline IS available."""
    current = np.array([0.80, 0.81, 0.42, 0.38, 0.37, 0.55, 0.72, 0.87])
    hist = np.array([0.78, 0.80, 0.79, 0.81, 0.80, 0.78, 0.79, 0.80])
    stats = calculate_traffic_statistics(current, hist)

    assert stats["peak_trough_drop_pct"] == pytest.approx((0.87 - 0.37) / 0.87 * 100, abs=1e-3)
    assert stats["historical_avg"] == pytest.approx(float(np.mean(hist)))


def test_peak_trough_drop_zero_only_for_empty_current():
    """An empty current window is the only case that may report a 0.0% drop."""
    stats = calculate_traffic_statistics(np.array([]), np.array([0.5, 0.6]))
    assert stats["peak_trough_drop_pct"] == 0.0
    assert stats["data_points"] == 0


def test_consensus_threshold_scales_with_available_scales():
    """The vote rule must adapt to how many scales actually produced a verdict."""
    ms = MultiScaleBaseline(lambda *a, **k: ([], []))
    scales = [
        _scale("hourly", available=True, is_anomaly=True, z=2.0, weight=0.35),
        _scale("daily", available=True, is_anomaly=True, z=2.0, weight=0.25),
        _scale("weekly", available=False),
        _scale("biweekly", available=False),
        _scale("monthly", available=False),
    ]
    decision = ms._decide(scale_results=scales, weighted_score=2.0, anomaly_count=2)

    # 2 of 2 available scales flag the window => anomaly.
    assert decision.is_anomaly is True
    assert decision.consensus_count == 2
    assert decision.available_scales == 2
    # A fixed 3-of-5 rule would have demanded 3 votes out of 2 possible.
    assert decision.consensus_required <= 2


def test_consensus_threshold_never_exceeds_available():
    """No verdict can be reached when no scale is available."""
    ms = MultiScaleBaseline(lambda *a, **k: ([], []))
    scales = [_scale("hourly", available=False), _scale("daily", available=False)]
    decision = ms._decide(scale_results=scales, weighted_score=0.1, anomaly_count=0)
    assert decision.is_anomaly is False
    assert decision.consensus_required >= 1


def test_consensus_does_not_fire_on_unanimous_normal():
    """Adapting the threshold must not manufacture anomalies from normal traffic."""
    ms = MultiScaleBaseline(lambda *a, **k: ([], []))
    scales = [
        _scale("hourly", available=True, is_anomaly=False, z=0.1, weight=0.35),
        _scale("daily", available=True, is_anomaly=False, z=0.1, weight=0.25),
    ]
    decision = ms._decide(scale_results=scales, weighted_score=0.1, anomaly_count=0)
    assert decision.is_anomaly is False
    assert decision.consensus_count == 0


def _scale(name, *, available, is_anomaly=False, z=0.0, weight=0.3, reason=""):
    from detectors.traffic.multi_scale_baseline import ScaleResult

    return ScaleResult(
        scale=name,
        available=available,
        is_anomaly=is_anomaly,
        z_score=z,
        confidence=0.0,
        baseline_mean=0.0,
        baseline_std=0.0,
        ci_lower=0.0,
        ci_upper=0.0,
        deviation_pct=0.0,
        direction="unknown" if not available else "normal",
        weight=weight,
        reason=reason,
    )
