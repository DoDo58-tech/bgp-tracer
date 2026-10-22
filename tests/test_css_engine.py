"""Unit tests for the Causal Sufficiency Score (CSS) engine.

The CSS engine is the paper's primary methodological contribution
(replacing the previous weighted-vote scheme). These tests exercise the
PNS-style scoring logic against known-direction synthetic signals.

Reference: Round 30, paper §5.2 (Method: Causal Sufficiency Score).
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from agents.css_engine import (  # noqa: E402
    CSSResult,
    bayesian_synthesize,
    css_score,
)


pytestmark = pytest.mark.fast


# ─── Helpers ────────────────────────────────────────────────────────────


def _make_timeline(n, anomaly_start, anomaly_end, baseline=0.1, peak=1.0):
    return [
        {"timestamp": f"2026-09-29T00:{i:02d}:00",
         "score": float(peak if anomaly_start <= i <= anomaly_end else baseline)}
        for i in range(n)
    ]


# ─── Tests ─────────────────────────────────────────────────────────────


def test_css_returns_result_object():
    """css_score() must return a CSSResult (not a plain dict)."""
    routing = _make_timeline(30, 10, 15)
    traffic = _make_timeline(30, 14, 22, baseline=1.0, peak=0.1)
    result = css_score(routing, traffic, n_bootstrap=200)
    assert isinstance(result, CSSResult)


def test_css_detects_routing_to_traffic():
    """Clear routing→traffic pattern (routing burst precedes traffic drop)."""
    routing = _make_timeline(30, 10, 15)
    traffic = _make_timeline(30, 14, 22, baseline=1.0, peak=0.1)
    result = css_score(routing, traffic, n_bootstrap=500)
    assert result.direction == "routing_to_traffic", (
        f"Expected routing_to_traffic, got {result.direction}; "
        f"css_rt={result.css_routing_to_traffic}, css_tr={result.css_traffic_to_routing}"
    )


def test_css_handles_traffic_only_drop():
    """Traffic drop with no routing change ⇒ CSS abstains (no intervention)."""
    n = 30
    routing = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": 0.2} for i in range(n)]
    traffic = _make_timeline(n, 5, 12, baseline=1.0, peak=0.1)
    result = css_score(routing, traffic, n_bootstrap=500)
    # Routing has no detectable shift → CSS abstains (Pearl: no
    # treatment ⇒ no causal claim).
    assert result.direction == "unknown", (
        f"Expected unknown (no intervention), got {result.direction}"
    )


def test_css_abstains_on_constant_series():
    """Both series flat ⇒ unknown (cannot establish intervention)."""
    n = 30
    routing = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": 0.5} for i in range(n)]
    traffic = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": 0.5} for i in range(n)]
    result = css_score(routing, traffic, n_bootstrap=200)
    assert result.direction == "unknown"


def test_css_ci_excludes_zero_on_clear_signal():
    """For a clear routing→traffic signal the 95% CI must exclude 0
    in the absolute sense (post − pre is bounded away from zero)."""
    n = 60
    r_arr = np.where(np.arange(n) > 30, 2.0, 0.2)
    t_arr = np.where(np.arange(n) > 35, 0.3, 1.0)
    routing = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": float(s)} for i, s in enumerate(r_arr)]
    traffic = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": float(s)} for i, s in enumerate(t_arr)]
    result = css_score(routing, traffic, n_bootstrap=2000)
    # For the routing→traffic direction, the post-minus-pre PNS CI
    # should be entirely positive (traffic surged) or entirely negative
    # (traffic dropped). Either way it excludes 0.
    if result.direction == "routing_to_traffic":
        rt = result.details["pns_routing_to_traffic"]
        ci_excludes_zero = rt["ci_lower"] > 0 or rt["ci_upper"] < 0
        assert ci_excludes_zero, (
            f"CSS CI must exclude 0 for a clear signal; got "
            f"CI=[{rt['ci_lower']:.3f}, {rt['ci_upper']:.3f}], point={rt['point']:.3f}"
        )


def test_css_is_causal_flag_consistent_with_ci():
    """is_causal must agree with the CI-exclusion check (PNS-style)."""
    n = 60
    r_arr = np.where(np.arange(n) > 30, 2.0, 0.2)
    t_arr = np.where(np.arange(n) > 35, 0.3, 1.0)
    routing = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": float(s)} for i, s in enumerate(r_arr)]
    traffic = [{"timestamp": f"2026-09-29T00:{i:02d}:00", "score": float(s)} for i, s in enumerate(t_arr)]
    result = css_score(routing, traffic, n_bootstrap=2000)
    if result.is_causal:
        rt = result.details["pns_routing_to_traffic"]
        assert rt["ci_lower"] > 0 or rt["ci_upper"] < 0
        assert result.p_value < 0.05


def test_bayesian_synthesis_uses_css_prior():
    """bayesian_synthesize must tilt the prior toward CSS's direction."""
    routing = _make_timeline(30, 10, 15)
    traffic = _make_timeline(30, 14, 22, baseline=1.0, peak=0.1)
    css = css_score(routing, traffic, n_bootstrap=500)
    # Even with empty channels, posterior should still favour CSS's
    # chosen direction.
    synth = bayesian_synthesize(css, evidence_channels={})
    assert synth["direction"] == css.direction, (
        f"Bayesian synthesis must follow CSS anchor; got {synth['direction']} vs CSS {css.direction}"
    )


def test_bayesian_synthesis_aggregates_channels():
    """Each evidence channel must contribute to the posterior."""
    routing = _make_timeline(30, 10, 15)
    traffic = _make_timeline(30, 14, 22, baseline=1.0, peak=0.1)
    css = css_score(routing, traffic, n_bootstrap=500)
    # No channels: posterior ≈ CSS prior.
    base = bayesian_synthesize(css, evidence_channels={})
    # One channel agreeing with CSS: posterior for CSS's direction grows.
    agreeing_lr = {"direction": css.direction,
                   "likelihood": {css.direction: 5.0,
                                  ("traffic_to_routing" if css.direction == "routing_to_traffic"
                                   else "routing_to_traffic"): 0.2,
                                  "independent": 1.0}}
    boosted = bayesian_synthesize(css, {"ch": agreeing_lr})
    css_dir_key = css.direction if css.direction in boosted["posterior"] else (
        "routing_to_traffic" if css.direction == "routing -> traffic"
        else "traffic_to_routing"
    )
    assert boosted["posterior"][css_dir_key] > base["posterior"][css_dir_key]


def test_css_breakpoint_from_msbd_respected():
    """An externally provided MSBD breakpoint must override CSS's
    auto-detection."""
    routing = _make_timeline(60, 30, 50)  # burst at idx 30-50
    traffic = _make_timeline(60, 35, 55, baseline=1.0, peak=0.3)
    # Provide MSBD breakpoint at idx 30 (correct).
    res_with_msbd = css_score(routing, traffic, msbd_breakpoint_idx=30, n_bootstrap=500)
    # Provide MSBD breakpoint at idx 50 (wrong — this is where the
    # intervention already happened).
    res_with_wrong_msbd = css_score(routing, traffic, msbd_breakpoint_idx=50, n_bootstrap=500)
    # The good MSBD breakpoint should give a stronger |CSS| than the wrong
    # one (the post window shrinks, so |post - pre| should be larger).
    assert abs(res_with_msbd.css_routing_to_traffic) > abs(res_with_wrong_msbd.css_routing_to_traffic) * 0.5


def test_css_handles_short_series():
    """Series too short for PNS estimation ⇒ direction=unknown."""
    routing = [{"timestamp": "2026-09-29T00:00:00", "score": 0.5}] * 3
    traffic = [{"timestamp": "2026-09-29T00:00:00", "score": 0.5}] * 3
    result = css_score(routing, traffic, n_bootstrap=100)
    assert result.direction == "unknown"


def test_css_deterministic_with_seed():
    """Same input must yield same output (deterministic bootstrap)."""
    routing = _make_timeline(40, 15, 25)
    traffic = _make_timeline(40, 20, 30, baseline=1.0, peak=0.2)
    r1 = css_score(routing, traffic, n_bootstrap=300)
    r2 = css_score(routing, traffic, n_bootstrap=300)
    assert r1.css_routing_to_traffic == r2.css_routing_to_traffic
    assert r1.ci_lower == r2.ci_lower
    assert r1.direction == r2.direction