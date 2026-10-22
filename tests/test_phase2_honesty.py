"""Regression tests for the Phase-2 audit (DIAGNOSIS_Phase2_20261022.md).

Each test pins one of the eight diagnosed defects so it cannot silently
return:

  1. the abstention gate must read the posterior, not the blended display
     score (0.6·css + 0.3·innovation + 0.1·TE) × 0.7/0.95;
  2. CSS(R→T) and CSS(T→R) must be measured on the same standardised scale;
  3. an abstention must never be scored as a correct direction;
  4. every baseline must be scored on the same, method-independent set;
  5. ``event_type`` (the ground-truth cause label) must not influence the
     posterior, because the expected direction is derived from it;
  6. ``_find_breakpoint`` must report "no breakpoint" on flat/all-zero series
     instead of returning the midpoint;
  7. TE needs one surrogate null per direction and must not commit without
     significance;
  8. correlated channels must not multiply into confidence.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from agents.causal_attribution import CausalAttributionEngine  # noqa: E402
from agents.causal_baselines import (  # noqa: E402
    _to_aligned_series,
    transfer_entropy_baseline,
)
from agents.css_engine import (  # noqa: E402
    CSSResult,
    _align_series,
    _bucketize_pair,
    _find_breakpoint,
    _is_prequantised,
    _pns_estimate,
    _split_at_breakpoint,
    bayesian_synthesize,
    css_score,
)
from scripts.eval_hcaf_vs_baselines import (  # noqa: E402
    posterior_to_css_direction,
    split_merged_timeline,
)

pytestmark = pytest.mark.fast


def _tl(values):
    return [
        {"timestamp": f"2026-09-29T00:{i:02d}:00", "score": float(v)}
        for i, v in enumerate(values)
    ]


# ── Defect 1: the gate reads the posterior, not the blended score ──────────

def test_abstention_gate_reads_posterior_and_is_wired():
    import agents.causal_attribution as ca
    import config

    src = Path(ca.__file__).read_text(encoding="utf-8")
    # The blend may still be computed for reporting, but not used as a gate.
    assert "HCAF_MIN_POSTERIOR" in src
    assert "max_posterior < HCAF_MIN_POSTERIOR" in src
    assert "confidence or 0.0) < HCAF_MIN_DIRECTION_CONFIDENCE" not in src
    assert hasattr(config, "HCAF_MIN_POSTERIOR")


def test_flat_event_abstains_with_a_statistical_reason():
    """No CSS signal ⇒ the engine must abstain and say why."""
    engine = CausalAttributionEngine()
    flat = _tl([0.1] * 20)
    result = engine.analyze(
        routing_timeline=flat,
        traffic_timeline=flat,
        target_as="AS0",
        routing_context={},
        traffic_context={},
    )
    assert result.direction == "unknown"
    assert result.evidence_support["abstained"] is True
    assert result.evidence_support["abstain_reason"] in (
        "no_supported_direction", "css_not_significant",
        "posterior_below_floor", "direction_flags_disagree",
    )
    # A flat pair produces a uniform-ish posterior, so the *floor* is what
    # decides; the label must say so instead of blaming missing evidence.
    assert result.evidence_support["abstain_reason"] == "posterior_below_floor"


# ── Defect 2: one scale for both CSS directions ────────────────────────────

def test_pns_effect_is_scale_invariant():
    """Multiplying a series by 10 must not change its standardised effect."""
    pre = [10.0, 10.4, 9.8, 10.1, 9.9, 10.3, 10.2, 9.7]
    post = [x + 0.6 for x in pre]
    base = _pns_estimate(pre, post, n_bootstrap=200, seed=7)
    scaled = _pns_estimate([x * 10 for x in pre], [x * 10 for x in post],
                           n_bootstrap=200, seed=7)
    assert base["point"] == pytest.approx(scaled["point"], rel=1e-9)
    assert base["ci_lower"] == pytest.approx(scaled["ci_lower"], rel=1e-9)


def test_css_directions_are_dimensionless():
    """Both CSS values are Cohen's d, so |CSS| ≤ ~5 for any input scale."""
    routing = [0.0] * 10 + [1000.0] * 2 + [0.0] * 10
    traffic = [50.0] * 12 + [1.0] * 10
    result = css_score(_tl(routing), _tl(traffic), n_bootstrap=300)
    assert abs(result.css_routing_to_traffic) < 10.0
    assert abs(result.css_traffic_to_routing) < 10.0


# ── Defect 3: abstention is not a correct answer ───────────────────────────

def test_per_event_csv_has_no_review_metric():
    src = (_ROOT / "scripts" / "build_per_event_30_csv.py").read_text(encoding="utf-8")
    assert "is_review_correct" not in src
    assert "_review" not in src
    assert "_correct" in src and "_wrong" in src and "_abstain" in src


def test_eval_script_scores_all_rows_and_adds_majority_baseline():
    """Defects 3 + 4: no HCAF-derived denominator, and a majority control."""
    src = (_ROOT / "scripts" / "eval_hcaf_vs_baselines.py").read_text(encoding="utf-8")
    # The old denominator:
    assert 'evaluable = [r for r in per_row if r["hcaf_correct"] is not None]' not in src
    # The majority-class control and the abstention-aware tally must exist.
    assert "__always_rt__" in src
    assert "Always R→T" in src
    assert '"abstain"' in src or "'abstain'" in src


def test_replay_summary_is_derived_from_the_jsonl():
    """The summary must not hard-code a replay size that the log contradicts."""
    src = (_ROOT / "scripts" / "summarize_alert_replay.py").read_text(encoding="utf-8")
    assert '"raw_alerts_enqueued": 150' not in src
    assert "alerts_submitted" in src
    assert "len(processed)" in src


# ── Defect 5: event_type must not influence the verdict ────────────────────

def test_event_type_is_not_a_prior():
    css = CSSResult(direction="unknown", confidence=0.0, is_causal=False)
    channel = {
        "direction": "routing_to_traffic",
        "likelihood": {
            "routing_to_traffic": 1.6,
            "traffic_to_routing": 1.0,
            "independent": 1.0,
        },
    }
    leak = bayesian_synthesize(css, {"msbd": channel}, event_type="route_leak")
    outage = bayesian_synthesize(css, {"msbd": channel}, event_type="outage")
    assert leak["posterior"] == outage["posterior"]
    assert leak["direction"] == outage["direction"]


def test_label_driven_channels_are_gone():
    src = (_ROOT / "agents" / "causal_attribution.py").read_text(encoding="utf-8")
    assert 'evidence_channels["routing_event_type"]' not in src
    assert "_dom_dir" not in src
    # The withdrawal signal survives only for the observable outage+withdrawal
    # case, never as a cause-label mapping.
    assert 'evt in ("route_leak", "roa_misconfig")' not in src


# ── Defect 6: flat series have no breakpoint ───────────────────────────────

@pytest.mark.parametrize("series", [[0.0] * 12, [5.0] * 12, [0.0] * 4])
def test_find_breakpoint_returns_sentinel_on_degenerate_series(series):
    assert _find_breakpoint(series) == -1


def test_find_breakpoint_still_detects_a_real_shift():
    series = [0.0] * 10 + [1.0] * 10
    assert _find_breakpoint(series) > 0


def test_split_at_breakpoint_abstains_instead_of_midpoint_split():
    flat = [0.0] * 12
    r_pre, t_pre, r_post, t_post, bp = _split_at_breakpoint(flat, flat)
    assert (r_pre, t_pre, r_post, t_post) == ([], [], [], [])
    assert bp == -1


def test_css_abstains_on_flat_routing_with_no_breakpoint_message():
    n = 16
    routing = _tl([0.0] * n)
    traffic = _tl([1.0] * 8 + [0.2] * 8)
    result = css_score(routing, traffic, n_bootstrap=100)
    assert result.direction == "unknown"
    assert result.details.get("reason") in (
        "no detectable breakpoint", "flat routing series", "no routing intervention"
    )


# ── Defect 7: TE needs per-direction nulls and significance ────────────────

def test_te_exposes_two_nulls_and_a_significance_flag():
    routing = _tl([0.1] * 15 + [1.0] * 10 + [0.1] * 15)
    traffic = _tl([1.0] * 16 + [0.2] * 9 + [1.0] * 15)
    result = transfer_entropy_baseline(routing, traffic, bins=2, n_perm=60)
    d = result.details
    assert {"null_rt_mean", "null_tr_mean", "p_value_rt", "p_value_tr",
            "sig_rt", "sig_tr", "significant"} <= set(d)
    # A committed direction must have cleared its own null.
    if result.direction == "routing_to_traffic":
        assert d["sig_rt"] and d["p_value_rt"] < 0.05
    if result.direction == "traffic_to_routing":
        assert d["sig_tr"] and d["p_value_tr"] < 0.05
    if result.direction == "unknown":
        assert result.confidence == 0.0


def test_te_docstring_documents_two_nulls():
    doc = inspect.getdoc(transfer_entropy_baseline) or ""
    assert "separate null" in doc
    assert "p_d < 0.05" in doc


# ── Defect 8: correlated channels are pooled, not multiplied ───────────────

def test_repeated_channels_do_not_inflate_confidence():
    css = CSSResult(direction="unknown", confidence=0.0, is_causal=False)
    channel = {
        "direction": "routing_to_traffic",
        "likelihood": {
            "routing_to_traffic": 2.0,
            "traffic_to_routing": 0.5,
            "independent": 1.0,
        },
    }
    one = bayesian_synthesize(css, {"ch": channel})
    five = bayesian_synthesize(css, {f"ch{i}": channel for i in range(5)})
    # Five copies of one signal are one signal: the posterior must not grow.
    assert five["posterior"]["routing_to_traffic"] == pytest.approx(
        one["posterior"]["routing_to_traffic"], abs=1e-6
    )
    assert five["redundancy"] == pytest.approx(5.0)


def test_css_enters_as_a_channel_not_as_a_prior():
    css = CSSResult(
        direction="routing_to_traffic",
        css_routing_to_traffic=1.5,
        css_traffic_to_routing=0.2,
        is_causal=True,
        confidence=0.8,
    )
    synth = bayesian_synthesize(css, {})
    assert synth["direction"] == "routing_to_traffic"
    assert synth["channels"].get("css_pns") == "routing_to_traffic"
    # Bounded likelihood, not the old 10:1 prior.
    assert synth["posterior"]["routing_to_traffic"] <= 5 / 6 + 1e-9



# ── Round-2 defects (second 2026-10-22 sweep) ──────────────────────────────
# The first sweep fixed the *evaluation* of the engine.  This sweep fixes
# defects that made the *engine itself* behave differently in the live
# workflow than in the evaluation, plus three metric bugs in the table
# builders.

def _irregular_log(n=24, step_min=7, score=0.9, start="2026-09-29T00:00:00"):
    """Raw event log: one entry per detected anomaly, irregular spacing."""
    from datetime import datetime, timedelta
    t0 = datetime.fromisoformat(start)
    return [
        {
            "timestamp": (t0 + timedelta(minutes=step_min * i + (i % 3))).isoformat(),
            "score": score,
            "event_type": "anomaly",
        }
        for i in range(n)
    ]


def test_raw_event_log_is_bucketed_not_passed_through():
    """A raw event log must not be mistaken for a pre-bucketed series.

    The old detector only required distinct timestamps, which is true of every
    event log.  ``_extract_scores`` then returned the detector score once per
    event, ``_find_breakpoint`` correctly found no break in the resulting
    near-constant series, and CSS abstained on every live run.
    """
    raw = _irregular_log()
    assert _is_prequantised(raw) is False
    r, t = _bucketize_pair(raw, raw)
    assert len(r) == len(t) >= 4
    assert len(set(r)) > 1, "bucketing must produce the quiet gaps between events"


def test_uniform_pre_bucketed_series_passes_through():
    tl = _tl([1.0, 0.0, 2.0, 0.0, 3.0, 0.0, 1.0, 0.0])
    assert _is_prequantised(tl) is True


def test_constant_pre_bucketed_series_is_not_rebucketised():
    """A flat but already-bucketed series must keep its resolution.

    The detection rule keys on schema (raw events carry ``raw_event`` /
    ``event_type``) and grid uniformity — not on score variance — so a
    constant 120-bucket series is still passed through and abstains on its
    own merits instead of being re-aggregated into 5-minute buckets.
    """
    tl = _tl([1e-9] * 30)
    assert _is_prequantised(tl) is True


def test_unequal_series_truncate_instead_of_zero_padding():
    """Never invent 'measured, no anomaly' buckets for an unobserved window."""
    assert _align_series([1.0, 2.0, 3.0], [9.0, 9.0]) == ([1.0, 2.0], [9.0, 9.0])
    r, t = _to_aligned_series(_tl([1, 2, 3]), _tl([7, 8]))
    assert r == [1.0, 2.0] and t == [7.0, 8.0]


def test_permutation_p_value_never_reaches_zero():
    pre = [0.0] * 12
    post = [10.0] * 12
    est = _pns_estimate(pre, post, n_bootstrap=200, seed=3)
    assert est["p_value"] > 0.0
    assert est["estimable"] is True


def test_single_sided_analysis_does_not_assert_a_direction():
    """Routing-only input cannot identify a direction — even for a hijack."""
    engine = CausalAttributionEngine()
    res = engine.analyze(
        routing_timeline=_tl([0.9] * 5),
        traffic_timeline=[],
        routing_context={"event_type": "hijack", "affected_as_count": 8},
        traffic_context={"traffic_drop_ratio": 0.6},
    )
    assert res.direction == "unknown"
    assert res.routing_caused_traffic is False
    assert res.is_causal is False


def test_cic_cascade_reports_scope_not_a_direction():
    """The propagation model assumes R→T; that assumption cannot be evidence."""
    src = (_ROOT / "agents" / "causal_attribution.py").read_text(encoding="utf-8")
    assert (
        'return {"direction": "unknown", "strength": strength, "significant": sig,'
        in src
    )
    assert "direction_note" in src


def test_no_event_type_channel_reaches_the_posterior():
    src = (_ROOT / "agents" / "causal_attribution.py").read_text(encoding="utf-8")
    assert "routing_withdrawal_signal=_routing_withdrawal_signal" not in src
    assert 'evt = routing_context.get("event_type"' not in src
    # It is still called, but with no label-derived signal.
    assert "routing_withdrawal_signal=None" in src


def test_degenerate_bucket_grid_has_distinct_timestamps():
    """All-events-in-one-instant must not produce two identical buckets."""
    merged = [
        {"timestamp": "2026-09-29T00:00:00", "source": "routing", "severity": 1.0},
        {"timestamp": "2026-09-29T00:00:00", "source": "routing", "severity": 1.0},
        {"timestamp": "2026-09-29T00:00:00", "source": "traffic", "severity": 2.0},
    ]
    r, t = split_merged_timeline(merged)
    assert len(r) == len(t) == 2
    assert r[0]["timestamp"] != r[1]["timestamp"]
    # The traffic series must carry the traffic count, not a copy of routing's.
    assert r[0]["score"] != t[0]["score"]


def test_css_direction_is_the_argmax_not_the_first_key():
    assert posterior_to_css_direction(
        {"routing_to_traffic": 0.35, "traffic_to_routing": 0.40, "independent": 0.25}
    ) == "traffic_to_routing"
    # Dominant hypothesis is "independent" → no directional verdict.
    assert posterior_to_css_direction(
        {"routing_to_traffic": 0.30, "traffic_to_routing": 0.30, "independent": 0.40}
    ) == "unknown"
    # Uniform posterior (no channel contributed) → abstain.
    assert posterior_to_css_direction(
        {"routing_to_traffic": 1 / 3, "traffic_to_routing": 1 / 3, "independent": 1 / 3}
    ) == "unknown"
    assert posterior_to_css_direction({}) == "unknown"
