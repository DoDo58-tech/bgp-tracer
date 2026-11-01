"""PADDLE must refuse what it cannot identify, and commit what it can.

The estimator is a veto chain, so most of these tests pin down
*refusals*: the geometries where a score-based method would still emit a
direction.  The positive cases plant a control-plane edge before a
traffic drop and require the commitment.

The geometries are built on a wall-clock grid rather than on two
abstract sequences, because the estimator's whole claim is that the two
sides are measured at the *same moment* and against the *same clock*
counterfactual.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

import pytest

from agents.control_plane import ControlPlaneSeries, same_clock_baseline
from agents.paddle_attribution import (
    PADDLE_PROTOCOL,
    REASONS,
    R2T,
    T2R,
    UNKNOWN,
    attribute,
    protocol_hash,
    traffic_deviation,
)

STEP = 300
N = 120
ORIGIN = datetime(2025, 1, 1, 0, 0)
CHANNELS = (
    "own_volume",
    "own_withdrawal",
    "volume",
    "withdrawal",
    "origin_change",
    "path_change",
)


def make_control(
    *,
    tau: int = 60,
    level: float = 10.0,
    after: float = 1.0,
    channel: str = "own_volume",
    days: int = 4,
    jitter: float = 0.10,
    seed: int = 7,
):
    """A control plane that is normal until ``tau`` and then moves.

    The baseline is four ordinary days whose rates carry the natural
    day-to-day variation of a real network.  Without that variation the
    placebo null would be exactly zero and the exclusivity test could
    not be exercised at all.
    """
    rng = random.Random(seed)
    stamps = [ORIGIN + timedelta(seconds=STEP * i) for i in range(N)]

    buckets = {}
    baseline_stamps = []
    for day in range(1, days + 1):
        base_day = ORIGIN - timedelta(days=day)
        for i in range(N):
            stamp = base_day + timedelta(seconds=STEP * i)
            buckets[stamp] = {
                "own_announcement_count": level * (1.0 + rng.uniform(-jitter, jitter)),
                "own_withdrawal_count": level * (1.0 + rng.uniform(-jitter, jitter)),
                "announcement_count": level * (1.0 + rng.uniform(-jitter, jitter)),
                "withdrawal_count": level * (1.0 + rng.uniform(-jitter, jitter)),
                "num_ori_change": level * (1.0 + rng.uniform(-jitter, jitter)),
                "num_path_change": level * (1.0 + rng.uniform(-jitter, jitter)),
            }
        baseline_stamps.append(base_day)

    baseline_stamps = sorted(buckets)
    channels = {name: [0.0] * N for name in CHANNELS}
    baseline_channels = {name: [0.0] * len(baseline_stamps) for name in CHANNELS}
    for i, stamp in enumerate(baseline_stamps):
        for name in CHANNELS:
            baseline_channels[name][i] = float(
                buckets[stamp].get(_FEATURE[name], 0.0))

    for i in range(N):
        channels[channel][i] = level if i < tau else after

    return ControlPlaneSeries(
        stamps=stamps,
        channels=channels,
        baseline=baseline_channels,
        baseline_stamps=baseline_stamps,
        baseline_bucket_map=buckets,
        # Only the channel under test is instrumented.  The others are
        # carried at zero because the fixture does not measure them, and
        # an unmeasured channel must not be read as a silent one.
        measured_channels=[channel],
    )


_FEATURE = {
    "own_volume": "own_announcement_count",
    "own_withdrawal": "own_withdrawal_count",
    "volume": "announcement_count",
    "withdrawal": "withdrawal_count",
    "origin_change": "num_ori_change",
    "path_change": "num_path_change",
}


def make_response(*, tau: int = 60, level: float = 10.0, after: float = 1.0):
    """A data plane that is normal until ``tau`` and then falls."""
    out = []
    for i in range(N):
        stamp = ORIGIN + timedelta(seconds=STEP * i)
        value = level if i < tau else after
        out.append({
            "timestamp": stamp,
            "raw_event": {"current_value": value, "historical_mean": level},
        })
    return out


# ── The data plane's deviation ─────────────────────────────────────────


def test_traffic_deviation_keeps_the_sign_of_a_drop():
    """A fall must read negative, whatever the z-score's sign says."""
    point = {"raw_event": {
        "current_value": 1.0,
        "historical_mean": 10.0,
        "z_score": 9.0,          # the detector records magnitude alone
    }}
    assert traffic_deviation(point) == pytest.approx(-0.9)


def test_traffic_deviation_keeps_the_sign_of_a_rise():
    point = {"raw_event": {
        "current_value": 15.0,
        "historical_mean": 10.0,
        "z_score": 5.0,
    }}
    assert traffic_deviation(point) == pytest.approx(0.5)


def test_traffic_deviation_refuses_the_placeholder_baseline():
    """The ``0.001`` sentinel is not a measurement.

    A consumer that accepts it sees a deviation of thousands of standard
    deviations with the sign inverted for every outage.
    """
    point = {"raw_event": {"value": 0.207, "mean": 0.001, "z_score": 8.24}}
    # The placeholder is refused, so only the z-score's magnitude is left
    # -- and it cannot be a *rise*.
    assert traffic_deviation(point) < 0


def test_traffic_deviation_prefers_the_detector_baseline():
    point = {"raw_event": {
        "value": 0.206972,
        "mean": 0.001,                       # the serialised placeholder
        "current_value": 0.206972,
        "historical_mean": 0.15536625,       # the detector's own baseline
    }}
    assert traffic_deviation(point) == pytest.approx(
        (0.206972 - 0.15536625) / 0.15536625)


# ── The counterfactual ─────────────────────────────────────────────────


def test_same_clock_baseline_spans_midnight():
    """A window crossing midnight keeps the nearest counterfactual day.

    The 03:00 slot of the window's own calendar date is, physically, the
    *previous* day's 03:00.  A calendar-day subtraction calls it "zero
    days old" and drops it, so the window loses its most relevant day
    and keeps its least relevant one.
    """
    window_start = datetime(2025, 1, 24, 21, 30)
    window_end = datetime(2025, 1, 25, 6, 0)
    buckets = {}
    # The window's own slots must not enter the baseline.
    stamp = window_start
    while stamp <= window_end:
        buckets[stamp] = {"announcement_count": 999.0}
        stamp += timedelta(minutes=5)
    # The nearest preceding day, at the same clock position.
    for i in range(72):
        stamp = datetime(2025, 1, 24, 0, 0) + timedelta(minutes=5 * i)
        buckets[stamp] = {"announcement_count": 77.0}
    # Older days, at the same clock position.
    for day, value in ((1, 10.0), (2, 20.0), (3, 30.0), (4, 40.0),
                       (5, 50.0), (6, 60.0), (7, 70.0)):
        stamp = datetime(2025, 1, 24) - timedelta(days=day)
        buckets[stamp.replace(hour=3, minute=0)] = {"announcement_count": value}

    baseline = same_clock_baseline(buckets, "volume", window_start, window_end)
    # The nearest day (77) counts and so does the sixth-oldest (60);
    # the seventh-oldest (70) falls outside the week-long horizon.  The
    # horizon is shared with the archive, so the counterfactual and the
    # placebo are measured over the same period.
    assert baseline["03:00"] == pytest.approx(
        (77.0 + 10.0 + 20.0 + 30.0 + 40.0 + 50.0 + 60.0) / 7)
    # The early-morning positions of the window's own calendar date are
    # the previous day's early-morning positions, and they are kept.
    assert baseline["00:00"] == pytest.approx(77.0)
    assert baseline["05:55"] == pytest.approx(77.0)
    # The window's own 21:30 slot has no preceding day behind it in this
    # fixture, so it has no counterfactual -- an absent baseline, not a
    # zero one.
    assert baseline["21:30"] == 0.0


def test_same_clock_baseline_excludes_the_window_itself():
    window_start = datetime(2025, 1, 24, 10, 0)
    window_end = datetime(2025, 1, 24, 12, 0)
    buckets = {}
    stamp = window_start
    while stamp <= window_end:
        buckets[stamp] = {"announcement_count": 999.0}
        stamp += timedelta(minutes=5)
    baseline = same_clock_baseline(buckets, "volume", window_start, window_end)
    assert all(value == 0.0 for value in baseline.values())


# ── The vetoes ─────────────────────────────────────────────────────────


def test_short_control_plane_abstains():
    control = ControlPlaneSeries()
    v = attribute(control, make_response())
    assert v.direction == UNKNOWN
    assert v.reason == "series_too_short"
    assert v.reason in REASONS


def test_flat_response_abstains():
    """A data plane that did not fall has no causal question to answer."""
    response = []
    for i in range(N):
        stamp = ORIGIN + timedelta(seconds=STEP * i)
        response.append({
            "timestamp": stamp,
            "raw_event": {"current_value": 10.0, "historical_mean": 10.0},
        })
    v = attribute(make_control(), response)
    assert v.direction == UNKNOWN
    assert v.reason == "response_series_flat"


def test_flat_control_plane_abstains():
    """No control-plane movement, no claim -- however clean the traffic."""
    v = attribute(make_control(after=10.0), make_response())
    assert v.direction == UNKNOWN
    assert v.reason == "control_plane_flat"


def test_a_silent_control_plane_commits():
    """An outage's control-plane signature is silence, not flatness.

    The target stops announcing its own routes, so the channel is flat
    at zero during the incident while ordinary days carry a rate.  A
    rule that discards a constant channel as "no observation" throws
    away the one measurement an outage produces, and the claim it
    supports with it.
    """
    control = make_control(after=0.0)
    v = attribute(control, make_response())
    assert v.reason == "committed", v.as_dict()
    assert v.direction == R2T
    assert v.channel == "own_volume"
    assert v.tau_control == pytest.approx(0.0, abs=1e-6)


def test_an_unmeasured_channel_is_not_a_silent_one():
    """A channel the instrument never carried is not a silent channel.

    The fixture instruments one channel.  The others are zero because
    nothing measured them, which is a different thing from measuring
    zero.  Reading the unmeasured ones as silence would let the
    estimator claim a cause from a channel that does not exist.
    """
    control = make_control(after=10.0)
    assert "own_withdrawal" not in control.measured_channels
    v = attribute(control, make_response())
    assert v.direction == UNKNOWN
    assert v.reason == "control_plane_flat"


def test_planted_outage_commits_routing_to_traffic():
    """The target falls silent, the traffic follows, the direction commits."""
    v = attribute(make_control(), make_response())
    assert v.reason == "committed", v.as_dict()
    assert v.direction == R2T
    assert v.vetoes["V1"] == "pass"
    assert v.vetoes["V2"] == "pass"
    assert v.channel == "own_volume"
    # The control plane was silent at the trough: the fixture plants a
    # rate of 1.0 against a normal rate of 10.0, so the displacement is
    # a tenth of normal.  The measurement is the median over the window,
    # so it reads the silence rather than the average of the silence and
    # the normal slots that precede it.
    assert v.tau_control == pytest.approx(0.1, abs=0.02)
    assert v.effect == pytest.approx(0.9, abs=0.02)
    # The incident beat the placebo null decisively: an ordinary day
    # reaching this silence is unlikely.
    assert v.exclusivity_probability <= PADDLE_PROTOCOL["max_placebo_probability"]


def test_a_burst_does_not_mask_the_silence_behind_it():
    """One enormous slot must not stand for the window's level.

    A network that re-announces its table emits a single huge slot
    right before it goes quiet.  The mean over that window is the
    burst; the median is the silence.  Reading the burst would turn an
    outage into a surge and the congruence test would refuse the very
    claim the window supports.
    """
    control = make_control()
    stamps = control.stamps
    values = control.channel("own_volume")
    trough_index = stamps.index(ORIGIN + timedelta(seconds=STEP * 60))
    values[trough_index - 1] = 8159.0

    v = attribute(control, make_response())
    assert v.reason == "committed", v.as_dict()
    assert v.tau_control < 0.5, v.tau_control


def test_control_plane_edge_after_the_trough_is_not_a_cause():
    """A routing change that appears after the traffic already fell cannot
    have caused it."""
    v = attribute(make_control(tau=90), make_response(tau=60))
    assert v.direction == UNKNOWN
    assert v.reason in ("no_control_plane_edge", "inadmissible_precedence")
    assert v.vetoes["V1"] != "pass"


def test_disjoint_scope_vetoes_the_claim():
    v = attribute(
        make_control(), make_response(),
        routing_scope=["64500"], series_scope=["15169"],
    )
    assert v.direction == UNKNOWN
    assert v.reason == "provenance_disjoint"
    assert v.vetoes["V3"] == "fail"


def test_shared_scope_passes_provenance():
    v = attribute(
        make_control(), make_response(),
        routing_scope=["64500", "15169"], series_scope=["15169", "3356"],
    )
    assert v.vetoes["V3"] == "pass"
    assert v.tests["provenance"]["shared"] == 1


def test_unknown_scope_suspends_provenance_without_refuting():
    """A missing scope must not be laundered into a refutation."""
    v = attribute(make_control(), make_response())
    assert v.vetoes["V3"] == "suspend"
    assert v.direction == R2T


def test_contradicted_signs_veto_the_claim():
    """A routing surge alongside a traffic collapse is not one phenomenon."""
    control = make_control(after=20.0)          # the control plane *rose*
    v = attribute(control, make_response())      # the traffic fell
    assert v.direction == UNKNOWN
    assert v.reason == "mirror_contradicted"
    assert v.vetoes["V4"] == "fail"


def test_a_bare_surge_is_not_a_cause():
    """A control plane that rose while the traffic fell is refuted, not
    explained."""
    control = make_control(level=1.0, after=20.0)
    v = attribute(control, make_response(level=10.0, after=1.0))
    assert v.direction == UNKNOWN
    assert v.vetoes["V4"] == "fail"


def test_withdrawal_is_not_read_as_a_reaction():
    """A withdrawal is what a failure looks like, and a failure and a
    traffic drop share a common cause."""
    v = attribute(make_control(), make_response(), routing_mechanism="withdrawal")
    if v.direction == T2R:
        assert v.reason == "reactive_incompatible"


def test_unknown_mechanism_does_not_claim_a_reaction():
    """The absence of an annotation is not evidence that a reaction
    occurred."""
    v = attribute(make_control(), make_response(), routing_mechanism=None)
    assert v.direction in (R2T, UNKNOWN)
    if v.direction == UNKNOWN:
        assert v.reason == "mechanism_unknown"


def test_no_commit_below_the_exclusivity_floor():
    """A displacement that cannot beat the placebo null is not evidence."""
    v = attribute(
        make_control(), make_response(),
        protocol={"max_placebo_probability": 0.0},
    )
    assert v.direction == UNKNOWN
    assert v.reason == "not_exclusive"
    assert v.vetoes["V2"] == "fail"


def test_no_commit_below_the_absolute_displacement_floor():
    v = attribute(
        make_control(), make_response(),
        protocol={"min_absolute_displacement": 0.99},
    )
    assert v.direction == UNKNOWN
    assert v.reason == "not_exclusive"


def test_verdicts_are_deterministic_and_protocol_identified():
    a = attribute(make_control(), make_response()).as_dict()
    b = attribute(make_control(), make_response()).as_dict()
    assert a == b
    assert a["protocol_hash"] == protocol_hash()
    assert protocol_hash() != protocol_hash(
        dict(PADDLE_PROTOCOL, max_placebo_probability=0.99))


def test_every_reason_has_a_name():
    """A new code path cannot ship without a name an operator can read."""
    observed = {
        attribute(ControlPlaneSeries(), make_response()).reason,
        attribute(make_control(), make_response()).reason,
        attribute(make_control(after=10.0), make_response()).reason,
        attribute(make_control(tau=90), make_response(tau=60)).reason,
        attribute(make_control(level=1.0, after=20.0), make_response()).reason,
        attribute(make_control(), make_response(),
                  routing_scope=["a"], series_scope=["b"]).reason,
    }
    assert observed <= set(REASONS)


def test_the_estimator_commits_only_one_direction_per_pair():
    """Swapping the two sides cannot reproduce the same direction.

    The estimator is asymmetric by construction: it anchors on the data
    plane's trough, so the two orderings are not the same measurement.
    """
    forward = attribute(make_control(), make_response())
    assert forward.direction == R2T

    # The same routing series, but the *traffic* side is flat: the
    # estimator must not manufacture a direction out of the control
    # plane alone.
    flat = []
    for i in range(N):
        stamp = ORIGIN + timedelta(seconds=STEP * i)
        flat.append({
            "timestamp": stamp,
            "raw_event": {"current_value": 10.0, "historical_mean": 10.0},
        })
    backward = attribute(make_control(), flat)
    assert backward.direction == UNKNOWN


def test_the_production_consumers_read_the_verdict_without_raising():
    """The verdict's public surface has to match what the pipeline reads.

    The pipeline builds its attribution dict from a fixed list of
    verdict attributes, and the whole stage sits inside an
    ``except AttributeError``.  So a field renamed in the estimator does
    not raise -- it silently turns every committed verdict into a failed
    stage, and the paper's causal numbers stop being produced without a
    single error anywhere.
    """
    from workflow_engine import paddle_explanation

    verdict = attribute(make_control(), make_response())
    assert verdict.committed, verdict.as_dict()

    # Every attribute the production path reads off the verdict.
    for name in ("direction", "reason", "vetoes", "channel", "lag_seconds",
                 "effect", "exclusivity_probability", "tau_response",
                 "tau_control", "baseline_displacement", "mechanism", "tests"):
        assert hasattr(verdict, name), (
            f"CausalVerdict has no attribute {name!r}; the production "
            f"pipeline reads it and would fail the whole causal stage"
        )

    # The explanation the report renders, on a committed verdict.
    assert "PADDLE committed" in paddle_explanation(verdict)

    # And the post-react attribution dict the workflow builds.
    attribution = {
        "direction": verdict.direction if verdict.committed else "unknown",
        "committed": verdict.committed,
        "reason": verdict.reason,
        "vetoes": dict(verdict.vetoes),
        "channel": verdict.channel,
        "lag": verdict.lag_seconds,
        "effect": verdict.effect,
        "exclusivity_probability": verdict.exclusivity_probability,
        "tau_traffic": (verdict.tau_response.isoformat()
                        if verdict.tau_response else None),
        "tau_routing": verdict.tau_control,
    }
    assert attribution["committed"] is True
    assert attribution["direction"] == R2T
