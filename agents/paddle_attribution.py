"""PADDLE -- Paired Displacement, Difference-in-differences, with Ledger Evidence.

The directional causal estimator, and the only one in this codebase.

The question it answers is physical: when the data plane deviated, had
the control plane already deviated, and by more than it does at this
hour on an ordinary day?

Pairing is the whole idea.  The control plane's rate series is sparse
and bursty, so a change-point search puts its change point wherever
the burst is -- often hours from the incident.  The data plane's
trough is sharp and well located, so the anchor comes from there and
the measurement is taken on the noisy side.

The counterfactual has to be the same clock: the same slots on the
previous days, for the same channel, by the same instrument.  A
bootstrap of the event window against itself would make the null
depend on the anomaly being tested, and a long-run average would
measure the time of day rather than the incident.

Three vetoes decide the outcome:

V1 precedence -- the control plane deviated at or before the trough,
within a bounded propagation time.
V2 exclusivity -- the deviation beats what the same channel shows at
placebo troughs drawn from the same-clock baseline.
V3 scope and congruence -- the routing edge is about the entity the
traffic measures, and the two movements point the same way.  A
withdrawal is never read as a reaction, because a failure and a
traffic drop share a common cause.

The channels are not scored and combined.  Each is a separate physical
hypothesis, and the estimator reports which one, if any, survives.
When the evidence does not support a direction it abstains and says
which veto stopped it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from agents.control_plane import (
    BASELINE_DAYS,
    CONTROL_PLANE_CHANNELS,
    GRID_SECONDS,
    ControlPlaneSeries,
)

R2T = "routing_to_traffic"
T2R = "traffic_to_routing"
UNKNOWN = "unknown"

#: Mechanisms a routing edge can carry.
ROUTING_MECHANISMS = (
    "withdrawal",
    "announcement",
    "path_change",
    "origin_change",
)

#: Mechanisms consistent with an operator *reacting* to observed traffic.
#:
#: ``withdrawal`` is deliberately **absent**.  A withdrawal is what a
#: failure looks like in the control plane, and a failure and a traffic
#: drop share a common cause; treating the withdrawal as a *reaction* to
#: the drop would assert a direction the evidence does not support.
REACTION_COMPATIBLE = ("announcement", "path_change")

#: Every reason this estimator can return.  The evaluator asserts that all
#: observed reasons are members of this tuple, so a new code path cannot ship
#: without a name an operator can read.
REASONS = (
    "series_too_short",
    "control_plane_flat",
    "response_series_flat",
    "no_response_trough",
    "no_control_plane_edge",
    "inadmissible_precedence",
    "lag_out_of_range",
    "not_exclusive",
    "provenance_disjoint",
    "mirror_contradicted",
    "mechanism_unknown",
    "reactive_incompatible",
    "committed",
)

#: Frozen decision rule.  Changing any value changes the operating point and
#: must be reported as a new protocol (``protocol_hash`` identifies it).
PADDLE_PROTOCOL: Dict[str, Any] = {
    # ── Representation ────────────────────────────────────────────────────
    "min_slots": 4,                 # below this the window cannot support a pair
    "min_response_points": 4,       # the data plane needs this many observations
    #: The trough is sought inside the impact window the traffic detector
    #: reported, so it is the one belonging to *this* event.
    "trough_search_hours": 6.0,

    # ── V1: precedence ───────────────────────────────────────────────────
    #: The control plane must be *at or before* the trough.  A routing
    #: change that appears after the data plane already answered cannot
    #: have caused the answer.
    "max_lag_seconds": 5400.0,     # 90 minutes: a propagation bound
    "min_lag_seconds": 0.0,

    # ── V2: exclusivity against the same-clock placebo null ──────────────
    #: The largest probability that an ordinary day is at least as
    #: extreme as the incident.  The null is the empirical tail of the
    #: placebo distribution of the *same* direction, so this is a
    #: significance level and not a ratio.
    "max_placebo_probability": 0.05,
    #: The absolute floor, so a channel that barely moves in both the
    #: incident and the placebo cannot pass on a large ratio alone.
    "min_absolute_displacement": 0.20,
    #: The control plane's displacement must be at least this, measured
    #: as a multiple of the same-clock baseline rate.  "One" is normal.
    "min_relative_displacement": 0.25,
    #: The quantile of the placebo distribution that is used as the null.
    #:
    #: The null is a quantile rather than the maximum because the
    #: maximum of a sample is the least stable statistic available: it
    #: estimates the extreme order statistic from one draw, so a single
    #: ordinary day that happens to contain a re-announcement burst
    #: raises the null by an order of magnitude and no incident can ever
    #: beat it.  The 95th percentile asks the same question -- "is this
    #: more than an ordinary day does?" -- while ignoring the handful of
    #: placebos that are ordinary only by luck.
    "placebo_null_quantile": 0.95,

    # ── V3: scope and congruence ─────────────────────────────────────────
    #: The response must observe at least this many of the entities the
    #: control-plane edge is about.
    "min_scope_overlap": 1,
    #: The two movements must agree in direction.  A routing *surge*
    #: alongside a traffic *collapse* is not the same phenomenon.
    "require_congruent_sign": True,
}


def protocol_hash(cfg: Optional[Dict[str, Any]] = None):
    """Short stable identifier of a protocol, printed into every artefact."""
    data = cfg if cfg is not None else PADDLE_PROTOCOL
    payload = json.dumps({k: data[k] for k in sorted(data)}, sort_keys=True,
                         default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


@dataclass
class CausalVerdict:
    """Outcome of one attribution, with every veto that was evaluated."""

    direction: str = UNKNOWN
    reason: str = ""
    vetoes: Dict[str, str] = field(default_factory=dict)
    #: The data plane's trough, in wall-clock time.
    tau_response: Optional[datetime] = None
    #: The control plane's displacement at that moment, as a multiple of
    #: the same-clock baseline rate.  One means normal.
    tau_control: Optional[float] = None
    #: The physical lag between the control plane's earliest deviation
    #: and the data plane's trough, in seconds.  Positive means the
    #: control plane moved first.
    lag_seconds: Optional[float] = None
    #: The control plane's deviation at the trough, in baseline units.
    effect: Optional[float] = None
    #: The probability that an ordinary day is at least as extreme as
    #: the incident, measured against the placebo null.
    exclusivity_probability: Optional[float] = None
    #: The size of the placebo null, in the same units as the effect.
    baseline_displacement: Optional[float] = None
    channel: str = ""
    mechanism: Optional[str] = None
    tests: Dict[str, Any] = field(default_factory=dict)
    protocol: Dict[str, Any] = field(default_factory=dict)

    @property
    def committed(self):
        return self.direction in (R2T, T2R)

    def as_dict(self, include_protocol: bool = True):
        out: Dict[str, Any] = {
            "direction": self.direction,
            "reason": self.reason,
            "committed": self.committed,
            "vetoes": dict(self.vetoes),
            "tau_response": (self.tau_response.isoformat()
                             if self.tau_response else None),
            "tau_control": (round(float(self.tau_control), 4)
                            if self.tau_control is not None else None),
            "lag_seconds": (round(self.lag_seconds, 2)
                            if self.lag_seconds is not None else None),
            "effect": (round(float(self.effect), 4)
                       if self.effect is not None else None),
            "exclusivity_probability": (
                round(float(self.exclusivity_probability), 6)
                if self.exclusivity_probability is not None else None),
            "baseline_displacement": (
                round(float(self.baseline_displacement), 4)
                if self.baseline_displacement is not None else None),
            "channel": self.channel,
            "mechanism": self.mechanism,
            "tests": self.tests,
        }
        if include_protocol:
            out["protocol"] = self.protocol
            out["protocol_hash"] = protocol_hash(self.protocol)
        return out


# ── The data plane's deviation ─────────────────────────────────────────


def as_float_value(value: Any):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


#: The baseline placeholder the serialised event stream used to carry.
#:
#: ``correlation_analyzer`` wrote ``0.001`` for "the detector did not put
#: a baseline on this anomaly".  A consumer that treats it as a
#: measurement sees a deviation of hundreds of standard deviations, and
#: the sign of the comparison is inverted for every outage -- the
#: placeholder is a sentinel, not an observation, and is refused here.
_PLACEHOLDER_MEAN = 0.001


def is_placeholder_mean(value: float):
    """Whether ``value`` is the sentinel baseline rather than a measurement."""
    return abs(value - _PLACEHOLDER_MEAN) < 1e-12


def traffic_deviation(point: Dict[str, Any]):
    """The signed deviation of one traffic observation from its baseline.

    The sign is the sign of the physical departure: negative means the
    measured quantity fell, which for a traffic series is the impact of
    an incident.

    Two defects in the detector's output make the reconstruction
    necessary.  The stored ``z_score`` carries the magnitude alone --
    an outage that took traffic down by 99.6% appears with a *positive*
    z-score -- so its sign cannot be read.  And the ``mean`` field used
    to be a ``0.001`` placeholder whenever the detector had not put a
    baseline on the anomaly, which a consumer would read as a deviation
    of hundreds of standard deviations.
    """
    raw = point.get("raw_event")
    raw = raw if isinstance(raw, dict) else {}

    value = as_float_value(point.get("current_value"))
    if value is None:
        value = as_float_value(raw.get("current_value"))
    if value is None:
        value = as_float_value(point.get("value"))
    if value is None:
        value = as_float_value(raw.get("value"))

    # The baseline, read from the fields that actually carry a
    # measurement.  The placeholder is recognised and refused, because a
    # baseline of 0.001 is a stand-in for "unknown", not an observation.
    mean = as_float_value(point.get("historical_mean"))
    if mean is None:
        mean = as_float_value(raw.get("historical_mean"))
    if mean is None:
        mean = as_float_value(point.get("baseline_mean"))
    if mean is None:
        mean = as_float_value(raw.get("baseline_mean"))
    if mean is None:
        candidate = as_float_value(point.get("mean"))
        if candidate is None:
            candidate = as_float_value(raw.get("mean"))
        if candidate is not None and not is_placeholder_mean(candidate):
            mean = candidate

    if value is not None and mean is not None and mean != 0:
        # The relative deviation, in the units the estimator compares in.
        return (value - mean) / abs(mean)

    z = as_float_value(point.get("z_score"))
    if z is None:
        z = as_float_value(raw.get("z_score"))
    if z is None:
        return None
    # The stored z-score's sign is not trusted to carry the direction,
    # but its magnitude is the detector's own standardised deviation.
    return -abs(float(z))


def find_trough(
    points: Sequence[Dict[str, Any]],
    *,
    search_from: Optional[datetime] = None,
    search_to: Optional[datetime] = None,
    run_points: int = 2,
):
    """The onset of the data plane's fall.

    The impact of a routing incident on the data plane is a *fall* in
    the measured quantity, so the trough is the moment the incident
    happened.  The search is bounded by the impact window the traffic
    detector reported, so the trough is the one belonging to *this*
    event rather than the worst deviation of the whole record.

    The trough is the **onset** of the fall, not its deepest point.
    An impact holds the measured quantity down for a while, and the
    deepest observation of such a plateau is wherever the noise
    happened to reach its lowest, which can be hours after the cause.
    Anchoring on it made the lag between the two edges a property of
    the noise, and two edges that moved *together* could be ordered by
    it.  The onset is the first observation of a run of falling
    observations, which is where the cause has to have been.

    The run that is chosen is the **deepest** one, not the first.  A
    series that wobbles crosses the floor often, and taking the first
    crossing anchors the measurement on whichever noise excursion
    happened to come first---which for a real drop is usually not the
    drop.  Choosing the deepest run and reporting its onset keeps both
    properties at once: the anchor is the onset of the event rather
    than of the noise, and a transient wobble cannot displace a
    sustained fall.
    """
    entries: List[Tuple[datetime, float]] = []
    for point in points:
        stamp = point.get("timestamp")
        if not isinstance(stamp, datetime):
            continue
        if search_from is not None and stamp < search_from:
            continue
        if search_to is not None and stamp > search_to:
            continue
        deviation = traffic_deviation(point)
        if deviation is None:
            continue
        entries.append((stamp, deviation))
    if not entries:
        return None

    entries.sort(key=lambda item: item[0])

    # The floor below which an observation counts as a fall.  It is
    # relative to the series' own scale, so that "fell" means "fell by
    # more than the series normally moves", and it is also bounded from
    # below, so that a series whose movements are all large does not
    # make its own fall too small to be seen.
    magnitude = float(np.median([abs(dev) for _, dev in entries])) or 0.0
    floor = -max(1.5 * magnitude, 0.02)

    # Every run of consecutive observations below the floor, with the
    # run's own depth and its first observation.
    runs: List[Tuple[float, int]] = []
    start = None
    for index, (_, deviation) in enumerate(entries):
        if deviation < floor:
            if start is None:
                start = index
        else:
            if start is not None and index - start >= run_points:
                runs.append((min(entries[i][1] for i in range(start, index)),
                             start))
            start = None
    if start is not None and len(entries) - start >= run_points:
        runs.append((min(entries[i][1] for i in range(start, len(entries))),
                     start))

    if runs:
        # The deepest run wins; a tie goes to the earlier one, so the
        # answer is stable.
        depth, start = min(runs, key=lambda item: (item[0], item[1]))
        return entries[start]

    # Nothing fell persistently.  The deepest observation is then the
    # best available answer, and it is reported as such.
    best = min(entries, key=lambda item: item[1])
    return best


# ── The control plane's deviation, paired with the trough ─────────────


def silent_against_live_baseline(control: ControlPlaneSeries, channel: str):
    """Whether the channel is silent while ordinary days were not.

    A constant event-window series is normally read as "the control plane
    did not move".  For an outage that reading is backwards: the target
    stops announcing its own routes, so the channel is *flat at zero*
    precisely when the incident happened, and the same clock slots on
    the preceding days carry a non-zero rate.  The silence is the
    measurement.

    So the question is not "is the series flat" but "is it flat against
    a live baseline".  A channel the instrument never carried is zero
    everywhere, baseline included, and there is nothing to compare it
    against; that one was not measured at all.
    """
    if not control.is_measured(channel):
        return False
    values = control.channel(channel)
    if len(values) < 2 or float(np.ptp(values)) >= 1e-9:
        return False
    if max(values) > 0:
        # Flat, but not at zero: the level simply did not change.
        return False
    baseline = control.baseline_channel(channel)
    return any(v > 0 for v in baseline)


def slot_index(stamps: Sequence[datetime], stamp: datetime):
    """The index of the slot that contains ``stamp``."""
    if not stamps:
        return None
    offset = (stamp - stamps[0]).total_seconds()
    index = int(offset // GRID_SECONDS)
    if not (0 <= index < len(stamps)):
        return None
    return index


def control_displacement(
    control: ControlPlaneSeries,
    channel: str,
    trough: datetime,
    *,
    half_width_slots: int = 3,
):
    """The control plane's departure from normal at the data plane's trough.

    The measurement is a **paired difference-in-differences**:

    * the *treatment* arm is the control plane's rate in the slots
      around the trough;
    * the *counterfactual* arm is the same clock slots on the previous
      days, for the same channel, measured by the same instrument.

    The displacement is reported as a multiple of the counterfactual:
    one is normal, zero is silence, three is a threefold surge.

    The two arms are summarised by their **median**, not their mean.
    BGP announcement counts are heavy-tailed: a network that re-announces
    its whole table after a session reset emits one enormous slot, and
    a mean over a window containing it is set by that slot alone.  In
    an outage that slot is the *last* burst before the silence, so a
    mean reads the outage as a hundredfold surge and the congruence
    test then refuses an outage whose whole signature is the opposite.

    The median answers the question the estimator is actually asking:
    what did this channel do *typically* in this window, compared with
    what it typically did at the same clock positions on the earlier
    days.  A burst is one slot, not the level.
    """
    stamps = control.stamps
    index = slot_index(stamps, trough)
    if index is None:
        return None

    lo = max(0, index - half_width_slots)
    hi = min(len(stamps) - 1, index + half_width_slots)
    if hi < lo:
        return None

    values = control.channel(channel)
    if len(values) != len(stamps):
        return None
    observed = median_of(values[lo:hi + 1])

    # The counterfactual: the same clock slots on the previous days.
    window_start = stamps[lo]
    window_end = stamps[hi]
    baseline_map = control.counterfactual(channel, window_start, window_end)
    # The counterfactual is summarised the same way as the treatment
    # arm.  Pairing two different statistics would compare a median with
    # a mean, and the ratio would not mean anything.
    expected = (median_of([baseline_map.get(control.clock_key(s), 0.0)
                           for s in stamps[lo:hi + 1]])
                if stamps else 0.0)

    if expected <= 0:
        # Without a counterfactual there is no displacement to state.
        return {"observed": observed, "expected": 0.0, "ratio": None,
                "delta": observed, "slots": [lo, hi]}

    ratio = observed / expected
    return {
        "observed": round(observed, 4),
        "expected": round(expected, 4),
        "ratio": round(ratio, 4),
        "delta": round(observed - expected, 4),
        "slots": [lo, hi],
    }


def median_of(values: Sequence[float]) -> float:
    """The median of a short sequence.

    The windows this estimator compares are a handful of slots long, so
    numpy's dispatch overhead costs more than the computation itself.
    Sorting the list and taking its middle is the same statistic.
    """
    if not values:
        return 0.0
    ordered = sorted(float(v) for v in values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def placebo_displacements(
    control: ControlPlaneSeries,
    channel: str,
    *,
    half_width_slots: int = 3,
):
    """The null distribution of the displacement, measured on ordinary days.

    The placebo is the *same measurement* applied to a day that is known
    to be ordinary: for each anchor in the baseline period, the channel's
    rate around the anchor against the same clock slots on the days
    before it.  Both the incident and the placebo are therefore paired
    differences against their own counterfactual, so the ratio between
    them is meaningful.

    The ratios are returned **signed**, because a silence and a surge do
    not share a scale.  A channel's rate cannot fall below zero, so the
    deepest silence any ordinary day reaches is a ratio of zero, while a
    re-announcement burst reaches a ratio of hundreds.
    """
    baseline = control.baseline_buckets()
    if not baseline:
        return []
    stamps = control.baseline_stamps
    if len(stamps) < 2 * half_width_slots + 2:
        return []

    values = control.baseline_channel(channel)
    if len(values) != len(stamps):
        return []

    # The clock positions of the baseline slots are fixed, so they are
    # written once rather than recomputed for every anchor.
    position_of = [control.clock_key(stamp) for stamp in stamps]

    # The counterfactual at each clock position depends on the anchor's
    # own time, because it is built from the days *before* that anchor.
    # The table is therefore built once per anchor, but each entry reads
    # only the days already behind the anchor rather than rescanning the
    # whole baseline, which is what made this loop quadratic.
    out: List[float] = []
    for index in range(half_width_slots, len(stamps) - half_width_slots):
        lo = index - half_width_slots
        hi = index + half_width_slots
        observed = median_of(values[lo:hi + 1])
        window_start = stamps[lo]
        window_end = stamps[hi]
        # The counterfactual for this placebo: the same clock slots on
        # the days *before* this anchor's day.
        baseline_map = control.counterfactual(channel, window_start, window_end)
        expected = median_of([baseline_map.get(position_of[i], 0.0)
                              for i in range(lo, hi + 1)])
        if expected <= 0:
            continue
        # A placebo whose counterfactual is incomplete is not a measurement
        # of ordinary behaviour, and it must not enter the null.  The clock
        # positions near the start of the baseline period have fewer days
        # behind them, and the positions after the last baseline day have
        # none at all.  Such a window's "expected" is systematically too
        # small, which would make the null so wide that no incident could
        # ever pass it.
        complete = True
        for i in range(lo, hi + 1):
            position = position_of[i]
            if baseline_map.get(position, 0.0) <= 0:
                complete = False
                break
            if control.days_before(channel, position, window_start) < 1:
                complete = False
                break
        if not complete:
            continue
        out.append(observed / expected)
    return out


def placebo_null(ratios: Sequence[float], quantile: float):
    """The displacement an ordinary day reaches at the given quantile.

    The null is a quantile rather than the maximum.  The maximum is the
    least stable statistic of a sample: it estimates the extreme order
    statistic from a single draw, so one ordinary day that happened to
    contain a re-announcement burst raises the null by an order of
    magnitude and no incident can ever beat it.  A quantile asks the same
    operational question while ignoring the few placebos that are
    ordinary only by luck.

    The quantile is only meaningful once there are enough placebos to
    estimate it, so a small sample falls back to its own maximum.
    """
    if not ratios:
        return 0.0
    values = sorted(ratios)
    if len(values) < 20:
        return values[-1]
    index = min(len(values) - 1,
                max(0, int(round(quantile * (len(values) - 1)))))
    return values[index]


def directional_null(ratio: float,
                     placebos: Sequence[float],
                     quantile: float):
    """The null for a displacement, taken from the same direction.

    A silence and a surge are not two sizes of the same thing.  A
    channel's rate cannot fall below zero, so the deepest silence an
    ordinary day reaches is a ratio of zero, while a surge has no
    ceiling.  One unsigned null would compare the smallest possible
    deviation against the largest possible one, and nothing that goes
    quiet could ever beat it.  So the placebos are split by direction
    and the incident is compared against the distribution of its own
    kind.

    The comparison is a **tail probability**, not a ratio against a
    quantile.  The quantity being compared is a *boundary*: a channel
    that falls silent reaches a ratio of exactly zero, and an ordinary
    day that happens to fall silent reaches a ratio very near zero but
    not exactly zero.  No quantile can express "no ordinary day
    reached this", because the incident is off the scale of the
    distribution rather than far along it.
    """
    silences = [abs(1.0 - r) for r in placebos if r < 1.0]
    surges = [abs(1.0 - r) for r in placebos if r > 1.0]

    if ratio < 1.0:
        matched = silences
        direction = "silence"
    else:
        matched = surges
        direction = "surge"

    deviation = abs(ratio - 1.0)
    if matched:
        at_least_as_extreme = sum(1 for d in matched if d >= deviation)
        # The plus one is the standard correction for a discrete
        # distribution: the incident itself is one of the draws, so
        # without it a probability of zero would be reported.
        probability = (at_least_as_extreme + 1) / (len(matched) + 1)
    else:
        probability = 1.0

    return {
        "null": placebo_null(matched, quantile),
        "direction": direction,
        "n_matched": len(matched),
        "probability": probability,
    }


def earliest_deviation(
    control: ControlPlaneSeries,
    channel: str,
    trough: datetime,
    *,
    threshold: float,
    max_lag_seconds: float,
    run_slots: int = 3,
):
    """The first moment the control plane deviated, at or before the trough.

    The search runs backwards from the trough, because the trough is
    the known sharp event and the control plane's own onset is the
    uncertain one.  A control plane that was already deviating for
    hours would make the claim weak, so the search is bounded by the
    propagation time.

    A deviation counts only when it **persists**.  The first slot that
    happens to cross the threshold is not an onset: a network whose
    rate wobbles crosses and recrosses the threshold constantly, and
    taking the first crossing would place the onset at the earliest
    wobble in the window.  Then every pair would be ordered, including
    a pair whose two sides moved *together*, and the precedence veto
    would stop discriminating between a cause and a common shock.

    So the onset is the first slot of a run of at least ``run_slots``
    consecutive deviating slots.  A simultaneous shock then has its
    onset at the shock, not before it, and the two edges cannot be
    ordered.
    """
    stamps = control.stamps
    index = slot_index(stamps, trough)
    if index is None:
        return None
    values = control.channel(channel)
    if len(values) != len(stamps):
        return None

    baseline_map = control.counterfactual(
        channel, stamps[max(0, index - 3)], stamps[index])
    if not baseline_map:
        return None
    level = float(np.mean(list(baseline_map.values())))
    if level <= 0:
        return None

    deviating = [False] * len(stamps)
    for i in range(index, -1, -1):
        stamp = stamps[i]
        if (trough - stamp).total_seconds() > max_lag_seconds:
            break
        expected = baseline_map.get(stamp.strftime("%H:%M"), level)
        if expected <= 0:
            continue
        deviation = abs(values[i] / expected - 1.0)
        deviating[i] = deviation >= threshold

    run = 0
    for i in range(index, -1, -1):
        if (trough - stamps[i]).total_seconds() > max_lag_seconds:
            break
        run = run + 1 if deviating[i] else 0
        if run >= run_slots:
            # The run ends at the slot under inspection and reaches
            # ``run_slots`` slots into the past, so its onset is
            # ``run_slots - 1`` slots earlier.
            return stamps[i - run_slots + 1] if i - run_slots + 1 >= 0 else stamps[i]
    return None


# ── The estimator ──────────────────────────────────────────────────────


def attribute(
    control: ControlPlaneSeries,
    response: Sequence[Dict[str, Any]],
    *,
    routing_mechanism: Optional[str] = None,
    routing_scope: Optional[Sequence[str]] = None,
    series_scope: Optional[Sequence[str]] = None,
    impact_window: Optional[Tuple[datetime, datetime]] = None,
    protocol: Optional[Dict[str, Any]] = None,
):
    """Return the direction that survives the vetoes, or an abstention.

    ``control`` is the routing side as a control-plane rate series and
    ``response`` is the traffic side as ``(timestamp, deviation)``
    observations on its own clock.  ``routing_mechanism`` is consulted
    only for a traffic-to-routing claim; ``routing_scope`` and
    ``series_scope`` are the affected and the observed entity sets, both
    optional -- an unknown scope suspends V3 instead of failing it.
    """
    cfg = dict(PADDLE_PROTOCOL)
    if protocol:
        cfg.update(protocol)

    verdict = CausalVerdict(
        mechanism=routing_mechanism,
        protocol={k: cfg[k] for k in sorted(cfg)},
    )

    def stop(reason: str, vetoes: Dict[str, str],
             tests: Optional[Dict[str, Any]] = None):
        verdict.reason = reason
        verdict.vetoes = vetoes
        if tests:
            verdict.tests.update(tests)
        return verdict

    blocked = {"V1": "fail", "V2": "not_run", "V3": "not_run", "V4": "not_run"}

    # ── The control plane has to exist ───────────────────────────────────
    if control.n_buckets < cfg["min_slots"]:
        return stop("series_too_short", {"V1": "fail"})

    # ── The data plane's trough: the anchor ──────────────────────────────
    points = [p for p in response if isinstance(p.get("timestamp"), datetime)]
    if len(points) < cfg["min_response_points"]:
        return stop("series_too_short", blocked)

    search_from = impact_window[0] if impact_window else None
    search_to = impact_window[1] if impact_window else None
    trough = find_trough(points, search_from=search_from, search_to=search_to)
    if trough is None:
        return stop("no_response_trough", blocked)
    trough_stamp, trough_deviation = trough
    verdict.tau_response = trough_stamp
    verdict.tests["trough"] = {
        "stamp": trough_stamp.isoformat(),
        "deviation": round(float(trough_deviation), 4),
        "window": ([search_from.isoformat() if search_from else None,
                    search_to.isoformat() if search_to else None]),
    }

    if trough_deviation >= 0:
        # The data plane did not fall.  An incident that does not reduce
        # the measured quantity is not an impact, and the estimator has
        # no causal question to answer.
        return stop("response_series_flat", {"V1": "fail"},
                    {"trough": verdict.tests["trough"]})

    # ── The control plane, measured at the trough ────────────────────────
    channel_report: Dict[str, Dict[str, Any]] = {}
    candidates: List[Tuple[float, str, Dict[str, Any]]] = []
    #: The channel that came closest to being usable, and why it did not
    #: make it.  Without this the estimator cannot say *which* test a
    #: channel failed, and "no control-plane edge" would cover both
    #: "the control plane did not move" and "it moved, but not
    #: distinguishably from an ordinary day" -- two very different
    #: findings.
    closest: Optional[Tuple[float, str, str, Dict[str, Any]]] = None

    for channel in CONTROL_PLANE_CHANNELS:
        raw = control.channel(channel)
        if len(raw) < 2:
            channel_report[channel] = {"status": "flat"}
            continue
        if float(np.ptp(raw)) < 1e-9 and not silent_against_live_baseline(control, channel):
            # A flat channel is only uninteresting when the baseline was
            # flat too.  A channel that says nothing during the event
            # while the same clock slots on ordinary days carry a rate
            # is *silent*, and silence is what an outage looks like.
            channel_report[channel] = {"status": "flat"}
            continue
        displacement = control_displacement(control, channel, trough_stamp)
        if displacement is None or displacement.get("ratio") is None:
            channel_report[channel] = {"status": "unmeasured",
                                       "detail": displacement}
            continue
        ratio = float(displacement["ratio"])
        deviation = abs(ratio - 1.0)
        placebos = placebo_displacements(control, channel)
        null_info = directional_null(ratio, placebos,
                                     cfg["placebo_null_quantile"])
        null = float(null_info["null"])
        probability = float(null_info["probability"])
        report = {
            "status": "measured",
            "ratio": round(ratio, 4),
            "deviation": round(deviation, 4),
            "null": round(null, 4),
            "null_direction": null_info["direction"],
            "p_value": round(probability, 6),
            "n_placebos": len(placebos),
            "n_matched_placebos": null_info["n_matched"],
            "observed": displacement.get("observed"),
            "expected": displacement.get("expected"),
        }
        channel_report[channel] = report

        if deviation < cfg["min_relative_displacement"]:
            failure = "below_displacement_floor"
        elif not null_info["n_matched"]:
            # Without a placebo of the same direction the channel cannot
            # be shown to be distinctive, however far it moved.
            failure = "no_placebo_null"
        elif probability > cfg["max_placebo_probability"]:
            failure = "not_exclusive"
        else:
            failure = ""

        if failure:
            report["failed"] = failure
            if closest is None or deviation > closest[0]:
                closest = (deviation, channel, failure, report)
            continue
        candidates.append((probability, channel, report))

    verdict.tests["channels"] = channel_report
    if not candidates:
        if not any(v.get("status") == "measured"
                   for v in channel_report.values()):
            return stop("control_plane_flat", {"V1": "fail"},
                        {"channels": channel_report})
        if closest is not None and closest[2] == "not_exclusive":
            # The control plane *did* move, and it moved further than the
            # absolute floor -- but an ordinary day at the same hour
            # moves at least as far.  That is a refutation of
            # distinctiveness, and it is reported as one.
            return stop("not_exclusive",
                        {"V1": "pass", "V2": "fail", "V3": "not_run",
                         "V4": "not_run"},
                        {"channels": channel_report,
                         "exclusivity": {
                             "channel": closest[1],
                             "effect": round(closest[0], 4),
                             "null": closest[3].get("null"),
                             "ratio": (round(closest[0] / closest[3]["null"], 4)
                                       if closest[3].get("null") else None),
                         }})
        return stop("no_control_plane_edge", blocked,
                    {"channels": channel_report})

    # The strongest credible channel wins, and its identity is reported:
    # the verdict says *which* control-plane property moved.
    # The most exclusive channel wins: the one whose displacement an
    # ordinary day is least likely to reproduce.
    candidates.sort(key=lambda item: item[0])
    probability, channel, report = candidates[0]
    verdict.channel = channel
    verdict.tau_control = float(report["ratio"])
    verdict.effect = float(report["deviation"])
    verdict.exclusivity_probability = probability
    verdict.baseline_displacement = float(report["null"])

    # ── V1: precedence ───────────────────────────────────────────────────
    # The control plane's earliest deviation, at or before the trough.
    earliest = earliest_deviation(
        control, channel, trough_stamp,
        threshold=cfg["min_relative_displacement"],
        max_lag_seconds=cfg["max_lag_seconds"],
    )
    if earliest is None:
        return stop("inadmissible_precedence", blocked,
                    {"channels": channel_report,
                     "precedence": {"verdict": "no_deviation_before_trough"}})

    lag_seconds = (trough_stamp - earliest).total_seconds()
    verdict.lag_seconds = lag_seconds
    verdict.tests["precedence"] = {
        "control_earliest": earliest.isoformat(),
        "trough": trough_stamp.isoformat(),
        "lag_seconds": round(lag_seconds, 2),
    }

    if lag_seconds < cfg["min_lag_seconds"]:
        # The control plane moved only after the data plane had already
        # answered, so the direction is the other way round.
        direction = T2R
        forward_lag = -lag_seconds
    else:
        direction = R2T
        forward_lag = lag_seconds

    if direction == T2R:
        if routing_mechanism is None:
            return stop("mechanism_unknown",
                        {"V1": "pass", "V2": "not_run", "V3": "not_run",
                         "V4": "not_run"},
                        {"channels": channel_report,
                         "mechanism": {"mechanism": None, "verdict": "unknown"}})
        if routing_mechanism not in REACTION_COMPATIBLE:
            return stop("reactive_incompatible",
                        {"V1": "pass", "V2": "not_run", "V3": "not_run",
                         "V4": "not_run"},
                        {"channels": channel_report,
                         "mechanism": {"mechanism": routing_mechanism,
                                       "verdict": "incompatible"}})
        verdict.tests["mechanism"] = {"mechanism": routing_mechanism,
                                      "verdict": "reaction_compatible"}

    if forward_lag > cfg["max_lag_seconds"]:
        return stop("lag_out_of_range",
                    {"V1": "pass", "V2": "not_run", "V3": "not_run",
                     "V4": "not_run"},
                    {"channels": channel_report,
                     "precedence": verdict.tests["precedence"]})

    # ── V2: exclusivity against the same-clock placebo null ─────────────
    if verdict.effect is None or verdict.effect < cfg["min_absolute_displacement"]:
        return stop("not_exclusive",
                    {"V1": "pass", "V2": "fail", "V3": "not_run", "V4": "not_run"},
                    {"channels": channel_report,
                     "exclusivity": {"effect": verdict.effect,
                                     "null": verdict.baseline_displacement,
                                     "ratio": ratio}})
    verdict.tests["exclusivity"] = {
        "effect": round(float(verdict.effect), 4),
        "null": round(float(verdict.baseline_displacement or 0.0), 4),
        "ratio": round(float(ratio), 4),
    }

    # ── V3: scope ────────────────────────────────────────────────────────
    provenance = "suspend"
    if routing_scope is not None and series_scope is not None:
        shared = {str(s) for s in routing_scope} & {str(s) for s in series_scope}
        provenance = "pass" if len(shared) >= cfg["min_scope_overlap"] else "fail"
        verdict.tests["provenance"] = {
            "routing_scope": len(list(routing_scope)),
            "series_scope": len(list(series_scope)),
            "shared": len(shared),
            "verdict": provenance,
        }
        if provenance == "fail":
            return stop("provenance_disjoint",
                        {"V1": "pass", "V2": "pass", "V3": "fail", "V4": "not_run"},
                        {"channels": channel_report,
                         "provenance": verdict.tests["provenance"]})
    else:
        verdict.tests["provenance"] = {"verdict": "suspend"}

    # ── V4: congruence ───────────────────────────────────────────────────
    # The two movements have to point the same way.  A routing *surge*
    # alongside a traffic *collapse* is not the same phenomenon, and
    # reading the surge as the cause of the collapse would be reading
    # the consequence backwards.
    control_ratio = float(report["ratio"])
    control_direction = 1.0 if control_ratio >= 1.0 else -1.0
    response_direction = 1.0 if trough_deviation >= 0 else -1.0
    congruent = (control_direction == response_direction)
    verdict.tests["congruence"] = {
        "control_ratio": round(control_ratio, 4),
        "response_deviation": round(float(trough_deviation), 4),
        "verdict": "congruent" if congruent else "contradicted",
    }
    if cfg["require_congruent_sign"] and not congruent:
        return stop("mirror_contradicted",
                    {"V1": "pass", "V2": "pass", "V3": provenance,
                     "V4": "fail"},
                    {"channels": channel_report,
                     "congruence": verdict.tests["congruence"]})

    verdict.vetoes = {"V1": "pass", "V2": "pass", "V3": provenance,
                      "V4": "pass"}
    verdict.direction = direction
    verdict.reason = "committed"
    return verdict


__all__ = [
    "PADDLE_PROTOCOL",
    "CausalVerdict",
    "CONTROL_PLANE_CHANNELS",
    "REACTION_COMPATIBLE",
    "REASONS",
    "ROUTING_MECHANISMS",
    "R2T",
    "T2R",
    "UNKNOWN",
    "attribute",
    "control_displacement",
    "find_trough",
    "placebo_displacements",
    "protocol_hash",
    "silent_against_live_baseline",
    "traffic_deviation",
]
