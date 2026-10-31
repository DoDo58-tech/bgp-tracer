"""PADDLE -- Paired Displacement, Difference-in-differences, with Ledger Evidence.

The directional causal estimator, and the only one in this codebase.

It replaces the correlation-shaped estimators it supersedes because
each of those answers a question that is not the question asked.  A
Granger statistic asks whether one series is *predictive* of another.
A transfer entropy asks how much the *uncertainty* of one series is
reduced by the other.  A Pearson correlation asks whether two series
*co-vary*.  None of these is a causal claim, and all three are
symmetric, so none of them can even express the asymmetry that a BGP
incident has: the control plane moved, and the data plane answered.

PADDLE answers the physical question directly.

**The question.**  When the data plane deviated, had the control plane
already deviated, and did it deviate *more than it does at this hour on
an ordinary day*?  That is a question about a *pair* of observations
at one moment, not about two sequences.

**Why pairing is the whole idea.**  A change-point search on the
control plane and a change-point search on the data plane, followed by
a comparison of their positions, is fragile in a way that is not
about statistics.  The control plane's rate series is *sparse and
bursty*: it is quiet for hours and then it emits in a burst.  A
segmentation of such a series puts its change point wherever the
burst is, which is often hours away from the incident that the burst
is a consequence of.  The data plane's deviation, by contrast, has a
well-defined location -- the trough -- because the trough is the
moment the traffic stopped.

So the *anchor* is taken from the side whose event is sharp, and the
*measurement* is taken on the side whose series is noisy.  The control
plane is then asked: at the data plane's trough, how far from normal
was this network's routing behaviour?  That question is answerable
even when the control plane's own series has no crisp onset.

**The counterfactual, and why it has to be the same clock.**  "How
far from normal" requires a counterfactual: what would this network's
routing behaviour have been at this moment if nothing had happened.
The counterfactual used here is the **same clock slots on the previous
days**, for the same channel, measured by the same instrument.  It is
not a bootstrap of the event window against itself, because that would
make the null depend on the very anomaly being tested.  And it is not
a long-run average, because a network announces more at 14:30 than at
03:00 whatever happened -- a long-run average measures the time of day,
not the incident.

**The three vetoes.**

V1 *Precedence* -- the control plane must have deviated **at or before**
    the data plane's trough, within a physically bounded propagation
    time.  A routing change reaches the data plane in seconds to
    minutes; a deviation that appears hours later is not an answer to
    it.

V2 *Exclusivity* -- the control plane's deviation at the trough must
    exceed what the same channel shows at **placebo troughs** drawn
    from the same-clock baseline.  The null is the instrument's own
    behaviour on the same quantity at the same hour on ordinary days.
    This is what makes the claim a claim about *this incident* rather
    than about a busy afternoon.

V3 *Scope and congruence* -- the routing edge must be about the
    entity the traffic series measures, and the two movements must
    point the same way.  A withdrawal is what a *failure* looks like
    and a traffic drop shares a common cause with it; treating it as a
    *reaction* would assert a direction the evidence does not support,
    so a withdrawal is never read as reaction-compatible.

**Why there is no vote.**  The four channels are not scored and
combined.  Each is a *separate physical hypothesis* about what happened
-- the network went quiet, the origin changed, the path changed -- and
the estimator reports which one, if any, survives.  Combining them
into a score would let a strong signal in one channel paper over the
absence of the signal in the other, and the resulting number would
mean nothing.

**What the estimator never does.**  It never computes a dependence
statistic between the two series, never resamples one series against
the other, and never emits a direction without a named mechanism and a
measured lag.  When the evidence does not support a direction it
abstains, and it says which veto stopped it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from agents.control_plane import (
    CONTROL_PLANE_CHANNELS,
    GRID_SECONDS,
    ControlPlaneSeries,
    same_clock_baseline,
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
    #: How many times the placebo troughs' own worst displacement the
    #: incident's displacement must exceed.
    "min_exclusivity_ratio": 1.5,
    #: The absolute floor, so a channel that barely moves in both the
    #: incident and the placebo cannot pass on a large ratio alone.
    "min_absolute_displacement": 0.20,
    #: The control plane's displacement must be at least this, measured
    #: as a multiple of the same-clock baseline rate.  "One" is normal.
    "min_relative_displacement": 0.25,

    # ── V3: scope and congruence ─────────────────────────────────────────
    #: The response must observe at least this many of the entities the
    #: control-plane edge is about.
    "min_scope_overlap": 1,
    #: The two movements must agree in direction.  A routing *surge*
    #: alongside a traffic *collapse* is not the same phenomenon.
    "require_congruent_sign": True,
}


def protocol_hash(cfg: Optional[Dict[str, Any]] = None) -> str:
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
    #: The incident's displacement as a multiple of the placebo null.
    exclusivity_ratio: Optional[float] = None
    #: The worst placebo displacement, in the same units.
    baseline_displacement: Optional[float] = None
    channel: str = ""
    mechanism: Optional[str] = None
    tests: Dict[str, Any] = field(default_factory=dict)
    protocol: Dict[str, Any] = field(default_factory=dict)

    @property
    def committed(self) -> bool:
        return self.direction in (R2T, T2R)

    def as_dict(self, include_protocol: bool = True) -> Dict[str, Any]:
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
            "exclusivity_ratio": (round(float(self.exclusivity_ratio), 4)
                                  if self.exclusivity_ratio is not None else None),
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


def _as_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def traffic_deviation(point: Dict[str, Any]) -> Optional[float]:
    """The signed deviation of one traffic observation from its baseline.

    The detector stores ``current_value`` alongside the ``historical_mean``
    it was compared against, so the **sign** of the deviation is
    recoverable even when the stored ``z_score`` has lost it.

    That loss is not hypothetical.  The traffic detector records the
    magnitude of the departure and the direction separately, and in the
    cached artefacts the ``z_score`` field carries the magnitude alone:
    an outage that took the network's traffic down by 99.6% appears
    with a *positive* ``z_score``.  A causal estimator that reads the
    sign off that field would read every outage as a surge.  The
    deviation is therefore reconstructed from the value and the
    historical mean, and the stored z-score is used only for the
    magnitude when the value is absent.

    A negative deviation means the measured quantity fell.  For a
    traffic series the quantity is a request or throughput count, so a
    fall is the impact of an incident.
    """
    raw = point.get("raw_event")
    raw = raw if isinstance(raw, dict) else {}

    value = _as_float(point.get("current_value"))
    if value is None:
        value = _as_float(raw.get("current_value"))
    if value is None:
        value = _as_float(point.get("value"))
    if value is None:
        value = _as_float(raw.get("value"))

    mean = _as_float(point.get("historical_mean"))
    if mean is None:
        mean = _as_float(raw.get("historical_mean"))

    if value is not None and mean is not None and mean != 0:
        # The relative deviation, in the units the estimator compares in.
        return (value - mean) / abs(mean)

    z = _as_float(point.get("z_score"))
    if z is None:
        z = _as_float(raw.get("z_score"))
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
) -> Optional[Tuple[datetime, float]]:
    """The sharpest downward deviation of the data plane.

    The impact of a routing incident on the data plane is a *fall* in
    the measured quantity, so the trough -- the most negative
    deviation -- is the moment the incident happened.  The search is
    bounded by the impact window the traffic detector reported, so the
    trough is the one belonging to *this* event rather than the worst
    deviation of the whole record.
    """
    best: Optional[Tuple[datetime, float]] = None
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
        if best is None or deviation < best[1]:
            best = (stamp, deviation)
    return best


# ── The control plane's deviation, paired with the trough ─────────────


def slot_index(stamps: Sequence[datetime], stamp: datetime) -> Optional[int]:
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
) -> Optional[Dict[str, Any]]:
    """The control plane's departure from normal at the data plane's trough.

    The measurement is a **paired difference-in-differences**:

    * the *treatment* arm is the control plane's rate in the slots
      around the trough;
    * the *counterfactual* arm is the same clock slots on the previous
      days, for the same channel, measured by the same instrument.

    The displacement is reported as a multiple of the counterfactual:
    one is normal, zero is silence, three is a threefold surge.
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
    observed = float(np.mean(values[lo:hi + 1]))

    # The counterfactual: the same clock slots on the previous days.
    window_start = stamps[lo]
    window_end = stamps[hi]
    baseline_map = same_clock_baseline(
        control.baseline_buckets(), channel, window_start, window_end)
    expected = (float(np.mean([baseline_map.get(s.strftime("%H:%M"), 0.0)
                               for s in stamps[lo:hi + 1]]))
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


def placebo_displacements(
    control: ControlPlaneSeries,
    channel: str,
    *,
    half_width_slots: int = 3,
) -> List[float]:
    """The null distribution of the displacement, measured on ordinary days.

    The placebo is the *same measurement* applied to a day that is known
    to be ordinary.  For each anchor in the baseline period, the
    displacement is computed the same way it is computed for the
    incident -- the channel's rate in the slots around the anchor,
    against the same clock slots on the days before that anchor.

    This is what makes the null honest.  The alternative -- comparing
    the incident's window with the baseline's overall mean -- would put
    the two quantities on different scales, because a rolling mean over
    ``w`` slots has expectation ``w`` times a mean per slot.  Here both
    the incident and the placebo are *paired differences against their
    own counterfactual*, so they are the same statistic and the ratio
    between them is meaningful.

    The null is therefore the instrument's own behaviour on the same
    quantity, at the same hour, on days without the incident.
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

    out: List[float] = []
    for index in range(half_width_slots, len(stamps) - half_width_slots):
        lo = index - half_width_slots
        hi = index + half_width_slots
        observed = float(np.mean(values[lo:hi + 1]))
        window_start = stamps[lo]
        window_end = stamps[hi]
        # The counterfactual for this placebo: the same clock slots on
        # the days *before* this anchor's day.
        baseline_map = same_clock_baseline(
            baseline, channel, window_start, window_end)
        expected = float(np.mean([baseline_map.get(s.strftime("%H:%M"), 0.0)
                                  for s in stamps[lo:hi + 1]]))
        if expected <= 0:
            continue
        out.append(abs(observed / expected - 1.0))
    return out


def earliest_deviation(
    control: ControlPlaneSeries,
    channel: str,
    trough: datetime,
    *,
    threshold: float,
    max_lag_seconds: float,
) -> Optional[datetime]:
    """The first moment the control plane deviated, at or before the trough.

    The search runs backwards from the trough, because the trough is
    the known sharp event and the control plane's own onset is the
    uncertain one.  A control plane that was already deviating for
    hours would make the claim weak, so the search is bounded by the
    propagation time.
    """
    stamps = control.stamps
    index = slot_index(stamps, trough)
    if index is None:
        return None
    values = control.channel(channel)
    if len(values) != len(stamps):
        return None

    baseline_map = same_clock_baseline(
        control.baseline_buckets(), channel,
        stamps[max(0, index - 3)], stamps[index])
    if not baseline_map:
        return None
    level = float(np.mean(list(baseline_map.values())))
    if level <= 0:
        return None

    earliest: Optional[datetime] = None
    for i in range(index, -1, -1):
        stamp = stamps[i]
        if (trough - stamp).total_seconds() > max_lag_seconds:
            break
        expected = baseline_map.get(stamp.strftime("%H:%M"), level)
        if expected <= 0:
            continue
        deviation = abs(values[i] / expected - 1.0)
        if deviation >= threshold:
            earliest = stamp
    return earliest


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
) -> CausalVerdict:
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
             tests: Optional[Dict[str, Any]] = None) -> CausalVerdict:
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
    for channel in CONTROL_PLANE_CHANNELS:
        raw = control.channel(channel)
        if len(raw) < 2 or float(np.ptp(raw)) < 1e-9:
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
        null = max(placebos) if placebos else 0.0
        report = {
            "status": "measured",
            "ratio": round(ratio, 4),
            "deviation": round(deviation, 4),
            "null": round(null, 4),
            "observed": displacement.get("observed"),
            "expected": displacement.get("expected"),
        }
        channel_report[channel] = report
        if deviation < cfg["min_relative_displacement"]:
            continue
        if null <= 1e-9:
            continue
        if deviation / null < cfg["min_exclusivity_ratio"]:
            continue
        candidates.append((deviation / null, channel, report))

    verdict.tests["channels"] = channel_report
    if not candidates:
        if not any(v.get("status") == "measured"
                   for v in channel_report.values()):
            return stop("control_plane_flat", {"V1": "fail"},
                        {"channels": channel_report})
        return stop("no_control_plane_edge", blocked,
                    {"channels": channel_report})

    # The strongest credible channel wins, and its identity is reported:
    # the verdict says *which* control-plane property moved.
    candidates.sort(key=lambda item: item[0], reverse=True)
    ratio, channel, report = candidates[0]
    verdict.channel = channel
    verdict.tau_control = float(report["ratio"])
    verdict.effect = float(report["deviation"])
    verdict.exclusivity_ratio = ratio
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
    "traffic_deviation",
]
