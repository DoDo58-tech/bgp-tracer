"""CDPR -- Control-plane Displacement, Paired Response.

The directional causal estimator.  It answers one question of a candidate
direction: *can the earlier edge be the administered cause of the later
one?*  It answers with vetoes and never with a score.

The method rests on four ideas, and each one is a departure from what
the estimators it replaces do.

1. **The routing side is an observation rate, not an amplitude.**
   A BGP incident is not a large value on a continuous signal; it is a
   change in how densely the collector observes the control plane.  The
   routing side is therefore carried as three separate rates --
   ``volume``, ``origin_change``, ``path_change`` -- read from the
   detector's own per-bucket feature series (see
   :mod:`agents.control_plane`).  They are kept apart on purpose: an
   origin change is what a hijack does, a path change is what a leak
   does, and a volume collapse is what an outage does.  A verdict can
   therefore name *which* control-plane property moved.

2. **The rate is normalised by the baseline.**
   "Forty messages per bucket" is quiet for an AS that normally emits
   forty thousand and loud for one that normally emits four.  Each
   bucket is therefore divided by the baseline's median count for the
   same channel, so the series reads "one times normal", "zero" or
   "twelve" and the estimator's thresholds are a property of the method
   rather than of the network the method was pointed at.

3. **The null comes from the period before the incident.**
   The detector already measures the same features over the window
   *before* the event.  That baseline is the null: the displacement the
   control plane shows at its own best anchor in the event window is
   compared against the displacement the same channel shows at its best
   anchor in the baseline window.  No bootstrap of the event window
   against itself is needed, and the comparison is between two
   measurements of the same quantity by the same instrument.

4. **The two sides keep their own clocks.**
   The control plane is sampled every few minutes; the data plane is
   sampled on the traffic provider's interval, which is coarser and
   offset.  Forcing them onto one grid throws away real observations and
   manufactures a lag that is an artefact of the resampling.  So each
   side locates its own change point **in wall-clock time**, and the
   comparison between them is made on that common axis.  The lag the
   verdict reports is a physical quantity -- how many seconds passed
   between the control plane moving and the data plane responding -- and
   not an artefact of a bucket index.

Direction is asymmetric by construction: only the control plane has an
observation rate and a baseline, and a traffic-to-routing claim requires
a named reaction-compatible mechanism.  A symmetric dependence statistic
cannot express either requirement, and none is computed in this module.

The verdict is committed only when every veto passes.  Otherwise the
first failing veto is recorded as a machine-readable reason, so a
refusal is auditable rather than a silent decline.
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
    ControlPlaneSeries,
)

R2T = "routing_to_traffic"
T2R = "traffic_to_routing"
UNKNOWN = "unknown"

#: Mechanisms a routing edge can carry.  ``origin_change`` denotes an
#: announcement of the prefix by a *different* origin, which is a fault
#: or a hijack; it is never a reaction to traffic.
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
    "no_control_plane_edge",
    "no_response_edge",
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
CDPR_PROTOCOL: Dict[str, Any] = {
    # ── Representation ────────────────────────────────────────────────────
    "min_buckets": 6,              # below this the window cannot support a split
    "min_segment_frac": 0.15,      # each side of a split holds >= 15% of the window

    # ── V1: the control plane must have moved ─────────────────────────────
    # The normalised rate must leave the band around one that the control
    # plane normally occupies.
    "min_rate_deviation": 0.40,
    # The Welch-t the jump must reach against the channel's own noise.
    "min_jump_t": 2.0,

    # ── V2: the movement must exceed the baseline ─────────────────────────
    # How many times the baseline's own best displacement the event
    # window's displacement must exceed.
    "min_exclusivity_ratio": 1.5,
    # The absolute floor, so a channel that barely moves in both windows
    # cannot pass on a large ratio alone.
    "min_absolute_displacement": 1e-9,

    # ── V3: scope ─────────────────────────────────────────────────────────
    # The response must observe at least this many of the entities the
    # control-plane edge is about.
    "min_scope_overlap": 1,

    # ── V4: mirror congruence ─────────────────────────────────────────────
    # The response must revert within this fraction of the window after
    # the control plane reverts.
    "recovery_tol_frac": 0.25,

    # ── The lag the data plane may take to answer ─────────────────────────
    # A routing change reaches the data plane in seconds to minutes; a
    # response that arrives hours later is not an answer to it.  The
    # bounds are in seconds and are expressed as a property of the
    # phenomenon, not of the window length.
    "min_response_lag_seconds": 0.0,
    "max_response_lag_seconds": 5400.0,
}


def protocol_hash(cfg: Optional[Dict[str, Any]] = None) -> str:
    """Short stable identifier of a protocol, printed into every artefact."""
    data = cfg if cfg is not None else CDPR_PROTOCOL
    payload = json.dumps({k: data[k] for k in sorted(data)}, sort_keys=True,
                         default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


@dataclass
class CausalVerdict:
    """Outcome of one attribution, with every veto that was evaluated."""

    direction: str = UNKNOWN
    reason: str = ""
    vetoes: Dict[str, str] = field(default_factory=dict)
    tau_control: Optional[int] = None
    tau_response: Optional[int] = None
    #: The physical lag between the two edges, in seconds.
    lag_seconds: Optional[float] = None
    effect: Optional[float] = None
    exclusivity_ratio: Optional[float] = None
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
            "tau_control": self.tau_control,
            "tau_response": self.tau_response,
            "lag_seconds": (round(self.lag_seconds, 2)
                            if self.lag_seconds is not None else None),
            "effect": (round(self.effect, 4)
                       if self.effect is not None else None),
            "exclusivity_ratio": (round(self.exclusivity_ratio, 4)
                                  if self.exclusivity_ratio is not None else None),
            "baseline_displacement": (
                round(self.baseline_displacement, 4)
                if self.baseline_displacement is not None else None),
            "channel": self.channel,
            "mechanism": self.mechanism,
            "tests": self.tests,
        }
        if include_protocol:
            out["protocol"] = self.protocol
            out["protocol_hash"] = protocol_hash(self.protocol)
        return out


# ── Segmentation helpers ───────────────────────────────────────────────


def segment(x: Sequence[float], min_seg: int) -> Dict[str, Any]:
    """The best single change in ``x``, with its jump and t-statistic.

    The change is chosen by the product of the *relative* jump and the
    Welch t-statistic: a relative jump alone would prefer a change
    between two tiny values, and a t-statistic alone would prefer a
    change between two large but noisy ones.
    """
    arr = np.asarray(x, dtype=float)
    n = len(arr)
    if n < 2 * min_seg + 1:
        return {"change": None, "jump": 0.0, "t": 0.0, "rel": 0.0,
                "means": [float(arr.mean())] if n else [0.0]}

    best = None
    for anchor in range(min_seg, n - min_seg + 1):
        pre = arr[:anchor]
        post = arr[anchor:]
        m1, m2 = float(pre.mean()), float(post.mean())
        v1 = float(pre.var(ddof=1)) if len(pre) > 1 else 0.0
        v2 = float(post.var(ddof=1)) if len(post) > 1 else 0.0
        denom = np.sqrt(v1 / len(pre) + v2 / len(post))
        t = 0.0 if denom <= 1e-12 else abs(m2 - m1) / denom
        # A relative jump: how large the change is against the level it
        # starts from.  A channel that goes from 5 to 0 has a relative
        # jump of 1; a channel that goes from 5000 to 4000 has 0.2.
        scale = max(abs(m1), abs(m2), 1e-9)
        rel = abs(m2 - m1) / scale
        score = (rel, t)
        if best is None or score > best[0]:
            best = (score, anchor, m1, m2, t, rel)
    if best is None:
        return {"change": None, "jump": 0.0, "t": 0.0, "rel": 0.0,
                "means": [float(arr.mean())]}
    _, anchor, m1, m2, t, rel = best
    return {"change": anchor, "jump": m2 - m1, "t": t, "rel": rel,
            "means": [m1, m2]}


def best_displacement(values: Sequence[float], min_seg: int) -> Tuple[float, int]:
    """The largest |post - pre| displacement and the anchor where it sits."""
    arr = np.asarray(values, dtype=float)
    n = len(arr)
    if n < 2 * min_seg + 1:
        return 0.0, -1
    best, at = 0.0, -1
    for anchor in range(min_seg, n - min_seg + 1):
        pre = arr[max(0, anchor - min_seg):anchor]
        post = arr[anchor:anchor + min_seg]
        if len(pre) == 0 or len(post) == 0:
            continue
        d = abs(float(post.mean()) - float(pre.mean()))
        if d > best:
            best, at = d, anchor
    return best, at


def revert_index(values: Sequence[float], anchor: int, level: float,
                 min_seg: int) -> Optional[int]:
    """The index where ``values`` returns to ``level`` after ``anchor``.

    Used by the mirror check: if the control plane goes back to where it
    was, the response has to go back too.
    """
    arr = np.asarray(values, dtype=float)
    n = len(arr)
    tol = max(1e-9, 0.10 * abs(level))
    for i in range(anchor + min_seg, n):
        if abs(float(arr[i]) - level) <= tol:
            return i
    return None


def response_onset(stamps: Sequence[datetime], magnitudes: Sequence[float],
                    min_seg: int) -> Optional[int]:
    """The index at which the response *starts* to deviate.

    The response to a routing failure is not a step: it is a deviation
    that starts at some moment and then persists.  A segmentation that
    looks for the best step therefore finds the *middle* of the affected
    interval rather than its beginning, and a verdict built on it would
    place the response before the cause.

    The onset is therefore found directly: the first index at which the
    response leaves the band it occupied before it.  The band is the
    median of the observations before the first deviation, widened by a
    factor that makes the test insensitive to a single noisy point.
    """
    values = np.asarray(magnitudes, dtype=float)
    n = len(values)
    if n < max(3, min_seg + 1):
        return None
    if float(np.ptp(values)) < 1e-9:
        return None

    # A robust reference: the lower half of the observations, which for a
    # response that is quiet before the incident is the quiet level.
    quiet = float(np.median(values[:max(1, n // 2)]))
    spread = float(np.median(np.abs(values[:max(1, n // 2)] - quiet)))
    # The band the response occupies before it deviates.  The factor
    # absorbs a single outlier without accepting a sustained change.
    band = max(spread * 3.0, abs(quiet) * 0.10, 1e-9)

    for i in range(1, n):
        if abs(float(values[i]) - quiet) > band:
            # Require the deviation to persist for a few observations,
            # so a single spike does not count as the onset.
            tail = values[i:i + min_seg]
            if len(tail) == 0:
                continue
            if float(np.mean(np.abs(tail - quiet))) > band:
                return i
    return None


# ── The estimator ──────────────────────────────────────────────────────


def attribute(
    control: ControlPlaneSeries,
    response: Sequence[Dict[str, Any]],
    *,
    routing_mechanism: Optional[str] = None,
    routing_scope: Optional[Sequence[str]] = None,
    series_scope: Optional[Sequence[str]] = None,
    protocol: Optional[Dict[str, Any]] = None,
) -> CausalVerdict:
    """Return the direction that survives the vetoes, or an abstention.

    ``control`` is the routing side as a control-plane rate series and
    ``response`` is the traffic side as ``(timestamp, magnitude)``
    observations on its own clock.  ``routing_mechanism`` is consulted
    only for a traffic-to-routing claim; ``routing_scope`` and
    ``series_scope`` are the affected and the observed entity sets, both
    optional -- an unknown scope suspends V3 instead of failing it.
    """
    cfg = dict(CDPR_PROTOCOL)
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

    # ── The control plane: which channel carries the incident? ───────────
    # The channels are evaluated separately and the strongest *credible*
    # one is selected: credible means it leaves the band around the
    # normal rate and the jump clears the t-statistic floor.  A channel
    # that does not move is not evidence, however large the raw numbers
    # are.
    n_control = control.n_buckets
    if n_control < cfg["min_buckets"]:
        return stop("series_too_short", {"V1": "fail"})

    min_seg = max(2, int(round(cfg["min_segment_frac"] * n_control)))
    channel_report: Dict[str, Dict[str, Any]] = {}
    best_channel: Optional[Tuple[float, str, Dict[str, Any]]] = None
    for channel in CONTROL_PLANE_CHANNELS:
        raw = control.channel(channel)
        if len(raw) < 2:
            channel_report[channel] = {"status": "absent"}
            continue
        if float(np.ptp(raw)) < 1e-9:
            channel_report[channel] = {"status": "flat"}
            continue
        # The channel as a multiple of its own baseline level.  A
        # normalised series reads "one" for normal, so the deviation is
        # measured from one rather than from zero.
        values = control.normalised(channel)
        seg = segment(values, min_seg)
        anchor = int(seg["change"]) if seg.get("change") is not None else 0
        pre_level = float(np.mean(values[max(0, anchor - min_seg):anchor]))
        post_level = float(np.mean(values[anchor:anchor + min_seg]))
        deviation = abs(post_level - pre_level)
        report: Dict[str, Any] = {
            "status": "measured",
            "anchor": seg.get("change"),
            "deviation": round(deviation, 4),
            "relative_jump": round(float(seg.get("rel", 0.0)), 4),
            "t": round(float(seg.get("t", 0.0)), 4),
            "jump": round(float(seg.get("jump", 0.0)), 4),
            "baseline_level": round(control.baseline_level.get(channel, 0.0), 4),
        }
        credible = (
            seg.get("change") is not None
            and deviation >= cfg["min_rate_deviation"]
            and float(seg.get("t", 0.0)) >= cfg["min_jump_t"]
        )
        report["credible"] = credible
        channel_report[channel] = report
        if credible:
            score = deviation * float(seg.get("t", 0.0))
            if best_channel is None or score > best_channel[0]:
                best_channel = (score, channel, seg)

    verdict.tests["channels"] = channel_report

    if not any(v.get("status") == "measured" for v in channel_report.values()):
        return stop("control_plane_flat", {"V1": "fail"})
    if best_channel is None:
        return stop("no_control_plane_edge", blocked,
                    {"channels": channel_report})

    _, channel, seg = best_channel
    verdict.channel = channel
    tau_control = int(seg["change"])
    verdict.tau_control = tau_control
    control_stamp = control.stamps[tau_control] if tau_control < len(control.stamps) else None

    # ── The data plane: its own onset, on its own clock ──────────────────
    # The response is a sequence of ``(timestamp, magnitude)`` points.
    # Its onset is located on the response's own clock and the two
    # onsets are then compared in wall-clock time.
    resp_points = [p for p in response if p.get("timestamp") is not None]
    if len(resp_points) < cfg["min_buckets"]:
        return stop("series_too_short", blocked,
                    {"channels": channel_report})
    resp_stamps = [p["timestamp"] for p in resp_points]
    resp_values = [float(p.get("magnitude", 0.0) or 0.0) for p in resp_points]
    if float(np.ptp(resp_values)) < 1e-9:
        return stop("response_series_flat", {"V1": "fail"})

    resp_min_seg = max(2, int(round(cfg["min_segment_frac"] * len(resp_values))))
    tau_response = response_onset(resp_stamps, resp_values, resp_min_seg)
    if tau_response is None:
        return stop("no_response_edge", blocked,
                    {"channels": channel_report})
    verdict.tau_response = int(tau_response)
    response_stamp = resp_stamps[tau_response]

    # ── V1: precedence, measured in wall-clock time ──────────────────────
    if control_stamp is None:
        return stop("inadmissible_precedence", blocked,
                    {"channels": channel_report})
    signed_lag = (response_stamp - control_stamp).total_seconds()
    verdict.lag_seconds = signed_lag
    verdict.tests["precedence"] = {
        "control_stamp": control_stamp.isoformat(),
        "response_stamp": response_stamp.isoformat(),
        "lag_seconds": round(signed_lag, 2),
    }

    if signed_lag >= 0:
        direction = R2T
        lag_seconds = signed_lag
    else:
        direction = T2R
        lag_seconds = -signed_lag

    # A reaction claim needs a named reaction.  Absence of an annotation
    # is not evidence that one occurred.
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

    # A response that arrives outside the window in which a routing
    # change can reach the data plane is not an answer to it.
    if lag_seconds < cfg["min_response_lag_seconds"] or \
            lag_seconds > cfg["max_response_lag_seconds"]:
        return stop("lag_out_of_range",
                    {"V1": "pass", "V2": "not_run", "V3": "not_run",
                     "V4": "not_run"},
                    {"channels": channel_report,
                     "precedence": verdict.tests["precedence"]})

    # ── V2: the movement must exceed the baseline ─────────────────────────
    # The same channel, measured over the window before the incident.
    # The event window's displacement is compared against the baseline's
    # own best displacement: the null is the instrument's normal
    # variation, not a resampling of the event window.
    control_values = control.normalised(channel)
    horizon = max(min_seg, n_control - tau_control)
    pre_level = float(np.mean(control_values[max(0, tau_control - min_seg):tau_control]))
    post_level = float(np.mean(control_values[tau_control:tau_control + horizon]))
    effect = abs(post_level - pre_level)
    verdict.effect = effect

    if control.has_baseline:
        base_disp, base_at = best_displacement(
            control.normalised_baseline(channel), min_seg)
    else:
        base_disp, base_at = 0.0, -1
    verdict.baseline_displacement = base_disp

    if base_disp > 0:
        ratio = effect / base_disp
    else:
        # No baseline variation to speak of: the event displacement has
        # to clear an absolute floor instead.
        ratio = float("inf") if effect > cfg["min_absolute_displacement"] else 0.0
    verdict.exclusivity_ratio = ratio if np.isfinite(ratio) else None
    verdict.tests["exclusivity"] = {
        "effect": round(float(effect), 4),
        "baseline_displacement": round(float(base_disp), 4),
        "ratio": (round(float(ratio), 4) if np.isfinite(ratio) else None),
        "baseline_anchor": base_at,
        "horizon": horizon,
        "has_baseline": control.has_baseline,
    }

    if effect < cfg["min_absolute_displacement"] or ratio < cfg["min_exclusivity_ratio"]:
        return stop("not_exclusive",
                    {"V1": "pass", "V2": "fail", "V3": "not_run", "V4": "not_run"},
                    {"channels": channel_report,
                     "exclusivity": verdict.tests["exclusivity"]})

    # ── V3: scope ─────────────────────────────────────────────────────────
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

    # ── V4: mirror congruence ─────────────────────────────────────────────
    # If the control plane returns to its previous level, the response
    # has to return as well.
    tol_buckets = max(2, int(round(cfg["recovery_tol_frac"] * n_control)))
    rec_control = revert_index(control_values, tau_control, pre_level, min_seg)
    rec_resp = revert_index(resp_values, tau_response,
                             float(np.mean(resp_values[:max(1, tau_response)])),
                             resp_min_seg)
    mirror = {
        "control_recovery": rec_control,
        "response_recovery": rec_resp,
        "tolerance": tol_buckets,
    }
    if rec_control is not None and rec_resp is not None:
        if abs(rec_control - rec_resp) > tol_buckets:
            mirror["verdict"] = "contradicted"
            verdict.tests["mirror"] = mirror
            return stop("mirror_contradicted",
                        {"V1": "pass", "V2": "pass", "V3": provenance,
                         "V4": "fail"},
                        {"channels": channel_report, "mirror": mirror})
        mirror["verdict"] = "congruent"
    elif rec_control is None and rec_resp is None:
        mirror["verdict"] = "unobservable"
    else:
        mirror["verdict"] = "one_sided"
    verdict.tests["mirror"] = mirror

    verdict.vetoes = {"V1": "pass", "V2": "pass", "V3": provenance, "V4": "pass"}
    verdict.direction = direction
    verdict.reason = "committed"
    return verdict


__all__ = [
    "CDPR_PROTOCOL",
    "CausalVerdict",
    "CONTROL_PLANE_CHANNELS",
    "REACTION_COMPATIBLE",
    "REASONS",
    "ROUTING_MECHANISMS",
    "R2T",
    "T2R",
    "UNKNOWN",
    "attribute",
    "best_displacement",
    "protocol_hash",
    "response_onset",
    "segment",
]
