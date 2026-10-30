"""AEA -- Administered-Edge Attribution.

A single-rule directional attribution for routing/traffic pairs.

The estimator asks one question of a candidate direction: *can the earlier edge
be the administered cause of the later one?*  It answers with four vetoes and
never with a score:

  V1  admissibility    the cause edge precedes the response edge and is a
                       persistent state change rather than a transient;
  V2  exclusivity      the displacement measured at the cause anchor exceeds
                       the displacement the response shows at placebo anchors
                       drawn from its own pre-period (a design-based null);
  V3  provenance       the response series observes the entity the cause edge
                       is about (scope intersection).  An unknown scope is
                       *suspended*, recorded as such, and never refutes;
  V4  mirror congruence if the cause edge reverts inside the window, the
                       response must revert after it.

Nothing is summed and no posterior is formed.  A direction is committed only
if all four vetoes pass; otherwise the first failing veto is recorded as a
machine-readable reason.

The asymmetry of the procedure -- the property a symmetric dependence
estimator cannot express -- enters through exactly two gates: V1 (only one of
the two orders can satisfy precedence) and V3 (only a control-plane edge has an
affected set).  No symmetric dependence statistic is computed anywhere in this
module.

Domain knowledge about *reaction* is isolated in one place: a traffic-to-routing
claim requires the routing change to carry a named reaction-compatible
mechanism.  Without one the estimator abstains (``mechanism_unknown``) rather
than treating the absence of an annotation as evidence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Sequence

import numpy as np

from agents._segmentation import (
    clean,
    detect_changes,
    its_effect,
    its_p_value,
    onset_interval,
    recovery_of,
)

R2T = "routing_to_traffic"
T2R = "traffic_to_routing"
UNKNOWN = "unknown"

#: Mechanisms a routing edge can carry.  ``origin_change`` denotes an
#: announcement of the prefix by a *different* origin, which is a fault or a
#: hijack and belongs to the Phase-1 rules; it is never a reaction to traffic.
ROUTING_MECHANISMS = (
    "withdrawal",
    "announcement",
    "path_change",
    "origin_change",
)

#: Mechanisms consistent with an operator *reacting* to observed traffic.
REACTION_COMPATIBLE = ("withdrawal", "announcement", "path_change")

#: Every reason this estimator can return.  The evaluator asserts that all
#: observed reasons are members of this tuple, so a new code path cannot ship
#: without a name an operator can read.
REASONS = (
    "series_too_short",
    "routing_series_flat",
    "traffic_series_flat",
    "no_routing_edge",
    "no_traffic_edge",
    "inadmissible_precedence",
    "pre_period_too_short",
    "post_window_too_short",
    "not_exclusive",
    "provenance_disjoint",
    "mirror_contradicted",
    "mechanism_unknown",
    "reactive_incompatible",
    "committed",
)

#: Frozen decision rule.  Changing any value changes the operating point and
#: must be reported as a new protocol (``protocol_hash`` identifies it).
AEA_PROTOCOL: Dict[str, Any] = {
    "min_buckets": 12,            # below this the series cannot support a split
    "min_segment_frac": 0.10,     # each side of a split holds >= 10% of the window
    "break_t_stat": 2.0,          # |Welch t| needed to call an edge
    "bic_penalty": 1.0,           # multiplier on the BIC penalty for extra changes
    "max_placebos": 60,           # placebo anchors enumerated for V2
    # The exact permutation p-value with the add-one correction cannot go
    # below 1/(B+1), so a window that supplies fewer than 1/alpha - 1 = 19
    # placebos cannot reject at alpha = 0.05 at all.  Requiring 20 anchors
    # makes that constraint explicit rather than leaving it to be discovered
    # as a window that never commits.
    "min_placebos": 20,           # below this the p-value cannot reach alpha
    "alpha": 0.05,                # level of the single V2 test
    "precedence_tol_buckets": 0,  # buckets of simultaneity tolerated by V1
    "onset_slack": 1.0,           # BIC units of onset ambiguity kept in V1
    "recovery_tol_frac": 1.0 / 12.0,
}


def protocol_hash(cfg: Optional[Dict[str, Any]] = None) -> str:
    """Short stable identifier of a protocol, printed into every artefact."""
    data = cfg if cfg is not None else AEA_PROTOCOL
    payload = json.dumps({k: data[k] for k in sorted(data)}, sort_keys=True,
                         default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


@dataclass
class OwnershipVerdict:
    """Outcome of one attribution, with every veto that was evaluated."""

    direction: str = UNKNOWN
    reason: str = ""
    vetoes: Dict[str, str] = field(default_factory=dict)
    tau_routing: Optional[int] = None
    tau_traffic: Optional[int] = None
    lag: Optional[int] = None
    effect: Optional[float] = None
    p_value: float = 1.0
    n_placebos: int = 0
    horizon: Optional[int] = None
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
            "tau_routing": self.tau_routing,
            "tau_traffic": self.tau_traffic,
            "lag": self.lag,
            "effect": round(self.effect, 4) if self.effect is not None else None,
            "p_value": (round(self.p_value, 6)
                        if self.p_value == self.p_value else None),
            "n_placebos": self.n_placebos,
            "horizon": self.horizon,
            "mechanism": self.mechanism,
            "tests": self.tests,
        }
        if include_protocol:
            out["protocol"] = self.protocol
            out["protocol_hash"] = protocol_hash(self.protocol)
        return out



def matched_horizon(tau: int, K: int, min_seg: int) -> Optional[int]:
    """The response horizon the engine uses at an onset ``tau``.

    The horizon is bounded by the pre-onset period, because the placebo null
    must be estimated from the same series with the same horizon: a window
    that cannot supply a matched-horizon comparison is an absence of
    evidence, not evidence of absence.

    Returns ``None`` when the window cannot support the test.
    """
    pre_capacity = tau - 2 * min_seg
    if pre_capacity < 2 * min_seg:
        return None
    horizon = min(K - tau, pre_capacity // 2)
    return horizon if horizon >= min_seg else None


def anchored_test(
    cause: np.ndarray,
    response: np.ndarray,
    det_c: Dict[str, Any],
    det_o: Dict[str, Any],
    cfg: Dict[str, Any],
    *,
    side: str,
    routing_scope: Optional[Sequence[str]],
    series_scope: Optional[Sequence[str]],
) -> Dict[str, Any]:
    """Evaluate V1-V4 with the anchor on ``cause`` and the outcome on ``response``.

    Precedence (the ordering half of V1) is the caller's responsibility; this
    function assumes the anchor is the earlier of the two edges.

    Returns a dict with ``reason`` (empty when every veto passes), ``vetoes``,
    the exclusivity statistics and a ``detail`` block for the cache.
    """
    K = len(cause)
    min_seg = max(2, int(round(cfg["min_segment_frac"] * K)))
    vetoes: Dict[str, str] = {"V1": "fail", "V2": "fail",
                              "V3": "suspend", "V4": "suspend"}
    out: Dict[str, Any] = {
        "reason": "",
        "vetoes": vetoes,
        "horizon": None,
        "effect": None,
        "p_value": 1.0,
        "n_placebos": 0,
        "detail": {},
    }

    # V1 (persistence half): the anchor must be a real, persistent edge.
    if det_c["changes"] and abs(det_c["t_onset"]) >= cfg["break_t_stat"]:
        vetoes["V1"] = "pass"
    else:
        out["reason"] = "no_%s_edge" % side
        return out

    tau = int(det_c["changes"][0])
    pre_capacity = tau - 2 * min_seg
    if pre_capacity < 2 * min_seg:
        out["reason"] = "pre_period_too_short"
        return out
    if K - tau < min_seg:
        out["reason"] = "post_window_too_short"
        return out
    horizon = matched_horizon(tau, K, min_seg)
    if horizon is None:
        out["reason"] = "post_window_too_short"
        return out

    effect = its_effect(response, tau, horizon, min_seg)
    if effect is None:
        out["reason"] = "post_window_too_short"
        return out
    p, n_placebos = its_p_value(
        response, tau, effect, horizon, min_seg,
        max_placebos=int(cfg["max_placebos"]),
        min_placebos=int(cfg["min_placebos"]),
    )
    out.update(horizon=horizon, effect=float(effect),
               p_value=float(p), n_placebos=int(n_placebos))
    if n_placebos == 0:
        # The pre-period cannot supply a matched-horizon comparison.  That is
        # an absence of evidence, not evidence of absence.
        out["reason"] = "pre_period_too_short"
        return out

    # V2: the displacement must exceed what the response does on its own.
    if not (p < cfg["alpha"]):
        vetoes["V2"] = "fail"
        out["reason"] = "not_exclusive"
        return out
    vetoes["V2"] = "pass"

    # V3: the response must be able to observe the entity the edge is about.
    provenance = "suspend"
    if routing_scope is not None and series_scope is not None:
        shared = {str(s) for s in routing_scope} & {str(s) for s in series_scope}
        provenance = "pass" if shared else "fail"
        out["detail"]["shared_scope"] = len(shared)
    vetoes["V3"] = provenance
    if provenance == "fail":
        out["reason"] = "provenance_disjoint"
        return out

    # V4: if the anchor reverts, the response must revert after it.
    rec_c, rec_o = recovery_of(det_c), recovery_of(det_o)
    tol = max(2, int(round(cfg["recovery_tol_frac"] * K)))
    mirror: Dict[str, Any] = {
        "cause_recovery": rec_c,
        "response_recovery": rec_o,
        "tolerance": tol,
    }
    if rec_c is not None and rec_o is not None:
        if abs(rec_c - rec_o) > tol:
            vetoes["V4"] = "fail"
            mirror["verdict"] = "contradicted"
            out["detail"]["mirror"] = mirror
            out["reason"] = "mirror_contradicted"
            return out
        vetoes["V4"] = "pass"
        mirror["verdict"] = "congruent"
    elif rec_c is None and rec_o is None:
        # No reversion inside the window: the check is unobservable, which is
        # recorded rather than treated as a pass or a refutation.
        mirror["verdict"] = "unobservable"
    else:
        mirror["verdict"] = "one_sided"
    out["detail"]["mirror"] = mirror
    return out


def attribute(
    routing_series: Sequence[float],
    traffic_series: Sequence[float],
    *,
    routing_mechanism: Optional[str] = None,
    routing_scope: Optional[Sequence[str]] = None,
    series_scope: Optional[Sequence[str]] = None,
    protocol: Optional[Dict[str, Any]] = None,
) -> OwnershipVerdict:
    """Return the direction that survives V1-V4, or an abstention with a reason.

    ``routing_mechanism`` is the annotated mechanism of the routing change and
    is consulted only for a traffic-to-routing claim; ``routing_scope`` and
    ``series_scope`` are the affected and the observed entity sets, both
    optional -- an unknown scope suspends V3 instead of failing it.
    """
    cfg = dict(AEA_PROTOCOL)
    if protocol:
        cfg.update(protocol)

    r = clean(routing_series)
    t = clean(traffic_series)
    K = int(min(len(r), len(t)))
    verdict = OwnershipVerdict(
        mechanism=routing_mechanism,
        protocol={k: cfg[k] for k in sorted(cfg)},
    )

    def stop_verdict(reason: str, vetoes: Dict[str, str],
              tests: Optional[Dict[str, Any]] = None) -> OwnershipVerdict:
        verdict.reason = reason
        verdict.vetoes = vetoes
        if tests:
            verdict.tests.update(tests)
        return verdict

    if K < cfg["min_buckets"]:
        return stop_verdict("series_too_short", {"V1": "fail"})
    r, t = r[:K], t[:K]
    if float(np.ptp(r)) < 1e-9:
        return stop_verdict("routing_series_flat", {"V1": "fail"})
    if float(np.ptp(t)) < 1e-9:
        return stop_verdict("traffic_series_flat", {"V1": "fail"})

    min_seg = max(2, int(round(cfg["min_segment_frac"] * K)))
    det_r = detect_changes(r, min_seg, cfg["bic_penalty"])
    det_t = detect_changes(t, min_seg, cfg["bic_penalty"])

    if not det_r["changes"] or abs(det_r["t_onset"]) < cfg["break_t_stat"]:
        return stop_verdict("no_routing_edge", {"V1": "fail"})
    if not det_t["changes"] or abs(det_t["t_onset"]) < cfg["break_t_stat"]:
        return stop_verdict("no_traffic_edge", {"V1": "fail"})

    tau_r, tau_t = int(det_r["changes"][0]), int(det_t["changes"][0])
    verdict.tau_routing, verdict.tau_traffic = tau_r, tau_t
    ci_r = onset_interval(r, min_seg, det_r, cfg["bic_penalty"],
                          cfg["onset_slack"])
    ci_t = onset_interval(t, min_seg, det_t, cfg["bic_penalty"],
                          cfg["onset_slack"])
    precedence = {
        "tau_routing": tau_r,
        "tau_traffic": tau_t,
        "routing_onset_interval": list(ci_r) if ci_r is not None else None,
        "traffic_onset_interval": list(ci_t) if ci_t is not None else None,
    }
    blocked = {"V1": "fail", "V2": "not_run", "V3": "not_run", "V4": "not_run"}

    # V1 (ordering half).  Precedence is established only when the onset sets
    # are disjoint: two edges whose onsets the data cannot separate are not
    # ordered, however their point estimates fall.
    tol = int(cfg["precedence_tol_buckets"])
    if ci_r is None or ci_t is None:
        return stop_verdict("inadmissible_precedence", blocked,
                     {"precedence": dict(precedence, verdict="onset_unresolved")})
    if ci_r[1] + tol < ci_t[0]:
        direction, side = R2T, "routing"
        cause, response, det_c, det_o = r, t, det_r, det_t
        verdict.lag = tau_t - tau_r
    elif ci_t[1] + tol < ci_r[0]:
        direction, side = T2R, "traffic"
        cause, response, det_c, det_o = t, r, det_t, det_r
        verdict.lag = tau_r - tau_t
    else:
        return stop_verdict("inadmissible_precedence", blocked,
                     {"precedence": dict(precedence,
                                         verdict="overlapping_onsets")})
    precedence.update(lag=verdict.lag, order=direction)
    verdict.tests["precedence"] = precedence

    # A reaction claim needs a named reaction.  Absence of an annotation is
    # not evidence that one occurred.
    if direction == T2R:
        if routing_mechanism is None:
            return stop_verdict(
                "mechanism_unknown",
                {"V1": "pass", "V2": "not_run", "V3": "not_run", "V4": "not_run"},
                {"mechanism": {"mechanism": None, "verdict": "unknown"}},
            )
        if routing_mechanism not in REACTION_COMPATIBLE:
            return stop_verdict(
                "reactive_incompatible",
                {"V1": "pass", "V2": "not_run", "V3": "not_run", "V4": "not_run"},
                {"mechanism": {"mechanism": routing_mechanism,
                               "verdict": "incompatible"}},
            )
        verdict.tests["mechanism"] = {"mechanism": routing_mechanism,
                                      "verdict": "reaction_compatible"}

    res = anchored_test(
        cause, response, det_c, det_o, cfg,
        side=side, routing_scope=routing_scope, series_scope=series_scope,
    )
    verdict.vetoes = res["vetoes"]
    verdict.effect, verdict.p_value = res["effect"], res["p_value"]
    verdict.n_placebos, verdict.horizon = res["n_placebos"], res["horizon"]
    verdict.tests["exclusivity"] = {
        "effect": None if res["effect"] is None else round(res["effect"], 4),
        "p": round(float(res["p_value"]), 4),
        "placebos": res["n_placebos"],
        "horizon": res["horizon"],
    }
    verdict.tests["provenance"] = {
        "routing_scope": None if routing_scope is None else len(list(routing_scope)),
        "series_scope": None if series_scope is None else len(list(series_scope)),
        "shared": res["detail"].get("shared_scope"),
        "verdict": res["vetoes"].get("V3"),
    }
    if "mirror" in res["detail"]:
        verdict.tests["mirror"] = res["detail"]["mirror"]

    if res["reason"]:
        return stop_verdict(res["reason"], res["vetoes"])

    verdict.direction = direction
    verdict.reason = "committed"
    return verdict


__all__ = [
    "AEA_PROTOCOL",
    "OwnershipVerdict",
    "REACTION_COMPATIBLE",
    "REASONS",
    "ROUTING_MECHANISMS",
    "R2T",
    "T2R",
    "UNKNOWN",
    "attribute",
    "matched_horizon",
    "protocol_hash",
]
