"""Production adapter for the CDPR estimator.

The estimator itself lives in :mod:`agents.cdpr_attribution` and decides
nothing about where its input comes from.  This module supplies the two
things the estimator needs and that only the pipeline knows: the routing
side as a control-plane rate series, and the traffic side as a series on
the *same* clock.

The two sides are put on one clock by bucketing the traffic series onto
the control-plane buckets.  An empty traffic bucket is a floor, not a
zero, so a quiet interval reads as "no observation" instead of silently
shortening the window.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agents.aea_runtime import parse_timestamp
from agents.cdpr_attribution import (
    CDPR_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    CausalVerdict,
    attribute,
    protocol_hash,
)
from agents.control_plane import (
    CONTROL_PLANE_CHANNELS,
    ControlPlaneSeries,
    build_control_plane_series,
)

__all__ = [
    "CDPR_PROTOCOL",
    "CausalVerdict",
    "CONTROL_PLANE_CHANNELS",
    "R2T",
    "T2R",
    "UNKNOWN",
    "attribute",
    "build_control_plane_series",
    "build_traffic_observations",
    "collect_mechanism",
    "collect_scope",
    "protocol_hash",
    "run_cdpr",
]

#: Event kinds that a routing edge can carry.  A traffic-to-routing claim
#: requires one of the reaction-compatible mechanisms, because only an
#: operator can react to observed traffic.
_MECHANISM_BY_EVENT_TYPE = {
    "hijack": "origin_change",
    "forge_hijack": "origin_change",
    "leak": "path_change",
    "outage": "withdrawal",
}


def build_traffic_observations(
    traffic_timeline: Sequence[dict],
) -> List[Dict[str, Any]]:
    """The traffic side as timestamped response magnitudes.

    The traffic detector samples on the provider's interval, which is
    coarser than and offset from the control-plane clock.  The
    observations are therefore kept as they were measured -- each with
    its own timestamp -- and the estimator places them on the common
    wall-clock axis itself.  Resampling them onto the control-plane grid
    here would throw away observations and manufacture a lag that is an
    artefact of the resampling.

    The magnitude is the *deviation* from the detector's own historical
    baseline, taken as an absolute value: a response to a routing change
    is a movement in either direction, and the sign is carried by the
    detector's own ``direction`` field rather than by the magnitude.
    """
    out: List[Dict[str, Any]] = []
    for point in traffic_timeline or []:
        ts = parse_timestamp(point.get("timestamp"))
        if ts is None:
            continue
        raw = point.get("raw_event")
        raw = raw if isinstance(raw, dict) else {}
        magnitude: Optional[float] = None
        for key in ("z_score", "severity", "score"):
            val = point.get(key)
            if val is None:
                val = raw.get(key)
            if isinstance(val, (int, float)):
                magnitude = abs(float(val))
                break
        if magnitude is None:
            magnitude = 0.0
        out.append({"timestamp": ts, "magnitude": magnitude, "raw_event": raw})
    return out


def collect_scope(
    routing_timeline: Sequence[dict],
    traffic_timeline: Sequence[dict],
    routing_context: Optional[dict] = None,
) -> Tuple[Optional[List[str]], Optional[List[str]]]:
    """Return the affected and the observed entity sets for the scope veto.

    The routing side is the set of prefixes the routing edges are about;
    the traffic side is the set of prefixes the traffic series was built
    over.  When either side is unknown the veto suspends rather than
    fails, so a missing scope is never laundered into a refutation.
    """
    ctx = routing_context or {}
    routing_scope: List[str] = []
    traffic_scope: List[str] = []

    affected = ctx.get("affected_prefixes")
    if isinstance(affected, (list, tuple, set)):
        routing_scope.extend(str(p) for p in affected if p)
    single = ctx.get("affected_prefix")
    if single:
        routing_scope.append(str(single))

    for point in routing_timeline or []:
        raw = point.get("raw_event") or {}
        if not isinstance(raw, dict):
            continue
        for key in ("prefix", "prefixes", "affected_prefix"):
            value = raw.get(key)
            if isinstance(value, (list, tuple, set)):
                routing_scope.extend(str(p) for p in value if p)
            elif value:
                routing_scope.append(str(value))

    for point in traffic_timeline or []:
        raw = point.get("raw_event") or {}
        if not isinstance(raw, dict):
            continue
        for key in ("prefix", "prefixes", "affected_prefix"):
            value = raw.get(key)
            if isinstance(value, (list, tuple, set)):
                traffic_scope.extend(str(p) for p in value if p)
            elif value:
                traffic_scope.append(str(value))

    routing_scope = sorted(set(routing_scope))
    traffic_scope = sorted(set(traffic_scope))
    return (
        routing_scope or None,
        traffic_scope or None,
    )


def collect_mechanism(
    routing_timeline: Sequence[dict],
    routing_context: Optional[dict] = None,
) -> Optional[str]:
    """Return the reaction-compatible mechanism of the routing edge.

    A traffic-to-routing claim asserts that an operator reacted to
    observed load, so the routing change must carry a mechanism an
    operator can produce in response.  The absence of an annotation is
    not evidence that a reaction occurred, so an unknown mechanism
    returns ``None`` and the estimator abstains.
    """
    ctx = routing_context or {}
    declared = ctx.get("routing_mechanism")
    if declared:
        return str(declared)

    kinds: List[str] = []
    for point in routing_timeline or []:
        kind = point.get("event_type")
        if kind:
            kinds.append(str(kind))
    for kind in kinds:
        mapped = _MECHANISM_BY_EVENT_TYPE.get(kind)
        if mapped:
            return mapped
    return None


def run_cdpr(
    routing_analysis: Optional[Dict[str, Any]],
    traffic_timeline: Sequence[dict],
    routing_timeline: Sequence[dict] = (),
    *,
    routing_context: Optional[dict] = None,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    protocol: Optional[Dict[str, Any]] = None,
) -> Tuple[CausalVerdict, ControlPlaneSeries, List[Dict[str, Any]]]:
    """Run the CDPR estimator over one window and return its verdict.

    The verdict carries the veto that failed and the statistic behind it,
    so a refusal is auditable rather than a silent decline.
    """
    control = build_control_plane_series(
        routing_analysis, window_start=window_start, window_end=window_end)
    traffic_observations = build_traffic_observations(traffic_timeline)
    routing_scope, traffic_scope = collect_scope(
        routing_timeline, traffic_timeline, routing_context)
    mechanism = collect_mechanism(routing_timeline, routing_context)

    verdict = attribute(
        control,
        traffic_observations,
        routing_mechanism=mechanism,
        routing_scope=routing_scope,
        series_scope=traffic_scope,
        protocol=protocol,
    )
    return verdict, control, traffic_observations
