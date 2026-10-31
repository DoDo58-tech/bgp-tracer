"""Production adapter for the PADDLE estimator.

The estimator itself lives in :mod:`agents.paddle_attribution` and
decides nothing about where its input comes from.  This module supplies
the three things the estimator needs and that only the pipeline knows:
the routing side as a control-plane rate series, the traffic side as a
series of signed deviations, and the impact window that bounds the
search for the data plane's trough.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agents.control_plane import (
    CONTROL_PLANE_CHANNELS,
    ControlPlaneSeries,
    build_control_plane_series,
)
from agents.paddle_attribution import (
    PADDLE_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    CausalVerdict,
    attribute,
    protocol_hash,
)
from agents.temporal import parse_timestamp

__all__ = [
    "PADDLE_PROTOCOL",
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
    "impact_window",
    "protocol_hash",
    "run_paddle",
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
    """The traffic side as timestamped, signed deviations.

    The traffic detector samples on the provider's interval, which is
    coarser than and offset from the control-plane clock.  The
    observations are therefore kept as they were measured -- each with
    its own timestamp -- and the estimator places them on the common
    wall-clock axis itself.  Resampling them onto the control-plane grid
    here would throw away observations and manufacture a lag that is an
    artefact of the resampling.

    The magnitude is the **signed** deviation from the detector's own
    historical baseline.  The sign matters and is recovered from the
    measured value against the historical mean, because the cached
    ``z_score`` field carries the magnitude alone; see
    :func:`agents.paddle_attribution.traffic_deviation`.
    """
    out: List[Dict[str, Any]] = []
    for point in traffic_timeline or []:
        ts = parse_timestamp(point.get("timestamp"))
        if ts is None:
            continue
        raw = point.get("raw_event")
        raw = raw if isinstance(raw, dict) else {}
        merged: Dict[str, Any] = dict(raw)
        merged.update({k: v for k, v in point.items() if v is not None})
        out.append({"timestamp": ts, "raw_event": merged})
    return out


def impact_window(
    traffic_block: Optional[Dict[str, Any]],
) -> Optional[Tuple[datetime, datetime]]:
    """The window the traffic detector reported as the impact.

    The trough is searched inside this window, so that the anchor is
    the event's own trough rather than the worst deviation of the whole
    record.
    """
    if not isinstance(traffic_block, dict):
        return None
    for key in ("expanded_windows", "consecutive_anomaly_windows"):
        windows = traffic_block.get(key)
        if isinstance(windows, list) and windows:
            first = windows[0]
            if not isinstance(first, dict):
                continue
            start = parse_timestamp(first.get("start"))
            end = parse_timestamp(first.get("end"))
            if start is not None:
                return (start, end if end is not None else start)
    period = traffic_block.get("original_outage_period")
    if isinstance(period, dict):
        start = parse_timestamp(period.get("start_time"))
        end = parse_timestamp(period.get("end_time"))
        if start is not None:
            return (start, end if end is not None else start)
    return None


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


def own_channels_present(control: ControlPlaneSeries) -> bool:
    """Whether the series carries the target's *own* announcement channel.

    The detector's cached feature series counts the target's
    *involvement* in other people's updates.  That is the wrong
    quantity for a causal measurement: while an AS is down it keeps
    receiving a flood of updates about other people's routes, so an
    involvement measure stays roughly flat through the outage, while the
    measure that moves is the count of announcements whose **origin** is
    the target.

    A series without the own-announcement channel can therefore never
    support the claim the estimator is trying to make, and saying so is
    more honest than measuring the wrong thing.
    """
    for channel in ("own_volume", "own_withdrawal"):
        values = control.channel(channel)
        if values and any(values):
            return True
    return False


def run_paddle(
    routing_analysis: Optional[Dict[str, Any]],
    traffic_timeline: Sequence[dict],
    routing_timeline: Sequence[dict] = (),
    *,
    routing_context: Optional[dict] = None,
    traffic_block: Optional[Dict[str, Any]] = None,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    protocol: Optional[Dict[str, Any]] = None,
    target_as: Optional[str] = None,
    archive_evidence: Optional[Dict[str, Any]] = None,
) -> Tuple[CausalVerdict, ControlPlaneSeries, List[Dict[str, Any]]]:
    """Run the PADDLE estimator over one window and return its verdict.

    The verdict carries the veto that failed and the statistic behind it,
    so a refusal is auditable rather than a silent decline.

    The control plane is taken from the detector's cached feature series
    when that series carries the target's own announcement channel, and
    from the update archive when it does not.  The archive is the
    authoritative source for that channel -- it is the only place the
    target's own origin is recorded -- and a cached series that lacks it
    cannot support a causal claim, so it is not used as if it could.
    """
    control = build_control_plane_series(
        routing_analysis, window_start=window_start, window_end=window_end)

    if not own_channels_present(control) and archive_evidence:
        from agents.control_plane_archive import series_from_payload

        archived = series_from_payload(
            archive_evidence,
            window_start=window_start,
        )
        if archived.stamps and own_channels_present(archived):
            control = archived

    traffic_observations = build_traffic_observations(traffic_timeline)
    routing_scope, traffic_scope = collect_scope(
        routing_timeline, traffic_timeline, routing_context)
    mechanism = collect_mechanism(routing_timeline, routing_context)
    window = impact_window(traffic_block)

    verdict = attribute(
        control,
        traffic_observations,
        routing_mechanism=mechanism,
        routing_scope=routing_scope,
        series_scope=traffic_scope,
        impact_window=window,
        protocol=protocol,
    )
    return verdict, control, traffic_observations
