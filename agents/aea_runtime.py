"""Production adapter for the admissible edge attribution (AEA) estimator.

The estimator itself lives in :mod:`agents.edge_ownership` and decides
nothing about where its input comes from.  This module supplies the two
things the estimator needs and the pipeline is the only place that knows:
the two bucketed series on a shared grid, and the two scope sets and the
routing mechanism that the vetoes read.

The series are built here rather than in the engine because the shared
grid is a property of the *event window*, and the engine already knows
the window.  Both logs are bucketed jointly, so index ``k`` denotes the
same wall-clock interval on both sides; an empty bucket is a floor, not a
zero.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agents.edge_ownership import (
    AEA_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    OwnershipVerdict,
    attribute,
    protocol_hash,
)

__all__ = [
    "AEA_PROTOCOL",
    "OwnershipVerdict",
    "R2T",
    "T2R",
    "UNKNOWN",
    "attribute",
    "build_shared_series",
    "protocol_hash",
    "run_aea",
]

#: Bucket width of the shared grid, in seconds.
GRID_SECONDS = 300

#: Event kinds that a routing edge can carry.  A traffic-to-routing claim
#: requires one of the reaction-compatible mechanisms, because only an
#: operator can react to observed traffic.
_MECHANISM_BY_EVENT_TYPE = {
    "hijack": "origin_change",
    "forge_hijack": "origin_change",
    "leak": "path_change",
    "outage": "withdrawal",
}


def parse_timestamp(value: object) -> Optional[datetime]:
    """Parse the timestamp spellings that reach the engine.

    Every parsed value is made timezone-naive in UTC.  The two logs that
    meet here carry timestamps in different spellings -- some with a
    ``Z`` suffix, some with an explicit offset, some with none -- and
    subtracting an aware from a naive datetime raises.  Normalising at the
    boundary keeps the arithmetic below total.
    """
    if isinstance(value, datetime):
        return _as_utc_naive(value)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    candidate = text.replace("Z", "+00:00")
    try:
        return _as_utc_naive(datetime.fromisoformat(candidate))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M",
                "%Y-%m-%d"):
        try:
            return _as_utc_naive(datetime.strptime(text[:len(fmt) + 6], fmt))
        except ValueError:
            continue
    return None


def _as_utc_naive(value: datetime) -> datetime:
    """Return ``value`` as a naive UTC datetime."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def build_shared_series(
    routing_timeline: Sequence[dict],
    traffic_timeline: Sequence[dict],
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    *,
    grid_seconds: int = GRID_SECONDS,
) -> Tuple[List[float], List[float]]:
    """Bucket both logs jointly and return the two series on one grid.

    The grid is anchored at the earliest timestamp of the union of the two
    logs, or at ``window_start`` when the caller knows it.  Both series
    are evaluated on the same index set, so a bucket index means the same
    wall-clock interval on both sides.  An empty bucket is floored rather
    than dropped, so a quiet interval reads as "no observation" instead of
    silently shortening the window.
    """
    events: List[Tuple[datetime, float, str]] = []
    for point in routing_timeline or []:
        ts = parse_timestamp(point.get("timestamp"))
        if ts is None:
            continue
        events.append((ts, float(point.get("score", 0.0) or 0.0), "routing"))
    for point in traffic_timeline or []:
        ts = parse_timestamp(point.get("timestamp"))
        if ts is None:
            continue
        events.append((ts, float(point.get("score", 0.0) or 0.0), "traffic"))

    if not events:
        return [], []

    stamps = [e[0] for e in events]
    origin = window_start or min(stamps)
    last = window_end or max(stamps)
    span = int((last - origin).total_seconds())
    buckets = max(1, span // grid_seconds + 1)
    if buckets < AEA_PROTOCOL["min_buckets"]:
        buckets = AEA_PROTOCOL["min_buckets"]

    r_sum = [0.0] * buckets
    t_sum = [0.0] * buckets
    r_n = [0] * buckets
    t_n = [0] * buckets
    for ts, score, side in events:
        idx = int((ts - origin).total_seconds()) // grid_seconds
        if idx < 0 or idx >= buckets:
            continue
        if side == "routing":
            r_sum[idx] += score
            r_n[idx] += 1
        else:
            t_sum[idx] += score
            t_n[idx] += 1

    eps = 1e-9
    routing = [(r_sum[i] / r_n[i]) if r_n[i] else eps for i in range(buckets)]
    traffic = [(t_sum[i] / t_n[i]) if t_n[i] else eps for i in range(buckets)]
    return routing, traffic


def collect_scope(
    routing_timeline: Sequence[dict],
    traffic_timeline: Sequence[dict],
    routing_context: Optional[dict] = None,
) -> Tuple[Optional[List[str]], Optional[List[str]]]:
    """Return the affected and the observed entity sets for the V3 veto.

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


def run_aea(
    routing_timeline: Sequence[dict],
    traffic_timeline: Sequence[dict],
    *,
    routing_context: Optional[dict] = None,
    traffic_context: Optional[dict] = None,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    protocol: Optional[Dict[str, Any]] = None,
) -> Tuple[OwnershipVerdict, List[float], List[float]]:
    """Run the AEA estimator over one window and return its verdict.

    The verdict carries the veto that failed and the statistic behind it,
    so a refusal is auditable rather than a silent decline.
    """
    routing_series, traffic_series = build_shared_series(
        routing_timeline, traffic_timeline, window_start, window_end)
    routing_scope, traffic_scope = collect_scope(
        routing_timeline, traffic_timeline, routing_context)
    mechanism = collect_mechanism(routing_timeline, routing_context)

    verdict = attribute(
        routing_series,
        traffic_series,
        routing_mechanism=mechanism,
        routing_scope=routing_scope,
        series_scope=traffic_scope,
        protocol=protocol,
    )
    return verdict, routing_series, traffic_series
