"""Keep the quick cache small enough to store, load and score.

The hijack detector emits **one record per announcement**.  A prefix that is
re-announced a few hundred times therefore produces a few hundred records for
what is a single incident, and the quick cache for such a window reaches
several hundred megabytes.  The correlation analyzer then copies that same
event stream into ``correlation.routing_events_full``, so the payload is
stored twice.

Downstream the code that scores the event already collapses the records into
incidents (``distinct_hijack_count`` counts distinct prefix/origin pairs), so
the per-announcement duplicates carry no information that the incident list
does not.  This module performs that collapse *before* the cache is written:

* every event list is reduced to one record per incident, keeping the first
  occurrence and the number of announcements it represents;
* the original lengths are preserved under ``*_record_count`` keys, so no
  downstream consumer loses the announcement-frequency information;
* the correlation block's duplicated ``*_events_full`` streams are dropped,
  since they are a second copy of the same events.

The result is a cache that keeps every signal the evaluation uses while
shrinking by one to two orders of magnitude.
"""
from __future__ import annotations

import copy
from typing import Any

# Event lists that hold one entry per announcement.
_INCIDENT_LISTS = (
    "origin_hijacked",
    "origin_hijacking",
    "forge_hijacked",
    "forge_hijacking",
    "route_leaks",
)

# Keys of the correlation block that duplicate the routing event stream.
_DUPLICATE_EVENT_STREAMS = (
    "routing_events_full",
    "traffic_events_full",
)


def incident_key(record: Any):
    """Identity of the incident a record belongs to.

    Two records describe the same incident when they name the same prefix
    and the same hijacking origin.  The timestamp is deliberately excluded:
    a leak or hijack that is re-announced for ten minutes is one incident
    observed repeatedly, not ten incidents.
    """
    if not isinstance(record, dict):
        return (str(record),)

    prefix = (
        record.get("prefix")
        or record.get("prefix_str")
        or record.get("claimed_prefix")
        or ""
    )
    origin = (
        record.get("hijacking_as")
        or record.get("hijacker_as")
        or record.get("origin_as")
        or record.get("leak_as")
        or record.get("as_path_origin")
        or ""
    )
    kind = record.get("type") or record.get("event_type") or ""
    return (str(kind), str(prefix), str(origin))


def collapse_records(records: list):
    """Reduce per-announcement records to one record per incident.

    Returns the collapsed list and the number of original records.
    """
    if not isinstance(records, list) or not records:
        return [], 0

    seen: dict[tuple, dict] = {}
    for record in records:
        key = incident_key(record)
        if key in seen:
            existing = seen[key]
            existing["announcement_count"] = int(
                existing.get("announcement_count", 1)) + 1
            continue
        if isinstance(record, dict):
            collapsed = copy.deepcopy(record)
            collapsed["announcement_count"] = 1
        else:
            collapsed = {"value": record, "announcement_count": 1}
        seen[key] = collapsed
    return list(seen.values()), len(records)


def compact_routing_payload(routing: Any):
    """Return a copy of the routing payload with the event lists collapsed."""
    if not isinstance(routing, dict):
        return routing

    result = dict(routing)
    for key in _INCIDENT_LISTS:
        if key not in result:
            continue
        records = result[key]
        collapsed, original = collapse_records(records)
        result[key] = collapsed
        result[f"{key}_record_count"] = original
    return result


def compact_correlation_payload(correlation: Any):
    """Return a copy of the correlation block without the duplicated stream."""
    if not isinstance(correlation, dict):
        return correlation

    result = dict(correlation)
    for key in _DUPLICATE_EVENT_STREAMS:
        if key in result:
            result.pop(key, None)

    # The nested ``correlation`` block may carry its own copy.
    inner = result.get("correlation")
    if isinstance(inner, dict):
        inner_copy = dict(inner)
        for key in _DUPLICATE_EVENT_STREAMS:
            inner_copy.pop(key, None)
        result["correlation"] = inner_copy
    return result


def compact_cache_payload(routing: Any, correlation: Any):
    """Compact both halves of a quick cache in one call."""
    return (compact_routing_payload(routing),
            compact_correlation_payload(correlation))
