"""The quick cache must stay small enough to store and to score.

The hijack detector emits one record per announcement.  Before the cache was
compacted, a single busy window produced a 450 MB cache that was OOM-killed
while being written and took minutes to load during evaluation.  These tests
pin the compaction behaviour so that cannot regress.

They also check that the compaction is *lossless for scoring*: the incident
count must survive, the announcement count must remain available, and the
distinct-incident helper must still see the same incidents.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_compaction import (  # noqa: E402
    collapse_records,
    compact_correlation_payload,
    compact_routing_payload,
    incident_key,
)


def test_repeated_announcements_collapse_to_one_incident():
    records = [
        {"prefix": "192.0.2.0/24", "hijacking_as": "AS64500", "type": "origin_hijacked"}
        for _ in range(50)
    ]
    collapsed, original = collapse_records(records)
    assert original == 50
    assert len(collapsed) == 1
    assert collapsed[0]["announcement_count"] == 50


def test_different_prefixes_stay_separate():
    records = [
        {"prefix": "192.0.2.0/24", "hijacking_as": "AS64500"},
        {"prefix": "198.51.100.0/24", "hijacking_as": "AS64500"},
        {"prefix": "192.0.2.0/24", "hijacking_as": "AS64501"},
    ]
    collapsed, original = collapse_records(records)
    assert original == 3
    assert len(collapsed) == 3


def test_incident_key_ignores_timestamp():
    a = {"prefix": "192.0.2.0/24", "hijacking_as": "AS1", "timestamp": "2024-01-01T00:00:00"}
    b = {"prefix": "192.0.2.0/24", "hijacking_as": "AS1", "timestamp": "2024-01-01T00:09:00"}
    assert incident_key(a) == incident_key(b)


def test_compact_routing_payload_keeps_record_counts():
    routing = {
        "origin_hijacked": [{"prefix": "192.0.2.0/24", "hijacking_as": "AS1"}] * 10,
        "route_leaks": [{"prefix": "192.0.2.0/24"}] * 3,
        "outage_score": 0.5,
    }
    out = compact_routing_payload(routing)
    assert len(out["origin_hijacked"]) == 1
    assert out["origin_hijacked_record_count"] == 10
    assert len(out["route_leaks"]) == 1
    assert out["route_leaks_record_count"] == 3
    # scalars untouched
    assert out["outage_score"] == 0.5


def test_compact_correlation_payload_drops_duplicated_streams():
    correlation = {
        "summary": {"routing_event_count": 408543},
        "routing_events_full": [{"timestamp": "t"}] * 100,
        "traffic_events_full": [{"timestamp": "t"}] * 50,
        "timeline": [{"timestamp": "t"}] * 10,
    }
    out = compact_correlation_payload(correlation)
    assert "routing_events_full" not in out
    assert "traffic_events_full" not in out
    # the timeline and the summary survive
    assert len(out["timeline"]) == 10
    assert out["summary"]["routing_event_count"] == 408543


def test_compaction_does_not_mutate_the_input():
    records = [{"prefix": "192.0.2.0/24", "hijacking_as": "AS1"}] * 5
    routing = {"origin_hijacked": records}
    compact_routing_payload(routing)
    assert len(routing["origin_hijacked"]) == 5


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
