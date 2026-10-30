"""The quick cache must not report truncated counts as real measurements.

Two counting bugs have silently degraded the evaluation, and both are pinned
here so they cannot come back:

1.  ``leak_count_total`` was written as the *truncated* length of the itemised
    leak list, so every saturated event read as exactly 5000 leaks.  The
    count then carried no information about the cause class: 4 of the 22
    scored events sat at the cap, spread over outage, leak and hijack alike.
    The true total comes from the detector's own ``leak_count_total`` /
    ``total_detected`` field.

2.  The quick cache stored one record per *announcement*.  A busy window
    produced a 450 MB cache that was OOM-killed while being written.  The
    records are collapsed into one record per incident, with the original
    count preserved separately.

The tests exercise the real functions, not a re-implementation.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_compaction import compact_cache_payload  # noqa: E402
from agents.report_agent import normalize_routing  # noqa: E402


def test_leak_count_total_is_not_the_truncated_length():
    """A saturated leak list must not report 5000 as its total."""
    truncated_list = [{"prefix": "192.0.2.0/24"}] * 5000
    routing = {
        "route_leaks": truncated_list,
        "leak_count": 5000,
        "leak_count_total": 123456,
        "leak_results_truncated": True,
        "origin_hijacked": [],
        "origin_hijacking": [],
        "forge_hijacked": [],
        "forge_hijacking": [],
    }
    out = normalize_routing(routing)
    assert out["leak_count_total"] == 123456, (
        "leak_count_total must carry the detector's uncapped total, "
        f"got {out['leak_count_total']}")
    assert out["leak_results_truncated"] is True


def test_leak_count_total_falls_back_to_the_itemised_count():
    """Without a separate total, the itemised length is the best available."""
    routing = {
        "route_leaks": [{"prefix": "192.0.2.0/24"}] * 3,
        "origin_hijacked": [],
        "origin_hijacking": [],
        "forge_hijacked": [],
        "forge_hijacking": [],
    }
    out = normalize_routing(routing)
    assert out["leak_count_total"] == 3


def test_compaction_keeps_every_incident():
    records = [
        {"prefix": f"192.0.2.{i}/32", "hijacking_as": "AS64500"}
        for i in range(100)
    ]
    for _ in range(5):
        records.extend(records[:100])
    routing, _ = compact_cache_payload({"origin_hijacked": records}, {})
    assert len(routing["origin_hijacked"]) == 100
    assert routing["origin_hijacked_record_count"] == 600


def test_compaction_shrinks_a_saturated_payload():
    """The compaction must actually reduce the payload, not just reshape it."""
    records = [
        {"prefix": "192.0.2.0/24", "hijacking_as": "AS64500",
         "as_path": "64500 64501 64502 64503"}
        for _ in range(50000)
    ]
    routing_before = {"origin_hijacked": records}
    correlation_before = {
        "routing_events_full": [{"timestamp": "t", "prefix": "192.0.2.0/24"}] * 50000}
    before = len(str(routing_before)) + len(str(correlation_before))

    routing, correlation = compact_cache_payload(routing_before, correlation_before)
    after = len(str(routing)) + len(str(correlation))

    assert after < before, f"payload did not shrink: {before} -> {after}"
    assert "routing_events_full" not in correlation


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"PASS {name}")
        except (AssertionError, Exception) as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
