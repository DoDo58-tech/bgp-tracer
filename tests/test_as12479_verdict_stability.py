"""End-to-end regression test for AS12479 verdict stability.

The original symptom: running the same query twice on the same AS/time
window produced reports where one showed 401 routing events and the other
showed 0 — leading to contradictory verdicts in the operator-facing HTML.

After Bug #R1 is fixed, both runs must report the same routing_event_count.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _as12479_payload(truncate_timestamps: bool):
    traffic = {
        "anomaly_count": 12,
        "anomalies": [
            {"timestamp": f"2024-01-03T{h:02d}:00:00", "severity": 0.9, "z_score": 7.2}
            for h in range(4, 16)
        ],
        "peak_trough_drop_pct": 81.47,
        "percent_change": -3.59,
        "success": True,
        "data_available": True,
    }
    ts = "14:54:29" if truncate_timestamps else "2024-01-03T14:54:29"
    routing = {
        "origin_hijacked": [],
        "origin_hijacking": [
            {"timestamp": ts, "prefix": f"2a01:c500::{i}::/48",
             "hijacker_as": "12479", "origin_as": "12479"}
            for i in range(401)
        ],
        "forge_hijacked": [], "forge_hijacking": [],
        "route_leaks": [], "leak_count": 0,
        "success": True, "data_available": True,
    }
    window = {"start": "2024-01-03T14:45:00", "end": "2024-01-03T15:00:00"}
    return traffic, routing, window


def test_as12479_routing_event_count_stable_across_timestamp_qualities():
    from agents.correlation_analyzer import analyze_temporal_correlation

    traffic, routing_full, window = _as12479_payload(truncate_timestamps=False)
    _, routing_broken, _ = _as12479_payload(truncate_timestamps=True)

    a = analyze_temporal_correlation(
        traffic_raw=traffic, routing_result=routing_full,
        target_as="12479", traffic_anomaly_window=window,
    )
    b = analyze_temporal_correlation(
        traffic_raw=traffic, routing_result=routing_broken,
        target_as="12479", traffic_anomaly_window=window,
    )

    count_a = a["correlation"]["signals"]["routing_event_count"]
    count_b = b["correlation"]["signals"]["routing_event_count"]
    assert count_a == 401, f"full-timestamp run should yield 401, got {count_a}"
    assert count_b == 401, (
        f"truncated-timestamp run lost events — root cause of AS12479 verdict "
        f"divergence; got {count_b}"
    )
    assert count_a == count_b, (
        f"data instability: full run={count_a}, broken run={count_b}"
    )


def test_as12479_traffic_event_count_preserved():
    """The traffic side should remain stable regardless of routing fix."""
    from agents.correlation_analyzer import analyze_temporal_correlation

    traffic, routing, window = _as12479_payload(truncate_timestamps=False)
    corr = analyze_temporal_correlation(
        traffic_raw=traffic, routing_result=routing,
        target_as="12479", traffic_anomaly_window=window,
    )
    assert corr["correlation"]["signals"]["traffic_event_count"] == 12
    assert corr["correlation"]["signals"]["traffic_signal_present"] is True
