"""Regression tests for Bug #R6 — react-mode multi-AS wrapper handling.

The original symptom: in React mode the tool ``analyze_traffic`` returned
``{"success": True, "results": {"12479": raw_result}}`` and the React
agent unwrapped one level into ``traffic_data = {"12479": raw_result}``.
That dict-shaped payload then went straight to ``analyze_temporal_correlation``,
which only knew how to unwrap ``{"result": ...}`` and the bare raw result —
NOT the ASN-keyed wrapper. As a result:

  - correlation.signals.traffic_event_count was always 0 in React mode
  - correlation.signals.routing_event_count was always 0 in React mode
  - The HTML report then contradicted itself by listing 12 AS-specific
    anomalies in one paragraph and 0 traffic events in the next.

These tests assert that the analyzers now auto-unwrap the multi-AS wrapper.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _react_traffic(asn="12479", n=12):
    return {
        asn: {
            "anomalies": [
                {"timestamp": f"2024-01-03T15:{i:02d}:00", "z_score": 7.2}
                for i in range(n)
            ],
            "anomaly_count": n,
            "anomalies_detected": True,
        }
    }


def _react_routing(asn="12479", n=401):
    return {
        asn: {
            "origin_hijacking": [
                {"timestamp": "2024-01-03T14:54:29", "prefix": f"2a01:c500::{i}::/48"}
                for i in range(n)
            ],
            "leak_count": 0,
            "success": True,
        }
    }


# ---------------------------------------------------------------------------
def test_extract_traffic_events_handles_react_wrapper():
    """React mode passes ``{asn: raw_result}`` to the analyzer — it must unwrap."""
    from agents.correlation_analyzer import extract_traffic_events

    evs = extract_traffic_events(_react_traffic(n=12))
    assert len(evs) == 12, (
        f"react wrapper dropped events: got {len(evs)}, expected 12. "
        f"This is the root cause of 'correlation.signals.traffic_event_count=0' "
        f"in 170004.html."
    )


def test_extract_routing_events_handles_react_wrapper():
    """Same wrapper shape for routing events."""
    from agents.correlation_analyzer import extract_routing_events

    evs = extract_routing_events(_react_routing(n=401))
    assert len(evs) == 401, (
        f"react wrapper dropped events: got {len(evs)}, expected 401"
    )


def test_analyze_temporal_correlation_react_mode_yields_correct_signals():
    """End-to-end: analyze_temporal_correlation must produce matching counts."""
    from agents.correlation_analyzer import analyze_temporal_correlation

    corr = analyze_temporal_correlation(
        traffic_raw=_react_traffic(n=12),
        routing_result=_react_routing(n=401),
        target_as="12479",
    )
    sig = corr["correlation"]["signals"]
    assert sig["routing_event_count"] == 401
    assert sig["traffic_event_count"] == 12
    assert sig["traffic_signal_present"] is True


def test_extract_traffic_events_picks_highest_anomaly_count_for_multi_as():
    """When multiple ASNs are wrapped, pick the one with the most anomalies."""
    from agents.correlation_analyzer import extract_traffic_events

    payload = {
        "12479": {"anomalies": [{"timestamp": "2024-01-03T15:00:00"}], "anomaly_count": 1},
        "50300": {
            "anomalies": [{"timestamp": "2024-01-03T15:00:00"} for _ in range(5)],
            "anomaly_count": 5,
        },
    }
    evs = extract_traffic_events(payload)
    assert len(evs) == 5, f"should pick the AS with more events, got {len(evs)}"


def test_extract_routing_events_picks_highest_event_count_for_multi_as():
    """Same heuristic for routing events."""
    from agents.correlation_analyzer import extract_routing_events

    payload = {
        "12479": {
            "origin_hijacking": [
                {"timestamp": "2024-01-03T14:54:29", "prefix": "1.0.0.0/24"}
            ],
            "leak_count": 0,
        },
        "50300": {
            "origin_hijacking": [
                {
                    "timestamp": "2024-01-03T14:54:29",
                    "prefix": f"10.0.{i}.0/24",
                }
                for i in range(50)
            ],
            "leak_count": 0,
        },
    }
    evs = extract_routing_events(payload)
    assert len(evs) == 50


def test_workflow_mode_payload_unaffected_by_unwrap_logic():
    """The new unwrap logic must NOT break the existing workflow payload shapes."""
    from agents.correlation_analyzer import (
        extract_traffic_events,
        extract_routing_events,
    )

    # Case A: bare raw result
    traffic_raw = {
        "anomalies": [{"timestamp": "2024-01-03T15:00:00"}],
        "anomaly_count": 1,
    }
    routing_raw = {
        "origin_hijacking": [{"timestamp": "2024-01-03T14:54:29"}],
        "leak_count": 0,
    }
    assert len(extract_traffic_events(traffic_raw)) == 1
    assert len(extract_routing_events(routing_raw)) == 1

    # Case B: workflow section with nested result
    section = {"result": traffic_raw, "anomaly_count": 1}
    assert len(extract_traffic_events(section)) == 1
