"""Tests for BUG-R143 / BUG-R144 / BUG-R145 (3 detector gaps exposed by
the v9 audit, 2026-09-29).

Each test exercises the synthetic case that exposes the bug, then
asserts the post-fix behaviour. Tests are isolated: no network, no
filesystem, no LLM, no RRC00 data.

Fix summary:
    BUG-R143  route_leak null-filter
              correlation_analyzer used to emit one TemporalEvent per
              ``route_leaks`` row, including records where both
              ``prefix`` and ``leaked_by`` are null. Detector batches
              return ~3000 of these noise rows on events without RRC00
              evidence, inflating ``leak_n`` past the hijack signal and
              flipping ``compute_top_cause`` to the wrong verdict.

    BUG-R144  DPI-level outage fallback in compute_top_cause
              Iran's June 2025 stealth blackout killed BGP at the
              national border via DPI / filternet nodes — no BGP
              withdrawals, but a -90% traffic drop. ``outage_suspected``
              was False and ``outage_score`` was 0.0, so the outage
              branch never fired. The new heuristic treats
              ``traffic_anomaly >= 30 + outage_score < 0.1 + no
              hijack dominance`` as a DPI-style outage.

    BUG-R145  no_radar_data verdict
              Myanmar AS134840 (MCCL) has no Cloudflare Radar
              timeseries. TrafficAgent returns ``data_points=0``,
              ``data_available=False``, but ``anomaly_count=12``
              (fabricated from a None baseline_avg). Without this guard
              the verdict falls through to ``silent_alert``, blaming
              the routing signal instead of flagging the radar gap.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))


pytestmark = pytest.mark.fast


# ─── BUG-R143: route_leak null-filter ──────────────────────────────────


def test_bug_r143_drops_null_leak_records():
    """``extract_routing_events`` must drop records where both
    ``prefix`` and ``leaked_by`` are null."""
    from agents.correlation_analyzer import extract_routing_events

    real_ts = "2024-01-03T15:00:00"
    routing_result = {
        "route_leaks": [
            # 2 real leaks
            {"timestamp": real_ts, "prefix": "10.0.0.0/24", "leaked_by": "AS65000"},
            {"timestamp": real_ts, "prefix": "192.168.0.0/16", "leaked_by": None},
            # 5 noise records (the bug)
            {"timestamp": real_ts, "prefix": None, "leaked_by": None},
            {"timestamp": real_ts, "prefix": None, "leaked_by": None},
            {"timestamp": real_ts, "prefix": None, "leaked_by": None},
            {"timestamp": real_ts, "prefix": None, "leaked_by": None},
            {"timestamp": real_ts, "prefix": None, "leaked_by": None},
        ],
        "analysis_period": "2024-01-03 14:45 to 2024-01-03 18:00",
    }
    events = extract_routing_events(routing_result, "12479")

    leak_events = [e for e in events if e.event_type == "route_leak"]
    assert len(leak_events) == 2, (
        f"Expected 2 real leaks (others are noise), got {len(leak_events)}. "
        f"BUG-R143 regression: null-filter is missing."
    )
    # Verify all kept events have at least one populated field
    for e in leak_events:
        d = e.details
        assert d.get("prefix") is not None or d.get("leaked_by") is not None, (
            f"Event {e} has both null fields — filter regressed."
        )


def test_bug_r143_drops_null_leak_records_in_annotation_package():
    """Same null-filter must apply to ``routing_result.leak.route_leaks``
    (the annotation_package nested format)."""
    from agents.correlation_analyzer import extract_routing_events

    real_ts = "2024-01-03T15:00:00"
    routing_result = {
        "leak": {
            "route_leaks": [
                {"timestamp": real_ts, "prefix": "10.0.0.0/24", "leaked_by": "AS65000"},
                {"timestamp": real_ts, "prefix": None, "leaked_by": None},
                {"timestamp": real_ts, "prefix": None, "leaked_by": None},
            ],
        },
        "analysis_period": "2024-01-03 14:45 to 2024-01-03 18:00",
    }
    events = extract_routing_events(routing_result, "12479")

    leak_events = [e for e in events if e.event_type == "route_leak"]
    assert len(leak_events) == 1, (
        f"Expected 1 real leak (annotation_package), got {len(leak_events)}"
    )


def test_bug_r143_drops_null_leak_records_in_alerts_format():
    """Same null-filter must apply to ``routing_result.alerts.route_leaks``
    (the alerts-bucket format)."""
    from agents.correlation_analyzer import extract_routing_events

    real_ts = "2024-01-03T15:00:00"
    routing_result = {
        "alerts": {
            "route_leaks": [
                {"timestamp": real_ts, "prefix": "10.0.0.0/24", "leaked_by": "AS65000"},
                {"timestamp": real_ts, "prefix": "172.16.0.0/12", "leaked_by": "AS65001"},
                {"timestamp": real_ts, "prefix": None, "leaked_by": None},
            ],
        },
        "analysis_period": "2024-01-03 14:45 to 2024-01-03 18:00",
    }
    events = extract_routing_events(routing_result, "12479")

    leak_events = [e for e in events if e.event_type == "route_leak"]
    assert len(leak_events) == 2, (
        f"Expected 2 real leaks (alerts format), got {len(leak_events)}"
    )


# ─── BUG-R144: DPI-level outage fallback in compute_top_cause ─────────


def test_bug_r144_dpi_outage_heuristic():
    """``compute_top_cause`` must include the outage candidate when
    ``traffic_anomaly >= 30`` AND ``outage_score < 0.1`` AND
    ``not strong_hijack_signal`` (Iran June 2025 signature)."""
    from agents.report_agent import compute_top_cause

    # Simulate the Iran 2025 case: lots of traffic anomalies, no BGP signal.
    routing_norm = {
        "hijack_count": 0,
        "hijacking_count": 0,
        "forge_hijacked": [],
        "forge_hijacking": [],
        "leak_count": 0,
        "route_leaks": [],
        "origin_hijacked": [],
        "origin_hijacking": [],
        "outage_score": 0.0,
        "outage_suspected": False,
    }
    traffic_norm = {
        "anomaly_count": 35,
        "peak_trough_drop_pct": -90.0,
    }
    correlation_norm = {
        "temporal_proximity": "high",
        "confidence": 0.7,
    }
    result = compute_top_cause(routing_norm, traffic_norm, correlation_norm,
                                target_as="44244")

    causes = [c["cause"] for c in result.get("ranked", [])]
    assert "outage" in causes, (
        f"DPI-outage signature missed by compute_top_cause. "
        f"ranked={causes}. BUG-R144 regression."
    )
    # outage confidence should beat traffic_anomaly_only (which is 0.45)
    outage_conf = next(c["confidence"] for c in result.get("ranked", []) if c["cause"] == "outage")
    assert outage_conf >= 0.60, (
        f"DPI-outage confidence too low: {outage_conf} (expected >= 0.60)"
    )


def test_bug_r144_no_false_positive_on_strong_hijack():
    """The DPI-outage fallback must NOT fire when hijacks dominate
    (e.g. Orange-style hijack with concurrent traffic drop — the
    drop is a symptom of the hijack, not a separate outage)."""
    from agents.report_agent import compute_top_cause

    routing_norm = {
        "hijack_count": 100,
        "hijacking_count": 100,  # symmetric — typical of an RPKI gap / Orange
        "forge_hijacked": [],
        "forge_hijacking": [],
        "leak_count": 0,
        "route_leaks": [],
        "origin_hijacked": [{"x": 1}] * 100,
        "origin_hijacking": [{"x": 1}] * 100,
        "outage_score": 0.05,
        "outage_suspected": False,
    }
    traffic_norm = {
        "anomaly_count": 35,
        "peak_trough_drop_pct": -50.0,
    }
    correlation_norm = {
        "temporal_proximity": "high",
        "confidence": 0.7,
    }
    result = compute_top_cause(routing_norm, traffic_norm, correlation_norm,
                                target_as="12479")
    top_cause = result.get("cause")
    # Strong hijack signal → outage should not be the top cause.
    assert top_cause != "outage", (
        f"DPI-outage fallback wrongly fired on a strong-hijack event. "
        f"top_cause={top_cause}. BUG-R144 false-positive regression."
    )


def test_bug_r144_no_false_positive_when_outage_score_high():
    """If the real outage detector already fired, the DPI fallback is
    irrelevant — the existing branch handles it."""
    from agents.report_agent import compute_top_cause

    routing_norm = {
        "hijack_count": 0,
        "hijacking_count": 0,
        "forge_hijacked": [],
        "forge_hijacking": [],
        "leak_count": 0,
        "route_leaks": [],
        "origin_hijacked": [],
        "origin_hijacking": [],
        "outage_score": 0.85,  # strong outage detector signal
        "outage_suspected": True,
    }
    traffic_norm = {
        "anomaly_count": 35,
        "peak_trough_drop_pct": -70.0,
    }
    correlation_norm = {
        "temporal_proximity": "high",
        "confidence": 0.8,
    }
    result = compute_top_cause(routing_norm, traffic_norm, correlation_norm,
                                target_as="52863")
    top_cause = result.get("cause")
    assert top_cause == "outage"
    # Existing branch gives higher confidence than DPI fallback
    assert result.get("confidence", 0) >= 0.85, (
        f"Strong outage should score >=0.85, got {result.get('confidence')}"
    )


# ─── BUG-R145: no_radar_data verdict ──────────────────────────────────


def test_bug_r145_no_radar_data_when_data_points_zero():
    """When TrafficAgent returns ``data_points=0`` (Radar has no
    timeseries), the quick verdict must be ``no_radar_data``, not
    ``silent_alert`` (the latter would falsely attribute the event
    to a routing-only signal)."""
    from chief_agent import build_quick_summary

    traffic = {
        "result": {
            "data_points": 0,
            "data_available": False,
            "anomaly_count": 12,  # fabricated by detector from None baseline
            "no_data_reason": "cloudflare_no_points",
        },
    }
    routing = {
        "result": {
            "hijack": {"origin_hijacked": [{"x": 1}], "forge_hijacked": []},
            "leak": {"route_leaks": []},
            "outage": {"score": 0.0},
        },
    }
    correlation = {
        "result": {
            "correlation": {"signals": {"temporal_proximity": "none"}},
            "summary": {"correlation_level": "none"},
            "strength": 0.0,
        },
    }
    out = build_quick_summary(traffic, routing, correlation)
    assert out.get("quick_verdict") == "no_radar_data", (
        f"BUG-R145 regression: expected 'no_radar_data', got "
        f"{out.get('quick_verdict')!r}. "
        f"Falling back to 'silent_alert' would falsely blame the "
        f"routing signal for an outage Radar can't see."
    )


def test_bug_r145_no_radar_data_overrides_real_incident():
    """When Radar has no data and routing has strong alerts,
    the verdict must still be ``no_radar_data`` (not
    ``real_incident``). The reviewer must be told the truth:
    no traffic signal was actually observed."""
    from chief_agent import build_quick_summary

    traffic = {
        "result": {
            "data_points": 0,
            "data_available": False,
            "anomaly_count": 0,
        },
    }
    routing = {
        "result": {
            "hijack": {"origin_hijacked": [{"x": 1}] * 50, "forge_hijacked": []},
            "leak": {"route_leaks": [{"x": 1}] * 100},
            "outage": {"score": 0.0},
        },
    }
    correlation = {
        "result": {
            "correlation": {"signals": {"temporal_proximity": "high"}},
            "summary": {"correlation_level": "high"},
            "strength": 0.7,
        },
    }
    out = build_quick_summary(traffic, routing, correlation)
    assert out.get("quick_verdict") == "no_radar_data", (
        f"Expected 'no_radar_data' even with strong routing signal, "
        f"got {out.get('quick_verdict')!r}"
    )


def test_bug_r145_data_available_keeps_real_verdicts():
    """Sanity: when Radar returns data, the verdict logic must be
    unchanged. ``real_incident`` for a fully-confirmed hijack."""
    from chief_agent import build_quick_summary

    traffic = {
        "result": {
            "data_points": 24,
            "data_available": True,
            "anomaly_count": 12,
        },
    }
    routing = {
        "result": {
            "hijack": {"origin_hijacked": [{"x": 1}] * 50, "forge_hijacked": []},
            "leak": {"route_leaks": []},
            "outage": {"score": 0.0},
        },
    }
    correlation = {
        "result": {
            "correlation": {"signals": {"temporal_proximity": "high"}},
            "summary": {"correlation_level": "high"},
            "strength": 0.7,
        },
    }
    out = build_quick_summary(traffic, routing, correlation)
    assert out.get("quick_verdict") == "real_incident", (
        f"Real-incident path regressed: got {out.get('quick_verdict')!r}"
    )