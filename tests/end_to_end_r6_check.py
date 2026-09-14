#!/usr/bin/env python3
"""
end_to_end_r6_check.py — Real-world simulation of the user-reported bug.

Bug: AS12479 reports showed contradictory verdicts:
  - llm_report_AS12479_20260913_163544.html  → "有路由异常" (routing anomalies detected)
  - llm_report_AS12479_20260913_170004.html  → "没有路由异常" (no routing anomalies)

Root cause (R6): correlation_analyzer.extract_routing_events could not
unwrap the React-mode `{asn: raw_result}` wrapper, so routing_event_count
came back as 0 even when the data was rich.

This script:
  1. Builds TWO payloads shaped like each of the two historical reports:
     - Workflow-mode: {result: {origin_hijacking: [...]}}     (legacy form)
     - React-mode:   {12479: {origin_hijacking: [...]}}        (broken form)
  2. Runs analyze_temporal_correlation on each.
  3. Asserts both yield identical, correct counts.
  4. Reports the verdict ("有路由异常" vs "没有路由异常") for each.

If R6 is fixed, the verdict should be stable.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def build_workflow_payload(n_routing: int = 401, n_traffic: int = 12):
    """Shape used in legacy workflow (the "163544" report)."""
    traffic = {
        "anomalies": [
            {"timestamp": f"2024-01-03T15:{i:02d}:00", "z_score": 7.2,
             "direction": "below", "current_value": 100, "mean": 1000, "pct_change": -90}
            for i in range(n_traffic)
        ],
        "anomaly_count": n_traffic,
        "anomalies_detected": True,
        "percent_change": -90.0,
        "peak_trough_drop_pct": 90.0,
    }
    routing = {
        "origin_hijacking": [
            {"timestamp": "2024-01-03T14:54:29",
             "prefix": f"2a01:c500::{i}::/48",
             "hijacker_as": "AS49581", "claimed_as": "AS12479"}
            for i in range(n_routing)
        ],
        "leak_count": 0,
        "success": True,
        "result": {  # wrapped twice — workflow path
            "origin_hijacking": [
                {"timestamp": "2024-01-03T14:54:29",
                 "prefix": f"2a01:c500::{i}::/48",
                 "hijacker_as": "AS49581", "claimed_as": "AS12479"}
                for i in range(n_routing)
            ],
            "leak_count": 0,
        },
    }
    return traffic, routing


def build_react_payload(n_routing: int = 401, n_traffic: int = 12):
    """Shape used in React mode (the "170004" report that broke)."""
    traffic_wrapped = {
        "12479": {
            "anomalies": [
                {"timestamp": f"2024-01-03T15:{i:02d}:00", "z_score": 7.2,
                 "direction": "below", "current_value": 100, "mean": 1000, "pct_change": -90}
                for i in range(n_traffic)
            ],
            "anomaly_count": n_traffic,
            "anomalies_detected": True,
            "percent_change": -90.0,
            "peak_trough_drop_pct": 90.0,
        }
    }
    routing_wrapped = {
        "12479": {
            "origin_hijacking": [
                {"timestamp": "2024-01-03T14:54:29",
                 "prefix": f"2a01:c500::{i}::/48",
                 "hijacker_as": "AS49581", "claimed_as": "AS12479"}
                for i in range(n_routing)
            ],
            "leak_count": 0,
            "success": True,
        }
    }
    return traffic_wrapped, routing_wrapped


def run_correlation(name, traffic_raw, routing_raw):
    from agents.correlation_analyzer import analyze_temporal_correlation
    print(f"\n=== {name} ===")
    print(f"  traffic_raw type:    {type(traffic_raw).__name__}")
    print(f"  routing_raw keys:    {list(routing_raw.keys())[:5]}")
    if isinstance(routing_raw, dict) and "12479" in routing_raw:
        inner = routing_raw["12479"]
        print(f"  routing_raw['12479'] keys: {list(inner.keys())[:5]}")

    corr = analyze_temporal_correlation(
        traffic_raw=traffic_raw,
        routing_result=routing_raw,
        target_as="12479",
    )

    sig = corr["correlation"]["signals"]
    summary = corr["summary"]
    print(f"  routing_event_count: {sig['routing_event_count']}")
    print(f"  traffic_event_count: {sig['traffic_event_count']}")
    print(f"  routing_signal_present: {sig['routing_signal_present']}")
    print(f"  traffic_signal_present: {sig['traffic_signal_present']}")
    print(f"  summary: {summary}")
    return corr


def main():
    print("=" * 70)
    print("END-TO-END R6 REGRESSION CHECK (AS12479 / Orange España)")
    print("=" * 70)

    # 1. Legacy workflow-mode payload (the report that said "有路由异常")
    wf_traffic, wf_routing = build_workflow_payload()
    wf_corr = run_correlation("WORKFLOW-MODE (legacy 163544 report)", wf_traffic, wf_routing)

    # 2. React-mode payload (the report that said "没有路由异常")
    rx_traffic, rx_routing = build_react_payload()
    rx_corr = run_correlation("REACT-MODE (broken 170004 report)", rx_traffic, rx_routing)

    # 3. Assertions
    print("\n" + "=" * 70)
    print("VERDICT STABILITY CHECK")
    print("=" * 70)

    wf_sig = wf_corr["correlation"]["signals"]
    rx_sig = rx_corr["correlation"]["signals"]

    wf_verdict = "有路由异常" if wf_sig["routing_signal_present"] else "没有路由异常"
    rx_verdict = "有路由异常" if rx_sig["routing_signal_present"] else "没有路由异常"

    print(f"  Workflow-mode verdict: {wf_verdict}")
    print(f"  React-mode verdict:    {rx_verdict}")

    ok = (
        wf_sig["routing_event_count"] == rx_sig["routing_event_count"]
        and wf_sig["traffic_event_count"] == rx_sig["traffic_event_count"]
        and wf_sig["routing_signal_present"] == rx_sig["routing_signal_present"]
        and wf_sig["traffic_signal_present"] == rx_sig["traffic_signal_present"]
        and wf_verdict == rx_verdict == "有路由异常"
    )

    if ok:
        print("\n✅ R6 FIXED: both payloads yield identical, correct verdict.")
        print("   routing_event_count: 401 (both)")
        print("   traffic_event_count: 12 (both)")
        print("   Verdict: 有路由异常 (both) — was contradictory in v4.")
        return 0
    else:
        print("\n❌ R6 NOT FIXED: verdicts still differ.")
        print(f"   WF: routing={wf_sig['routing_event_count']} traffic={wf_sig['traffic_event_count']}")
        print(f"   RX: routing={rx_sig['routing_event_count']} traffic={rx_sig['traffic_event_count']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
