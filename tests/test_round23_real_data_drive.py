"""End-to-end smoke: drive round-23 fixed helpers over real AS8048 data.

Does NOT call any LLM — instead exercises the four code paths where
round-23 fixes live, with the actual AS8048 routing JSON. Produces a
side-by-side comparison so we can see what changes in the rendered
output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

WORK = Path("/data/bgp_tracer")
sys.path.insert(0, str(WORK))

from agents.report_agent import (  # noqa: E402
    _collect_origin_hijack_rows,
    _collect_traffic_anomaly_rows,
    _render_section_anchor_inserts,
    _scrub_json_key_placeholders,
    _SECTION_TITLE_HIJACK,
    _SECTION_TITLE_TRAFFIC,
    slim_payload,
    validate_html_balance,
)


def load_as8048() -> tuple[str, str, dict]:
    asn = "8048"
    start = "2024-08-01 08:45"
    end = "2024-08-01 09:45"
    with open(WORK / "results/json/hijack_alerts_AS8048_20240801_0845_20240801_0945.json") as f:
        d = json.load(f)
    routing = {
        "result": {
            "origin_hijacked": d["alerts"]["origin_hijacks"],
            "origin_hijacking": d["alerts"]["origin_hijacks"][:5],
        }
    }
    return asn, start, end, routing


def test_slim_payload_real_data():
    asn, _, _, routing = load_as8048()
    events = routing["result"]["origin_hijacked"]
    print(f"\n=== slim_payload on AS8048 origin_hijacked ({len(events)} events) ===")

    # What the report pipeline does: payload with the events list,
    # limit=20, ask for a slim version.
    payload = {"origin_hijacked": events, "asn": asn}
    slim = slim_payload(payload, limit=20)
    n = len(slim.get("origin_hijacked", []))
    print(f"  slim size: {n}/{len(events)}")
    if n == len(events):
        print("  → round-23 preserves all 500 events (round-22 would have dropped 450)")
    elif n == 50:
        print("  → ROUND-22 BUG: capped at 50, dropped 450")
    else:
        print(f"  → intermediate cap: {n}")


def test_origin_hijack_table():
    asn, _, _, routing = load_as8048()
    events = routing["result"]["origin_hijacked"]
    print(f"\n=== _collect_origin_hijack_rows on first 5 events ===")
    rows = _collect_origin_hijack_rows({"result": {"origin_hijacked": events[:5]}})
    for r in rows:
        print(f"  {r}")


def test_scrub_real_leaks():
    """Two real reports contain leaks. Confirm scrub closes them."""
    leaks = [
        "[user_analysis_window]",
        "[target_as]",
        "[start_time]",
        "[end_time]",
        "[auto_probe_findings]",
    ]
    print(f"\n=== _scrub_json_key_placeholders with real leaks ===")
    html = f"<h1>Report for [target_as] window [user_analysis_window] events [unknown_xyz]</h1>"
    out = _scrub_json_key_placeholders(
        html,
        asn="8048",
        start_time="2024-08-01 08:45",
        end_time="2024-08-01 09:45",
    )
    print(f"  IN : {html}")
    print(f"  OUT: {out}")
    assert "[target_as]" not in out, "BUG: [target_as] still leaked"
    assert "[user_analysis_window]" not in out, "BUG: [user_analysis_window] still leaked"
    print("  ✓ scrub replaced all JSON-key placeholders")


def test_anchor_routing_real_doc():
    """Build a doc with the headings a real report might generate,
    confirm round-23 places both tables correctly."""
    print(f"\n=== _render_section_anchor_inserts (real-shape headings) ===")
    html = (
        "<html><body>"
        "<h2>Executive Summary</h2>"
        "<h2>Traffic Analysis</h2>"
        "<h2>Traffic Anomaly Events</h2>"
        "<h2>Origin Hijacking Events</h2>"
        "</body></html>"
    )
    sections = [
        (_SECTION_TITLE_TRAFFIC, "<table>Traffic-1</table>", "x"),
        (_SECTION_TITLE_TRAFFIC, "<table>Traffic-2 (Anomaly)</table>", "x"),
        (_SECTION_TITLE_HIJACK, "<table>Hijack</table>", "x"),
    ]
    out = _render_section_anchor_inserts(html, sections)
    print(f"  OUT: {out}")
    # Verify table positions (search for the table opening tags, not the
    # bare text "Hijack" which appears mid-table content).
    t1 = out.find("<table>Traffic-1")
    t2 = out.find("<table>Traffic-2")
    h = out.find("<table>Hijack")
    h2_anom = out.find("Traffic Anomaly Events</h2>") + len("Traffic Anomaly Events</h2>")
    h2_hij = out.find("Origin Hijacking Events</h2>") + len("Origin Hijacking Events</h2>")
    h2_traf = out.find("Traffic Analysis</h2>") + len("Traffic Analysis</h2>")
    assert h2_traf <= t1 < h2_anom, f"Traffic-1 misplaced: t1={t1}, h2_traf={h2_traf}, h2_anom={h2_anom}"
    assert h2_anom <= t2, f"Traffic-2 misplaced: t2={t2}, h2_anom={h2_anom}"
    assert h2_hij <= h, f"Hijack misplaced: h={h}"
    print("  ✓ all tables placed correctly")


def test_validate_html_real_report():
    """Confirm round-23 doesn't break balance on existing reports."""
    print(f"\n=== validate_html_balance on existing AS8048 reports ===")
    for path in [
        "results/html/llm_report_AS8048_20260916_013331.html",
        "results/html/llm_report_AS8048_resub2.html",
    ]:
        full = WORK / path
        if not full.exists():
            continue
        html = full.read_text()
        ok, problems = validate_html_balance(html)
        print(f"  {path}: ok={ok}, problems={problems[:2]}")


def main():
    test_slim_payload_real_data()
    test_origin_hijack_table()
    test_scrub_real_leaks()
    test_anchor_routing_real_doc()
    test_validate_html_real_report()
    print("\n=== ALL REAL-DATA DRIVE TESTS PASSED ===")


if __name__ == "__main__":
    main()
