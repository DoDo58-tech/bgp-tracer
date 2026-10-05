"""Regression tests for the leak-signal loss and count corruption (BUG-R141).

The batch evaluation against the v4 ground-truth dataset showed every
route-leak event (Cox AS22773, Voxility AS3223, ReliableSite AS23470,
Uztelecom AS28910) reported as "Traffic anomaly, routing quiet" with
route-leak=0 — even though running the leak detector directly over the same
window found 5000 / 5000 / 48 / 5000 leaks respectively.

Three independent defects, one per test below.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.payload_builder import _ROUTING_KEEP, slim_section  # noqa: E402
from agents.report_agent import _normalize_routing, compute_top_cause  # noqa: E402


def _live_routing_payload(leak_n: int = 5000) -> dict:
    """The exact shape routing_impl.run_routing_agent_async() returns."""
    leaks = [{"prefix": f"2.0.{i // 256}.{i % 256}.0/24"} for i in range(leak_n)]
    return {
        "success": True,
        "asn": "22773",
        "origin_hijacked": [],
        "forge_hijacked": [],
        "origin_hijacking": [],
        "forge_hijacking": [],
        "mitm_alerts": [],
        "leak_analysis": {
            "success": True,
            "route_leaks": leaks,
            "leak_count": leak_n,
        },
        "route_leaks": leaks,
        "leak_count": leak_n,
        "outage_analysis": {"is_outage_suspected": False, "outage_score": 0.0},
        "outage_suspected": False,
        "outage_score": 0.0,
        "total_prefix_hijacks": 0,
    }


def test_payload_allowlist_keeps_leak_and_outage_blocks():
    """The live payload nests leaks under ``leak_analysis`` and outage under
    ``outage_analysis``; neither key was allow-listed, so both were stripped
    before rendering."""
    for key in ("leak_analysis", "outage_analysis", "leak_count", "outage_score"):
        assert key in _ROUTING_KEEP, f"{key!r} missing from _ROUTING_KEEP"

    slim = slim_section("routing", _live_routing_payload())
    assert "leak_analysis" in slim, "leak_analysis stripped by slim_section"
    assert "leak_count" in slim, "leak_count stripped by slim_section"
    assert "outage_analysis" in slim, "outage_analysis stripped by slim_section"


def test_truncated_leak_list_does_not_shrink_the_count():
    """The LLM payload path truncates event lists to fit the token budget, so
    len(route_leaks) became 40 while the detector had recorded 5000. The
    classifier ranks on this number, so the truncation changed verdicts."""
    payload = _live_routing_payload(leak_n=5000)
    slim = slim_section("routing", payload)

    assert len(slim["route_leaks"]) < 5000, "expected the list to be truncated"

    norm = _normalize_routing(slim)
    assert norm["leak_count"] == 5000, (
        f"authoritative leak count lost: got {norm['leak_count']}"
    )

    top = compute_top_cause(
        norm,
        {"anomaly_count": 265, "peak_trough_drop_pct": 15.0, "percent_change": 0.0},
        {"temporal_proximity": "none", "confidence": 0.0, "delta_ts": []},
        target_as="22773",
    )
    assert top["cause"] == "route_leak", (
        f"truncated leak list flipped the verdict to {top['cause']}"
    )


def test_leak_only_event_is_not_treated_as_routing_quiet():
    """An event whose only routing signal is a leak must not fall through to
    the 'Traffic anomaly, routing quiet' branch."""
    norm = _normalize_routing({"result": _live_routing_payload(leak_n=5000)})
    top = compute_top_cause(
        norm,
        {"anomaly_count": 265, "peak_trough_drop_pct": 15.0, "percent_change": 0.0},
        {"temporal_proximity": "none", "confidence": 0.0, "delta_ts": []},
        target_as="22773",
    )
    assert top["cause"] != "traffic_anomaly_only", (
        "a 5000-event leak was reported as 'routing quiet'"
    )
    assert top["cause"] == "route_leak"


def test_percent_change_does_not_explode_on_tiny_baseline():
    """AS22773 rendered '+266727751609.52%' because the historical baseline was
    near zero. A ratio against such a baseline carries no information."""
    from detectors.traffic.clustering import calculate_traffic_statistics

    stats = calculate_traffic_statistics(
        current_values=[1_974_111_685.19],
        historical_means=[0.00000074],
    )
    pct = stats["percent_change"]
    assert abs(pct) <= 1000.0, f"percent_change exploded to {pct}"
    assert pct == 0.0, f"near-zero baseline should yield 0.0, got {pct}"


def test_percent_change_still_works_on_normal_baseline():
    """The near-zero guard must not break ordinary traffic drops."""
    from detectors.traffic.clustering import calculate_traffic_statistics

    stats = calculate_traffic_statistics(
        current_values=[50.0, 52.0],
        historical_means=[100.0, 100.0],
    )
    assert abs(stats["percent_change"] - -49.0) < 1e-6, (
        f"expected ~-49%, got {stats['percent_change']}"
    )
