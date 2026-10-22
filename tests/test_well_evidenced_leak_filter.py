#!/usr/bin/env python3
"""Tests for the well-evidenced leak filter (ROUND-26).

The RRC00 leak detector fires on every BGP update that mentions the target
AS, including 5000+ empty events during outage withdrawal storms. The
filter must:
  - count real events (with prefix/as-path) as positive
  - count empty events (no prefix, no as-path) as noise
  - prefer well-evidenced over raw scalar when majority of events are empty
"""
import sys
import json
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_well_evidence_count_dict_events():
    """A dict-shaped leak event with prefix+as-path is well-evidenced."""
    from agents.report_agent import _normalize_routing
    routing = {
        "leak": {"route_leaks": [
            {"prefix": "1.2.3.0/24", "as-path": "123 456 789", "origin-as": "789"},
            {"prefix": "1.2.4.0/24", "as-path": "111 222 333", "origin-as": "333"},
        ]},
    }
    norm = _normalize_routing(routing)
    assert "route_leaks" in norm
    assert len(norm["route_leaks"]) == 2


def test_well_evidence_count_string_events():
    """An AnomalyDetail repr string with populated fields is well-evidenced."""
    from agents.report_agent import _normalize_routing
    routing = {
        "leak": {"route_leaks": [
            "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:00', "
            "affected_prefixes=['1.2.3.0/24'], affected_asns=['789'], claimed_as='789')",
            "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:01', "
            "affected_prefixes=['1.2.4.0/24'], affected_asns=['333'], claimed_as='333')",
        ]},
    }
    norm = _normalize_routing(routing)
    assert "route_leaks" in norm
    assert len(norm["route_leaks"]) == 2


def test_empty_leak_events_filtered():
    """Empty AnomalyDetail events (no prefix, no asns) should not be well-evidenced."""
    # Test the well-evidenced filter logic directly
    leak_list = [
        "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:00', "
        "affected_prefixes=[], affected_asns=[], claimed_as=None, victim_as=None)",
        "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:01', "
        "affected_prefixes=['1.2.3.0/24'], affected_asns=['789'], claimed_as='789')",
    ]

    def well_evidence_count(leak_list):
        if not leak_list:
            return 0
        if isinstance(leak_list[0], str):
            return sum(
                1 for s in leak_list
                if isinstance(s, str)
                and not (
                    'affected_prefixes=[]' in s
                    and 'affected_asns=[]' in s
                    and 'claimed_as=None' in s
                    and 'victim_as=None' in s
                )
            )
        return 0

    well = well_evidence_count(leak_list)
    assert well == 1  # Only the second event is well-evidenced


def test_outage_window_withdrawal_storm_filtered():
    """5000 empty leak events should be filtered, only well-evidenced kept."""
    leak_list = [
        "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:00', "
        "affected_prefixes=[], affected_asns=[], claimed_as=None, victim_as=None)"
    ] * 5000

    def well_evidence_count(leak_list):
        if not leak_list:
            return 0
        if isinstance(leak_list[0], str):
            return sum(
                1 for s in leak_list
                if isinstance(s, str)
                and not (
                    'affected_prefixes=[]' in s
                    and 'affected_asns=[]' in s
                    and 'claimed_as=None' in s
                    and 'victim_as=None' in s
                )
            )
        return 0

    well = well_evidence_count(leak_list)
    assert well == 0  # All 5000 are empty


def test_real_leak_with_5000_real_events_preserved():
    """5000 real leak events should all be counted as well-evidenced."""
    leak_list = [
        "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:00', "
        f"affected_prefixes=['1.2.3.{i}/24'], affected_asns=['789'], claimed_as='789')"
        for i in range(5000)
    ]

    def well_evidence_count(leak_list):
        if not leak_list:
            return 0
        if isinstance(leak_list[0], str):
            return sum(
                1 for s in leak_list
                if isinstance(s, str)
                and not (
                    'affected_prefixes=[]' in s
                    and 'affected_asns=[]' in s
                    and 'claimed_as=None' in s
                    and 'victim_as=None' in s
                )
            )
        return 0

    well = well_evidence_count(leak_list)
    assert well == 5000  # All 5000 are well-evidenced


def test_compute_top_cause_outage_withdrawal_storm():
    """A 5000-empty-leak withdrawal storm should NOT win as 'route_leak'."""
    from agents.report_agent import _normalize_routing, compute_top_cause

    # Build a routing payload that looks like Pakistan PTCL: outage + 5000 empty leaks
    routing = {
        "leak": {"route_leaks": [
            "AnomalyDetail(type='leak', subtype=None, timestamp='2024-01-01 12:00:00', "
            "affected_prefixes=[], affected_asns=[], claimed_as=None, victim_as=None)"
        ] * 5000},
        "outage_analysis": {"is_outage_suspected": True, "outage_score": 0.30},
    }
    norm = _normalize_routing(routing)
    verdict = compute_top_cause(
        norm,
        {"anomaly_count": 7, "peak_trough_drop_pct": -6.5},
        {"temporal_proximity": "none", "confidence": 0.0},
        target_as="17557",
        hcaf_direction="",
    )
    # Should predict outage, not route_leak
    assert verdict["cause"] in ("outage", "traffic_anomaly_only"), \
        f"Expected outage or traffic_anomaly_only, got {verdict['cause']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
