"""The cause-axis arbitration must not be decided by the agent's confidence.

These tests pin the behaviour that the measured failure motivated.  The
agent's stated confidence was measured to be uncalibrated on the
corpus, so the cause axis is gated on corroboration instead, and the
tests exist so that a later change cannot silently restore a
confidence-based gate.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detectors.evidence_chain_builder import (  # noqa: E402
    EvidenceChainBuilder,
    TRAFFIC_DROP_THRESHOLD_PCT,
)


def build_cross_origin_record(victim: str, origin: str):
    return {
        "origin_as": origin,
        "legitimate_origins": [victim],
    }


def routing_with(records: list[dict], **extra):
    payload = {
        "target_asn": "64500",
        "origin_hijacked": records,
        "route_leaks": [],
        "outage_analysis": {
            "event_features": {
                "announcement_count": 1000,
                "withdrawal_count": 0,
            }
        },
    }
    payload.update(extra)
    return payload


def traffic_with(available: bool, drop: float = 0.0, anomalies: int = 0):
    return {
        "data_available": available,
        "success": available,
        "peak_trough_drop_pct": drop,
        "anomaly_count": anomalies,
        "traffic_signal_present": anomalies > 0,
        "outage_period_anomaly_count": anomalies,
    }


@pytest.fixture
def builder():
    return EvidenceChainBuilder()


def test_agent_confidence_alone_does_not_override(builder):
    """A confident agent proposal without corroboration does not win.

    The rule's own default answer for a window with no traffic
    anomaly and no hijack record is the hijack label, so the returned
    cause would coincide with the agent's proposal.  The invariant is
    that the proposal was not *accepted* on its confidence: the
    corroboration predicate must be false, and the proposal must not
    reach the arbitration at all.
    """
    routing = routing_with([])
    proposal = {
        "cause": "route_leak",
        "confidence": 0.99,
    }
    assert not builder.agent_proposal_is_corroborated(
        "route_leak", routing
    )
    assert not builder.agent_may_break_an_unobservable_tie(
        "route_leak", traffic_with(True, 0.0, 0), routing
    )
    cause = builder.determine_cause(
        traffic_with(True, 0.0, 0), routing, proposal, "routing_only_anomaly"
    )
    assert cause != "route_leak"


def test_corroborated_hijack_proposal_overrides(builder):
    """A hijack proposal backed by a cross-origin record does win."""
    routing = routing_with([
        build_cross_origin_record("64500", "64501"),
    ])
    proposal = {
        "cause": "origin_hijack_victim",
        "confidence": 0.99,
    }
    cause = builder.determine_cause(
        traffic_with(True, 0.0, 0), routing, proposal, "routing_only_anomaly"
    )
    assert cause == "origin_hijack_victim"


def test_self_flagged_record_is_not_corroboration(builder):
    """A record naming the victim itself is a detector artefact.

    It does not count as corroboration.  The rule may still reach the
    same label by its own default, so the invariant is on the
    corroboration count rather than on the returned cause.
    """
    routing = routing_with([
        {"origin_as": "64500", "legitimate_origins": ["64500"]},
    ])
    assert builder.count_cross_origin_records(routing) == 0
    assert not builder.agent_proposal_is_corroborated(
        "origin_hijack_victim", routing
    )


def test_count_cross_origin_records(builder):
    routing = routing_with([
        build_cross_origin_record("64500", "64501"),
        build_cross_origin_record("64500", "64502"),
        {"origin_as": "64500", "legitimate_origins": ["64500"]},
        "not-a-dict",
    ])
    assert builder.count_cross_origin_records(routing) == 2


def test_agent_decides_when_traffic_observed_nothing(builder):
    """With no traffic data the physical layer cannot separate classes."""
    routing = routing_with([])
    proposal = {"cause": "route_leak", "confidence": 0.8}
    cause = builder.determine_cause(
        traffic_with(False), routing, proposal, "inconclusive_missing_traffic"
    )
    assert cause == "route_leak"


def test_agent_does_not_overturn_a_measured_traffic_reading(builder):
    """With traffic data present the measured reading stands."""
    routing = routing_with([])
    proposal = {"cause": "route_leak", "confidence": 0.95}
    cause = builder.determine_cause(
        traffic_with(True, 10.0, 1), routing, proposal, "routing_only_anomaly"
    )
    assert cause != "route_leak"


def test_hard_physical_signature_still_vetoes(builder):
    """The physical veto is unaffected by the arbitration change."""
    routing = routing_with([])
    proposal = {
        "cause": "origin_hijack_victim",
        "confidence": 0.99,
    }
    cause = builder.determine_cause(
        traffic_with(True, TRAFFIC_DROP_THRESHOLD_PCT + 10.0, 3),
        routing,
        proposal,
        "routing_only_anomaly",
    )
    assert cause == "outage"
