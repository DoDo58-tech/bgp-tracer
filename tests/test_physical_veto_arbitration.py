"""The physical veto must fire only on an unambiguous signature.

The agent's cause proposal is arbitrated against the deterministic tree.
An agent proposal is accepted when an independent physical record
supports it, or when the physical layer observed nothing and therefore
cannot separate the classes; otherwise the measured reading stands.
The physical veto sits above both: where the physical layer states a
cause unambiguously, it wins regardless of what the agent proposed.

These tests pin that behaviour so the veto cannot silently widen into
"the agent is never allowed to disagree with the rules" — which would
make the agent layer decorative — and so the arbitration cannot silently
revert to gating on the agent's own confidence, which was measured to be
uncalibrated on the corpus.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402


def traffic(**kw):
    base = {"data_available": True, "anomaly_count": 0}
    base.update(kw)
    return base


def routing(**kw):
    base = {"leak_count": 0}
    base.update(kw)
    return base


@pytest.fixture()
def builder() -> EvidenceChainBuilder:
    return EvidenceChainBuilder()


class TestHardPhysicalSignature:
    def test_window_spanning_collapse_is_an_outage(
        self, builder: EvidenceChainBuilder
    ):
        cause = builder.hard_physical_signature(
            traffic(anomaly_count=12, peak_trough_drop_pct=81.0,
                    outage_period_anomaly_count=3),
            routing(),
        )
        assert cause == "outage"

    def test_collapse_without_window_span_is_ambiguous(
        self, builder: EvidenceChainBuilder
    ):
        """A concentrated drop is what a hijack looks like, not an outage."""
        cause = builder.hard_physical_signature(
            traffic(anomaly_count=5, peak_trough_drop_pct=81.0,
                    outage_period_anomaly_count=0),
            routing(),
        )
        assert cause == ""

    def test_withdrawal_alone_is_not_a_veto(
        self, builder: EvidenceChainBuilder
    ):
        """Labelled leaks and hijacks also carry high withdrawal ratios."""
        cause = builder.hard_physical_signature(
            traffic(data_available=False, anomaly_count=0),
            routing(
                outage_analysis={
                    "event_features": {
                        "withdrawal_count": 31408,
                        "announcement_count": 137785,
                    }
                }
            ),
        )
        assert cause == ""

    def test_no_traffic_at_all_is_ambiguous(
        self, builder: EvidenceChainBuilder
    ):
        cause = builder.hard_physical_signature(
            traffic(data_available=False), routing()
        )
        assert cause == ""


class TestAgentArbitration:
    def test_agent_may_decide_when_physical_layer_is_ambiguous(
        self, builder: EvidenceChainBuilder
    ):
        """The veto must not silence the agent where rules are unsure.

        The physical layer is ambiguous here: traffic was observed, but
        the drop does not span the outage window, so the veto does not
        fire and the tree has no reachability signature to offer.  The
        agent is arbitrated on the record rather than on its confidence;
        with no traffic data at all, its contextual reading is what
        decides.
        """
        cause = builder.determine_cause(
            traffic(anomaly_count=0, data_available=False),
            routing(leak_count=0),
            {"cause": "route_leak", "confidence": 0.82},
            "real_incident",
        )
        assert cause == "route_leak"

    def test_agent_confidence_alone_does_not_decide(
        self, builder: EvidenceChainBuilder
    ):
        """A confident proposal over a measured reading does not win.

        Traffic was observed, so the physical layer is not blind and its
        reading stands; the agent's stated confidence is not what
        decides the cause.
        """
        cause = builder.determine_cause(
            traffic(anomaly_count=5, peak_trough_drop_pct=60.0,
                    outage_period_anomaly_count=0),
            routing(leak_count=0),
            {"cause": "route_leak", "confidence": 0.82},
            "real_incident",
        )
        assert cause != "route_leak"

    def test_physical_veto_overrides_a_confident_agent(
        self, builder: EvidenceChainBuilder
    ):
        cause = builder.determine_cause(
            traffic(anomaly_count=12, peak_trough_drop_pct=85.0,
                    outage_period_anomaly_count=4),
            routing(leak_count=0),
            {"cause": "route_leak", "confidence": 0.95},
            "real_incident",
        )
        assert cause == "outage"

    def test_low_confidence_agent_falls_back_to_the_tree(
        self, builder: EvidenceChainBuilder
    ):
        cause = builder.determine_cause(
            traffic(anomaly_count=0, data_available=True),
            routing(leak_count=0),
            {"cause": "route_leak", "confidence": 0.10},
            "real_incident",
        )
        assert cause == "no_clear_anomaly"
