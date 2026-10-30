"""Tests for the typed evidence-gap records.

The Evidence Blackboard's Q5 answerability score is the fraction of runs
that carry a record of a missing or degraded input.  A gap that is
never written therefore lowers a measured property of the system, so the
conditions that produce a gap are worth pinning: each degradation the
pipeline can observe must produce a typed record with an impact.

The route-leak detector's saturation is the case that matters most on the
evaluation corpus: it hits its result cap on most windows, so the
reported leak count is a floor rather than a total, and a reader of the
board would otherwise take the count at face value.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.core import Blackboard  # noqa: E402
from workflow_engine import WorkflowEngine  # noqa: E402


class FakeContext:
    """The slice of a WorkflowContext that gap recording reads."""

    def __init__(self, blackboard, traffic=None, routing=None,
                 hcaf_status=""):
        self._bb = blackboard
        self.traffic_result = traffic or {}
        self.routing_result = routing or {}
        self.hcaf_attribution_status = hcaf_status

    def get_blackboard(self):
        return self._bb


async def record(routing=None, traffic=None, quality=1.0, hcaf_status=""):
    bb = Blackboard()
    engine = WorkflowEngine()
    ctx = FakeContext(bb, traffic=traffic, routing=routing,
                      hcaf_status=hcaf_status)
    await engine.record_evidence_gaps(ctx, quality)
    board = await bb.read_evidence_board()
    gaps = board.get("gaps") or []
    if isinstance(gaps, dict):
        gaps = gaps.get("value") or []
    return gaps


def kinds(gaps):
    return {g.get("kind") for g in gaps if isinstance(g, dict)}


def test_saturated_leak_detector_is_recorded_as_a_gap():
    gaps = asyncio.run(record(routing={
        "success": True,
        "data_available": True,
        "leak_results_truncated": True,
        "leak_count": 5000,
    }))
    assert "leak_detector_saturated" in kinds(gaps)
    saturated = next(g for g in gaps
                     if g.get("kind") == "leak_detector_saturated")
    assert saturated.get("impact"), "a gap must state its consequence"
    assert saturated.get("severity") in ("missing", "degraded")


def test_skipped_leak_analysis_is_recorded_as_a_gap():
    gaps = asyncio.run(record(routing={
        "success": True,
        "data_available": True,
        "leak_analysis_skipped": True,
    }))
    assert "leak_analysis_not_run" in kinds(gaps)


def test_a_healthy_routing_result_records_no_leak_gap():
    gaps = asyncio.run(record(routing={
        "success": True,
        "data_available": True,
        "leak_results_truncated": False,
        "leak_analysis_skipped": False,
    }))
    assert "leak_detector_saturated" not in kinds(gaps)
    assert "leak_analysis_not_run" not in kinds(gaps)


def test_missing_traffic_is_recorded():
    gaps = asyncio.run(record(traffic={
        "success": False,
        "data_available": False,
        "no_data_reason": "fetch_failed",
    }))
    assert "traffic_data_unavailable" in kinds(gaps)


def test_cross_layer_mismatch_is_recorded():
    gaps = asyncio.run(record(
        traffic={"success": True, "data_available": True, "anomaly_count": 3},
        routing={"success": True, "data_available": True},
    ))
    assert "cross_layer_mismatch" in kinds(gaps)


def test_failed_causal_attribution_is_recorded():
    gaps = asyncio.run(record(hcaf_status="failed"))
    assert "causal_attribution_unavailable" in kinds(gaps)


def test_low_evidence_completeness_is_recorded():
    gaps = asyncio.run(record(quality=0.2))
    assert "low_evidence_completeness" in kinds(gaps)


def test_every_gap_states_a_kind_and_an_impact():
    gaps = asyncio.run(record(
        traffic={"success": False, "data_available": False},
        routing={"success": True, "data_available": True,
                 "leak_results_truncated": True},
        quality=0.2,
    ))
    assert gaps
    for gap in gaps:
        assert gap.get("kind"), f"gap without a kind: {gap}"
        assert gap.get("impact"), f"gap without an impact: {gap}"
        assert gap.get("summary"), f"gap without a summary: {gap}"
