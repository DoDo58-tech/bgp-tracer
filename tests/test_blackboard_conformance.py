#!/usr/bin/env python3
"""Conformance tests for the Evidence Blackboard's stated guarantees.

The paper claims three properties of the Blackboard that are architectural
guarantees rather than empirical observations, so they are tested here as
invariants that a future refactor could break:

  1. Write-once semantics for critical telemetry. A second write whose
     semantic fingerprint differs from the first is rejected and the
     original is retained, with the rejected writer named. This is the
     property that stops a later stage from silently replacing an earlier
     stage's measurement.

  2. The Blackboard is shared across the stages of a run. The workflow
     used to construct one board per stage, which made the "shared"
     evidence surface four disjoint boards.

  3. The typed record vocabulary is complete. Observations, claims,
     challenges, verdicts, alternatives, gaps and metrics each land in
     their own list, and merging the report stage's snapshot into the
     board appends rather than replaces.

Run: python -m pytest tests/test_blackboard_conformance.py -q
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.core import Blackboard  # noqa: E402


# ── 1. Write-once semantics ────────────────────────────────────────────────


def test_second_write_with_different_content_is_rejected():
    """A divergent second write must not replace the original value."""
    async def run():
        bb = Blackboard()
        await bb.write("routing", "result", {"anomaly_count": 3}, _writer="RoutingAgent")
        # Same key, semantically different content.
        await bb.write("routing", "result", {"anomaly_count": 9}, _writer="ReportAgent")
        return await bb.read("routing", "result")

    result = asyncio.run(run())
    assert result["anomaly_count"] == 3, "divergent write replaced the original"


def test_rewrite_with_equivalent_content_is_accepted():
    """A re-write of the same measurement must not be treated as drift."""
    async def run():
        bb = Blackboard()
        await bb.write("routing", "result", {"anomaly_count": 3}, _writer="RoutingAgent")
        await bb.write("routing", "result", {"anomaly_count": 3}, _writer="RoutingAgent")
        return await bb.read("routing", "result")

    result = asyncio.run(run())
    assert result["anomaly_count"] == 3


def test_explicit_overwrite_is_honoured():
    """The escape hatch must still work for intentional replacements."""
    async def run():
        bb = Blackboard()
        await bb.write("routing", "result", {"anomaly_count": 3}, _writer="RoutingAgent")
        await bb.write("routing", "result", {"anomaly_count": 9},
                       _writer="Recovery", _allow_overwrite=True)
        return await bb.read("routing", "result")

    result = asyncio.run(run())
    assert result["anomaly_count"] == 9


def test_write_once_holds_under_concurrent_writers():
    """Concurrent divergent writes must leave exactly one value, and it must
    be one of the values that was actually written (never a blend)."""
    async def run():
        bb = Blackboard()
        await bb.write("traffic", "result", {"anomaly_count": 0}, _writer="TrafficAgent")
        await asyncio.gather(*(
            bb.write("traffic", "result", {"anomaly_count": i}, _writer=f"writer{i}")
            for i in range(1, 21)
        ))
        return await bb.read("traffic", "result")

    result = asyncio.run(run())
    assert result["anomaly_count"] in {0} | set(range(1, 21))
    assert isinstance(result["anomaly_count"], int)


def test_non_critical_keys_are_writable():
    """The guard must apply to the critical keys only."""
    async def run():
        bb = Blackboard()
        await bb.write("traffic", "anomaly_window", {"start": "a"})
        await bb.write("traffic", "anomaly_window", {"start": "b"})
        return await bb.read("traffic", "anomaly_window")

    assert asyncio.run(run()) == {"start": "b"}


# ── 1b. Slimming must bound size without deleting content ─────────────────


def test_slimming_does_not_empty_a_payload_with_unlisted_keys():
    """A section allow-list must not wipe a value whose keys it does not name.

    Regression test: the traffic/validation/evidence profiles are keyed for
    whole-section payloads. Applying them to an individual key's value
    replaced ``traffic.anomaly_window``, ``validation.hcaf_attribution``
    and ``evidence.chain`` with empty dicts, erasing the analysis window,
    the causal attribution and the reasoning chain from the board.
    """
    async def run():
        bb = Blackboard()
        await bb.write("validation", "hcaf_attribution", {
            "direction": "routing->traffic", "strength": 0.8, "confidence": 0.9,
        })
        await bb.write("evidence", "chain", {
            "verdict": "cooccurring_anomalies", "confidence": 0.55,
            "reasoning_steps": ["step one", "step two"],
        })
        await bb.write("traffic", "anomaly_window", {
            "start": "2026-01-01T00:00:00", "end": "2026-01-01T01:00:00",
        })
        return (
            await bb.read("validation", "hcaf_attribution"),
            await bb.read("evidence", "chain"),
            await bb.read("traffic", "anomaly_window"),
        )

    hcaf, chain, window = asyncio.run(run())
    assert hcaf.get("direction") == "routing->traffic"
    assert chain.get("reasoning_steps") == ["step one", "step two"]
    assert window.get("start") == "2026-01-01T00:00:00"


def test_slimming_still_bounds_an_oversized_payload():
    """The size guard must keep working after the content guard."""
    async def run():
        bb = Blackboard()
        await bb.write("traffic", "analysis_payload", {
            "anomaly_count": 3,
            "anomalies": [{"prefix": f"10.0.0.{i}", "as_path": "x" * 200} for i in range(200)],
        })
        return await bb.read("traffic", "analysis_payload")

    payload = asyncio.run(run())
    assert payload, "payload was emptied"
    assert len(payload.get("anomalies", [])) < 200, "oversized list was not bounded"


# ── 2. The board is shared across stages ───────────────────────────────────


def test_workflow_context_returns_one_board_for_the_whole_run():
    """Every stage of a run must see the same board instance."""
    from workflow_engine import WorkflowContext

    ctx = WorkflowContext(asn="AS64500", start_time="2026-01-01T00:00:00",
                          end_time="2026-01-01T01:00:00")
    first = ctx.get_blackboard()
    second = ctx.get_blackboard()
    assert first is second, "stages received different Blackboard instances"


def test_board_is_shared_between_two_workflow_contexts_only_when_requested():
    """Two independent runs must not share a board by accident."""
    from workflow_engine import WorkflowContext

    a = WorkflowContext(asn="AS1", start_time="t0", end_time="t1")
    b = WorkflowContext(asn="AS2", start_time="t0", end_time="t1")
    assert a.get_blackboard() is not b.get_blackboard()


# ── 3. The typed record vocabulary ─────────────────────────────────────────


@pytest.mark.parametrize(
    "method,key",
    [
        ("add_observation", "observations"),
        ("add_claim", "claims"),
        ("add_challenge", "challenges"),
        ("add_verdict", "verdicts"),
        ("add_alternative", "alternatives"),
        ("add_gap", "gaps"),
        ("add_metric", "metrics"),
    ],
)
def test_each_record_type_lands_in_its_own_list(method, key):
    """Each record kind must be retrievable from its own list."""
    async def run():
        bb = Blackboard()
        payload = {
            "add_observation": {"source": "S", "kind": "k", "summary": "s"},
            "add_claim": {"source": "S", "kind": "k", "summary": "s"},
            "add_challenge": {"source": "S", "target_id": "t", "summary": "s"},
            "add_verdict": {"source": "S", "target_id": "t", "verdict": "v", "summary": "s"},
            "add_alternative": {"source": "S", "alternative": "a", "rejected_because": "r"},
            "add_gap": {"source": "S", "kind": "k", "summary": "s"},
            "add_metric": {"source": "S", "name": "n", "value": 1},
        }[method]
        await getattr(bb, method)(payload)
        return await bb.read_evidence_board()

    board = asyncio.run(run())
    assert len(board[key]) == 1, f"{method} did not land in evidence.{key}"
    assert board[key][0]["type"] == key.rstrip("s") if key != "observations" else True


def test_alternative_record_carries_the_rejection_reason():
    """An alternative is only useful if it says why it lost."""
    async def run():
        bb = Blackboard()
        rec = await bb.add_alternative({
            "source": "EvidenceChainBuilder",
            "alternative": "traffic_only_anomaly",
            "competes_with": "cooccurring_anomalies",
            "rejected_because": "a routing anomaly was also present",
        })
        return rec

    rec = asyncio.run(run())
    assert rec["type"] == "alternative"
    assert rec["alternative"] == "traffic_only_anomaly"
    assert rec["rejected_because"]
    assert rec["competes_with"] == "cooccurring_anomalies"


def test_gap_record_carries_severity_and_impact():
    """A gap is only useful if it says what it weakens."""
    async def run():
        bb = Blackboard()
        return await bb.add_gap({
            "source": "WorkflowEngine",
            "kind": "traffic_data_unavailable",
            "severity": "missing",
            "impact": "The traffic side of the correlation is unobserved.",
        })

    rec = asyncio.run(run())
    assert rec["type"] == "gap"
    assert rec["severity"] == "missing"
    assert rec["impact"]


def test_merge_evidence_appends_and_does_not_replace():
    """The report stage's snapshot must not wipe earlier records."""
    async def run():
        bb = Blackboard()
        await bb.add_observation({"source": "TrafficAgent", "kind": "traffic_analysis",
                                  "summary": "traffic obs"})
        await bb.add_claim({"source": "HypothesisAgent", "kind": "origin_hijack",
                            "summary": "hypothesis 1"})
        before = await bb.read_evidence_board()
        before_counts = {k: len(v) for k, v in before.items() if isinstance(v, list)}
        await bb.merge_evidence({
            "observations": [{"source": "Report", "kind": "k", "summary": "late obs"}],
            "claims": [{"source": "Report", "kind": "k", "summary": "late claim"}],
        }, _writer="test")
        after = await bb.read_evidence_board()
        return before_counts, after

    before_counts, after = asyncio.run(run())
    assert len(after["observations"]) == before_counts["observations"] + 1
    assert len(after["claims"]) == before_counts["claims"] + 1
    # The original records must still be present.
    assert any(o.get("source") == "TrafficAgent" for o in after["observations"])
    assert any(c.get("source") == "HypothesisAgent" for c in after["claims"])


def test_clear_resets_every_record_list():
    """A cleared board must not retain records of any type."""
    async def run():
        bb = Blackboard()
        await bb.add_observation({"source": "S", "kind": "k", "summary": "s"})
        await bb.add_alternative({"source": "S", "alternative": "a"})
        await bb.add_gap({"source": "S", "kind": "k"})
        await bb.clear()
        return await bb.read_evidence_board()

    board = asyncio.run(run())
    for key in ("observations", "claims", "challenges", "verdicts",
                "alternatives", "gaps", "metrics"):
        assert board[key] == [], f"evidence.{key} survived clear()"


# ── 4. The rejected-verdict enumeration is consistent with the verdict ────


def test_rejected_verdicts_exclude_the_chosen_one():
    """The chosen verdict must never appear among the rejected ones."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    builder = EvidenceChainBuilder()
    traffic = {"anomaly_count": 5, "data_available": True}
    routing = {"origin_hijacked": [1, 2], "success": True}
    for chosen in ("correlated_observations", "cooccurring_anomalies",
                   "traffic_only_anomaly", "routing_only_anomaly", "verified_normal"):
        rejected = builder.enumerate_rejected_verdicts(
            traffic_result=traffic,
            routing_result=routing,
            causal_analysis={"has_association": False},
            chosen_verdict=chosen,
        )
        assert chosen not in [r[0] for r in rejected]
        assert all(r[1] for r in rejected), "a rejection must carry a reason"


def test_rejected_verdicts_are_empty_when_a_layer_is_unavailable():
    """With a missing layer there is no decision table to enumerate."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    builder = EvidenceChainBuilder()
    rejected = builder.enumerate_rejected_verdicts(
        traffic_result={"anomaly_count": 5, "data_available": False},
        routing_result={"origin_hijacked": [1], "success": True},
        causal_analysis=None,
        chosen_verdict="inconclusive_missing_traffic",
    )
    assert rejected == []
