"""Regression tests for the data-flow / correlation bugs fixed 2026-09-13.

These cover three failure modes operators observed on AS12479:

  1. ``correlation.signals.routing_event_count`` flipping between 401 and 0
     across runs of the same ASN / time window. Root cause: events whose
     timestamp was missing or in an unparseable format (e.g. ``"14:54:29"``
     with no date) were silently dropped by ``extract_routing_events``.

  2. Non-enhanced runs silently produced an empty ``victim_traffic_results``,
     because ``WorkflowEngine._handle_validation`` only fetched victim
     traffic when ``context.shared_blackboard`` existed.

  3. ``RoutingAgent.step`` did a double-write to blackboard (update_section
     + write) with the bulk update landing first and carrying the raw
     ``result`` key, then the second write overwriting it with the rich
     normalised form. A concurrent reader in between would see the raw form
     and the verdict would diverge.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
def test_extract_routing_events_falls_back_to_analysis_window():
    """Events with timestamp='14:54:29' (no date) used to be dropped → 0 events.

    After the fix, they must all be counted, with a single WARN log.
    """
    from agents.correlation_analyzer import extract_routing_events

    events = [
        {"timestamp": "14:54:29", "prefix": f"2001:db8::{i}::/48", "hijacker_as": "12479"}
        for i in range(401)
    ]
    routing = {
        "origin_hijacking": events,
        "leak_count": 0,
        "success": True,
        "analysis_period": "2024-01-03 14:45 to 2024-01-03 15:00",
    }
    extracted = extract_routing_events(
        routing,
        target_as="12479",
        analysis_window={
            "start": "2024-01-03T14:45:00",
            "end": "2024-01-03T15:00:00",
        },
    )
    assert len(extracted) == 401, (
        f"expected 401 events after timestamp fallback, got {len(extracted)}"
    )


def test_extract_routing_events_no_window_uses_analysis_period():
    """Without analysis_window, the analysis_period string is the fallback source."""
    from agents.correlation_analyzer import extract_routing_events

    events = [{"timestamp": "noon", "prefix": f"10.0.{i}.0/24"} for i in range(10)]
    routing = {
        "origin_hijacking": events,
        "analysis_period": "2024-06-01 10:00 to 2024-06-01 14:00",
    }
    extracted = extract_routing_events(routing, target_as="64512")
    assert len(extracted) == 10
    # All events share the same fallback midpoint timestamp.
    timestamps = {e.timestamp for e in extracted}
    assert len(timestamps) == 1


def test_extract_routing_events_keeps_valid_events_with_real_timestamps():
    """The fallback must NOT corrupt events that already have valid timestamps."""
    from agents.correlation_analyzer import extract_routing_events

    events = [
        {"timestamp": f"2024-01-03T14:5{i}:00", "prefix": f"10.0.{i}.0/24"}
        for i in range(5)
    ]
    routing = {"origin_hijacking": events}
    extracted = extract_routing_events(routing, target_as="12479")
    assert len(extracted) == 5
    # Each event retains its original timestamp (not the fallback).
    for ev in extracted:
        assert ev.timestamp.year == 2024
        assert ev.timestamp.month == 1
        assert ev.timestamp.day == 3


def test_extract_routing_events_logs_warn_only_once_for_many_events():
    """A 401-event payload must produce ONE warning, not 401."""
    import logging

    from agents.correlation_analyzer import extract_routing_events

    events = [{"timestamp": "14:54:29", "prefix": f"2001:db8::{i}::/48"} for i in range(401)]
    routing = {"origin_hijacking": events, "analysis_period": "2024-01-03 14:45 to 2024-01-03 15:00"}

    # Capture warnings emitted during the call.
    captured = []

    class _Capture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                captured.append(record.getMessage())

    logger = logging.getLogger("bgp_tracer")
    h = _Capture()
    logger.addHandler(h)
    logger.setLevel(logging.WARNING)
    try:
        extract_routing_events(routing, target_as="12479")
    finally:
        logger.removeHandler(h)

    matching = [m for m in captured if "missing/unparseable timestamp" in m]
    assert len(matching) == 1, (
        f"expected exactly one fallback warning, got {len(matching)}: {matching[:3]}"
    )


# ---------------------------------------------------------------------------
def test_handle_validation_runs_victim_traffic_without_shared_blackboard():
    """``_handle_validation`` must call ``_fetch_victim_traffic`` even when
    ``context.shared_blackboard`` is None (the default non-enhanced path).
    """
    from workflow_engine import WorkflowEngine, WorkflowContext

    captured: dict = {"called": False, "wrote_to_bb": None}

    async def main():
        engine = WorkflowEngine()
        ctx = WorkflowContext(
            asn="12479",
            start_time="2024-01-03T14:45:00",
            end_time="2024-01-03T15:00:00",
            victim_asns=["50300", "2914"],
            data_quality="high",
            confidence_score=0.7,
        )
        # shared_blackboard is a class-level attribute on WorkflowContext,
        ctx.shared_blackboard = None

        async def fake_fetch(ctx, bb):
            captured["called"] = True
            captured["wrote_to_bb"] = bb is not None
            await bb.write("routing", "victim_traffic_results", {"50300": {"ok": True}})

        engine._fetch_victim_traffic = fake_fetch  # type: ignore[assignment]
        await engine._handle_validation(ctx)
        return ctx

    asyncio.run(main())
    assert captured["called"], "victim_traffic fetch was skipped in non-enhanced mode"
    assert captured["wrote_to_bb"], "fetched victim traffic was not written to any blackboard"


# ---------------------------------------------------------------------------
def test_routing_agent_writes_result_before_bulk_update(monkeypatch):
    """In RoutingAgent.step(), the rich ``routing.result`` must be written
    *before* the bulk ``update_section`` so concurrent readers can never see
    the raw dict lacking flat count fields.
    """
    import asyncio
    from agents.core import Blackboard
    from agents.routing_agent import RoutingAgent

    async def main():
        bb = Blackboard()
        # Seed config so RoutingAgent doesn't bail out.
        await bb.write("config", "asn", "12479")
        await bb.write("config", "start_time", "2024-01-03T14:45:00")
        await bb.write("config", "end_time", "2024-01-03T15:00:00")
        await bb.write("config", "enable_mitm", False)
        await bb.write("config", "routing_detail", "light")
        await bb.write("config", "use_traffic_time_window", False)

        events = [{"timestamp": "2024-01-03T14:54:29Z", "prefix": f"2a01:c500::{i}::/48"} for i in range(10)]
        # Mock the heavy impl call.
        async def fake_impl(*args, **kwargs):
            return {
                "success": True,
                "asn": "12479",
                "origin_hijacked": [],
                "origin_hijacking": events,
                "forge_hijacked": [],
                "forge_hijacking": [],
                "leak_analysis": {"success": True, "route_leaks": [], "leak_count": 0},
                "route_leaks": [],
                "leak_count": 0,
                "outage_analysis": {"success": True, "is_outage_suspected": False, "outage_score": 0.0},
            }
        import agents.routing_agent as ra_mod
        monkeypatch.setattr(ra_mod, "_impl_async", fake_impl)

        # Spy on bb.write so we can confirm ordering.
        call_order = []
        orig_write = bb.write
        orig_update = bb.update_section
        async def spy_write(section, key, value, **kw):
            call_order.append(("write", section, key))
            return await orig_write(section, key, value, **kw)
        async def spy_update(section, data, **kw):
            call_order.append(("update_section", section, sorted(data.keys())))
            return await orig_update(section, data, **kw)
        bb.write = spy_write
        bb.update_section = spy_update

        agent = RoutingAgent(bb)
        await agent.start()
        result = await agent.step()
        assert result.success
        # Confirm routing.result was written BEFORE update_section(routing, ...).
        routing_writes = [c for c in call_order if c[1] == "routing"]
        assert routing_writes, "no routing writes captured"
        # The first write to ``routing`` should be the result key.
        assert ("write", "routing", "result") in call_order, (
            f"first routing write should be the rich result; got {routing_writes[:3]}"
        )
        # And update_section must NOT include a ``result`` key (since we
        # stripped it to avoid clobbering).
        update_calls = [c for c in call_order if c[0] == "update_section" and c[1] == "routing"]
        assert update_calls, "no routing update_section captured"
        _, _, keys = update_calls[0]
        assert "result" not in keys, (
            f"update_section must not carry the raw result key (would clobber "
            f"the rich normalised result); got keys={keys[:8]}"
        )

        # Final state: routing.result must carry the normalised flat fields.
        result_payload = await bb.read("routing", "result")
        assert "hijack_count" in result_payload, (
            "routing.result lost the flat count fields — readers downstream "
            "would compute inconsistent verdicts."
        )

    asyncio.run(main())
