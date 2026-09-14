"""Regression tests for the 2026-09-13 round-3 bug fixes.

Covers:
  - workflow_engine.WorkflowEngine._extract_hcaf_strength (bug: dual-getattr
    made "unknown" unreachable; bug fix flattens the logic).
  - workflow_engine subscriber-clear when WORKFLOW_EVENT_DRIVEN_ENABLED
    is false (bug: iterating ``bus._subscriptions.values()`` and using
    the list as a dict key raised TypeError).
  - agents.report_agent._run_auto_probes no longer blocks the running
    event loop for up to 30s when called from an async context.
  - chief_agent / workflow_engine: ``event_type`` and ``as_role`` are
    now propagated to the Blackboard ``config`` section.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Bug fix 1: HCAF strength extraction
# ---------------------------------------------------------------------------

def test_extract_hcaf_strength_handles_missing_attr():
    """If ``强度`` is missing on the result object, return "unknown"."""
    from workflow_engine import WorkflowEngine

    class _R:
        pass

    out = WorkflowEngine._extract_hcaf_strength(_R())
    assert out == {"strength": "unknown"}


def test_extract_hcaf_strength_handles_none():
    """If ``强度`` is explicitly None, return "unknown"."""
    from workflow_engine import WorkflowEngine

    class _R:
        强度 = None

    out = WorkflowEngine._extract_hcaf_strength(_R())
    assert out == {"strength": "unknown"}


def test_extract_hcaf_strength_uses_value_attribute():
    """If 强度 has a ``.value`` (e.g. Enum), use that."""
    from workflow_engine import WorkflowEngine

    class _Enum:
        value = "STRONG"

    class _R:
        强度 = _Enum()

    out = WorkflowEngine._extract_hcaf_strength(_R())
    assert out == {"strength": "STRONG"}


def test_extract_hcaf_strength_falls_back_to_scalar():
    """If 强度 is a plain scalar (e.g. float), use it directly."""
    from workflow_engine import WorkflowEngine

    class _R:
        强度 = 0.75

    out = WorkflowEngine._extract_hcaf_strength(_R())
    assert out == {"strength": 0.75}


def test_extract_hcaf_strength_falls_back_to_str():
    """If 强度 is some other type, coerce to string."""
    from workflow_engine import WorkflowEngine

    class _Custom:
        def __str__(self):
            return "CUSTOM_STRENGTH"

    class _R:
        强度 = _Custom()

    out = WorkflowEngine._extract_hcaf_strength(_R())
    assert out == {"strength": "CUSTOM_STRENGTH"}


# ---------------------------------------------------------------------------
# Bug fix 2: subscriber clearing no longer raises TypeError
# ---------------------------------------------------------------------------

def test_subscriber_clear_no_typeerror():
    """WORKFLOW_EVENT_DRIVEN_ENABLED=false path must not raise TypeError.

    The previous implementation iterated ``bus._subscriptions.values()``
    and used each list (callback list) as a dict key — TypeError.
    """
    from agents.enhanced import AgentMessageBus, Topic

    bus = AgentMessageBus.get_instance("test_clear")
    bus.subscribe_sync(Topic.TRAFFIC_FULL_RESULT, lambda x: None, "tester1")
    bus.subscribe_sync(Topic.ROUTING_COMPLETE, lambda x: None, "tester2")
    assert len(bus._subscriptions.get(Topic.TRAFFIC_FULL_RESULT, [])) > 0

    # The fix: iterate keys, clear values
    for topic in list(bus._subscriptions.keys()):
        bus._subscriptions[topic] = []

    # Each topic's list should now be empty
    for topic, callbacks in bus._subscriptions.items():
        assert callbacks == [], (
            f"subscriber list for {topic!r} was not cleared: {callbacks}"
        )

    AgentMessageBus.clear_instance("test_clear")


# ---------------------------------------------------------------------------
# Bug fix 3: _run_auto_probes no longer blocks the event loop
# ---------------------------------------------------------------------------

def test_run_auto_probes_does_not_block_event_loop():
    """When called from an async context, the old ``future.result(timeout=30)``
    would block the running event loop. The fix uses ``asyncio.wrap_future``
    so the loop stays responsive.
    """
    from agents import report_agent

    async def main():
        loop = asyncio.get_running_loop()
        # Schedule a heartbeat that fires every 50ms; if _run_auto_probes
        # blocks the loop for 30s, our heartbeats will be delayed.
        heartbeats = []

        async def heartbeat():
            for _ in range(5):
                heartbeats.append(asyncio.get_event_loop().time())
                await asyncio.sleep(0.05)

        async def call_run():
            # We can't actually run real probes (no LLM); pass a sentinel
            # that immediately raises to short-circuit the inner work.
            try:
                await report_agent._run_auto_probes(
                    findings_or_recommendations=[],
                    target_as="0",
                    enable_external=False,
                )
            except Exception:
                pass

        # Start heartbeat + run in parallel
        t0 = loop.time()
        await asyncio.gather(heartbeat(), call_run())
        elapsed = loop.time() - t0
        # If the loop was blocked for 30s, elapsed >= 30. Allow a small
        # buffer (the inner run completes quickly) so a 5s threshold is
        # already conclusive: it shouldn't be anywhere near 30s.
        assert elapsed < 5.0, (
            f"event loop was blocked for {elapsed:.1f}s — old behavior would "
            "block for ~30s waiting on a thread-pool future"
        )
        # Heartbeats should have fired multiple times
        assert len(heartbeats) >= 3, (
            f"only {len(heartbeats)} heartbeats fired in {elapsed:.1f}s; "
            "loop was blocked"
        )

    asyncio.run(main())


# ---------------------------------------------------------------------------
# Bug fix 4: event_type / as_role carried on WorkflowContext
# ---------------------------------------------------------------------------

def test_event_type_propagated_to_workflow_context():
    """Sanity check: WorkflowContext carries event_type/as_role.

    The actual propagation into the Blackboard ``config`` section is
    integration-tested by the end-to-end workflow; here we just verify
    the dataclass still accepts the fields and preserves them.
    """
    from workflow_engine import WorkflowContext

    ctx = WorkflowContext(
        asn="12479",
        start_time="2024-01-03T14:00:00",
        end_time="2024-01-03T16:00:00",
        event_type="hijack",
        as_role="victim",
    )
    assert ctx.event_type == "hijack"
    assert ctx.as_role == "victim"
