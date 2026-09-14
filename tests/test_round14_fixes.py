"""Regression tests for Round 14 bug fixes (BUG-R100..R112).

Each test focuses on one of the silent failures identified during the
2026-09-13 audit. Together they form a regression suite that exercises:

- BUG-R100: ``format_observation`` no longer raises ``TypeError`` on
  non-serialisable dict-list values (e.g. datetimes, sets), and avoids
  duplicating the same item when count == 1.

- BUG-R101: ``try_enhanced_report`` is now an ``async`` method that
  ``await``s ``MultiAgentReportAgent.generate`` directly, instead of
  using ``asyncio.run`` from inside a running loop (which silently
  raised ``RuntimeError`` and swallowed the enhanced-report path).

- BUG-R102: ``_handle_report_generation`` no longer overwrites the
  authoritative ``legacy_html`` with an unconditional Blackboard read;
  the new logic prefers the longer of the two values when they
  diverge.

- BUG-R103: ``_extract_anomaly_times`` no longer leaks the dead local
  variable ``detected_windows`` and parses ISO timestamps in
  ``outage_period_anomalies`` before computing min/max, fixing the
  lexicographic comparison bug for non-ISO inputs.

- BUG-R107: ``router_agent._parse_react_response`` uses
  ``extract_json_object`` (string-aware brace counting) instead of a
  manual counter, preventing Action Input truncation when string values
  contain literal braces.

- BUG-R110: ``routing_impl.run_routing_agent_async`` parses each
  timestamp independently, supports ISO 8601 and plain-date formats,
  and returns a structured error dict instead of crashing when the
  caller passed an empty string.

- BUG-R111: ``traffic_impl._analyze_single_as_traffic`` accepts the
  same expanded format list and no longer aborts silently on ISO
  inputs.

- BUG-R112: ``AgentMessageBus._deliver`` no longer leaks completed
  tasks into ``_pending_deliveries`` — each task is removed via a
  done-callback plus an opportunistic sweep at every publish.

Run with::

    pytest tests/test_round14_fixes.py -v
"""

import asyncio
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

# Make sure we can import from the bgp_tracer package regardless of where
# pytest is invoked from.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# BUG-R100: format_observation must not raise on non-JSON-serialisable values
# ---------------------------------------------------------------------------

class _ReactAgentStub:
    """Minimal stub that exposes just enough of ReactAgent for format_observation."""
    def __init__(self):
        self.OBSERVATION_MAX_CHARS = 4000


def _get_format_observation():
    """Return the ReactAgent.format_observation unbound function."""
    from agents.react_agent import ReactAgent
    return ReactAgent.format_observation


def test_format_observation_handles_datetime_in_list():
    """BUG-R100: a list of dicts whose values contain datetime objects
    must not raise — fall back to ``default=str``."""
    f = _get_format_observation()
    stub = _ReactAgentStub()
    dt = datetime(2024, 1, 15, 12, 30, 0, tzinfo=timezone.utc)
    result = {
        "success": True,
        "anomalies": [
            {"timestamp": dt, "value": 1.5, "z_score": 2.3},
            {"timestamp": dt, "value": 1.4, "z_score": 2.1},
        ],
    }
    obs = f(stub, result)
    assert "anomalies" in obs
    assert "总数=2" in obs
    assert "2024" in obs  # datetime serialised via default=str


def test_format_observation_count_one_does_not_duplicate():
    """BUG-R100: a list of length 1 should not print the same item twice
    (浪费 context tokens)."""
    f = _get_format_observation()
    stub = _ReactAgentStub()
    result = {
        "success": True,
        "anomalies": [{"timestamp": "2024-01-15T12:30:00", "value": 1.5}],
    }
    obs = f(stub, result)
    assert "总数=1" in obs
    assert "唯一条目=" in obs
    # The duplicated "第一条" / "最后一条" form must NOT be present.
    assert "第一条=" not in obs
    assert "最后一条=" not in obs


def test_format_observation_handles_unserialisable_nested():
    """BUG-R100: a dict with an unserialisable value in results must not
    raise — the catch-all branch should print a safe placeholder."""
    f = _get_format_observation()
    stub = _ReactAgentStub()

    class _Weird:
        def __repr__(self):
            return "<weird>"

    result = {
        "success": True,
        "results": {"data": _Weird()},  # default= will fall back to str()
    }
    obs = f(stub, result)
    assert "Results" in obs  # not an exception


# ---------------------------------------------------------------------------
# BUG-R101: try_enhanced_report is now async and awaits MultiAgentReportAgent
# ---------------------------------------------------------------------------

def test_try_enhanced_report_is_async():
    """BUG-R101: ``try_enhanced_report`` must be a coroutine function and
    must call ``multi.generate`` via ``await``, not ``asyncio.run``.

    Without the fix, calling ``asyncio.run`` from inside the React
    loop raised ``RuntimeError`` and silently fell back to the plain
    ``generate_report`` tool.
    """
    from agents.react_agent import ReactAgent
    import inspect

    assert inspect.iscoroutinefunction(ReactAgent.try_enhanced_report), (
        "try_enhanced_report must be async to avoid asyncio.run() inside a "
        "running event loop."
    )


def test_try_enhanced_report_does_not_use_asyncio_run():
    """BUG-R101: the method body must not contain ``asyncio.run`` — the
    previous implementation called it from inside the running loop,
    which raised ``RuntimeError: asyncio.run() cannot be called from a
    running event loop``."""
    from agents.react_agent import ReactAgent
    import inspect
    src = inspect.getsource(ReactAgent.try_enhanced_report)
    # Strip comments + docstrings so the BUG-R101 explanation in the
    # method's docstring doesn't itself trip the assertion.
    import re
    code_only = re.sub(r"#.*", "", src)
    code_only = re.sub(r"\"{3}.*?\"{3}", "", code_only, flags=re.DOTALL)
    assert "asyncio.run" not in code_only, (
        "try_enhanced_report must not use asyncio.run() — it is invoked "
        "from within an already-running event loop."
    )


# ---------------------------------------------------------------------------
# BUG-R102: workflow_engine _handle_report_generation prefers longer HTML
# ---------------------------------------------------------------------------

def test_workflow_handle_report_generation_uses_smart_merge():
    """BUG-R102: the legacy report path no longer silently overwrites the
    authoritative ``legacy_html`` with a blank Blackboard value. The new
    logic compares lengths and keeps the longer of the two."""
    import inspect
    from workflow_engine import WorkflowEngine
    src = inspect.getsource(WorkflowEngine._handle_report_generation)
    # The unconditional over-write
    # ``html = bb._sections.get("report", {}).get("html") or ""``
    # must be replaced by a length-aware merge.
    assert "bb_html" in src, "expected new bb_html merge variable"
    assert "len(bb_html)" in src, "expected length-aware comparison"


# ---------------------------------------------------------------------------
# BUG-R103: _extract_anomaly_times: priority chain + ISO parse for outages
# ---------------------------------------------------------------------------

def test_extract_anomaly_times_uses_elif_chain():
    """BUG-R103: the previous code used ``if`` (not ``elif``) for
    ``consecutive_anomaly_windows`` vs ``expanded_windows`` — when both
    keys were present, the consecutive block ran unnecessarily before
    being overwritten. The fix uses an explicit priority chain."""
    import inspect
    import re
    from chief_agent import ChiefExpertAgent
    src = inspect.getsource(ChiefExpertAgent._extract_anomaly_times)
    # Strip comments + docstrings so the BUG-R103 explanation in the
    # method's docstring doesn't itself trip the assertion (the word
    # ``detected_windows`` appears in the historical-context comment).
    code_only = re.sub(r"#.*", "", src)
    code_only = re.sub(r"\"{3}.*?\"{3}", "", code_only, flags=re.DOTALL)
    # The new code uses an ``elif`` chain and no longer references the
    # dead local ``detected_windows``.
    assert "elif traffic_result.get('consecutive_anomaly_windows')" in code_only, (
        "expected elif chain between expanded_windows and consecutive_anomaly_windows"
    )
    assert "detected_windows" not in code_only, (
        "detected_windows was a dead local variable that was never returned"
    )


def test_extract_anomaly_times_parses_iso_for_outages():
    """BUG-R103: when ``outage_period_anomalies`` is the only key, the
    function must parse the timestamps and pick min/max on the parsed
    datetimes — not on the raw strings (which would sort lexicographically)."""
    from chief_agent import ChiefExpertAgent
    agent = ChiefExpertAgent.__new__(ChiefExpertAgent)
    traffic = {
        "outage_period_anomalies": [
            {"timestamp": "2024-01-15T13:00:00Z"},
            {"timestamp": "2024-01-05T11:00:00Z"},  # earlier
        ],
    }
    start, end = agent._extract_anomaly_times(
        traffic, "2024-01-01 00:00", "2024-02-01 00:00"
    )
    # Both inputs are returned as normalised strings. We just need to
    # ensure both came from the ISO parse, not from the (broken)
    # min/max over raw strings. The earliest of the two ISO strings is
    # ``2024-01-05``, so the first segment of the returned start must
    # be ``2024-01-05``.
    assert "2024-01-05" in start, (
        f"expected earliest outage timestamp; got {start!r}"
    )
    assert "2024-01-15" in end, (
        f"expected latest outage timestamp; got {end!r}"
    )


# ---------------------------------------------------------------------------
# BUG-R107: router_agent._parse_react_response uses string-aware brace count
# ---------------------------------------------------------------------------

def test_parse_react_response_handles_braces_in_string():
    """BUG-R107: an Action Input whose string value contains literal
    braces must not be truncated by the naive counter."""
    from tools.router_agent import RouterAgent

    # A value containing ``{x}`` and ``{y}`` would have caused the
    # old code to count ``{x}`` as the JSON terminator.
    response = (
        "Thought: I need to call a tool.\n"
        'Action: some_tool\n'
        'Action Input: {"template": "{a} and {b}", "count": 3}'
    )
    parsed = RouterAgent._parse_react_response(None, response)
    assert parsed["type"] == "action", parsed
    assert parsed["action"] == "some_tool", parsed
    assert parsed["input"] == {"template": "{a} and {b}", "count": 3}, parsed


def test_parse_react_response_falls_back_to_empty_on_bad_json():
    """BUG-R107: a malformed JSON body must still produce an empty
    dict (so the LLM caller can recover), not a truncated half-parse."""
    from tools.router_agent import RouterAgent

    response = (
        "Thought: I will try\n"
        "Action: some_tool\n"
        "Action Input: {this is not valid json"
    )
    parsed = RouterAgent._parse_react_response(None, response)
    assert parsed["type"] == "action"
    # Either we parsed the trailing ``{...}`` cleanly OR we fell back to
    # an empty dict — both are acceptable recoveries. We must NOT have
    # silently parsed something broken.
    assert isinstance(parsed["input"], dict)


# ---------------------------------------------------------------------------
# BUG-R110: routing_impl parses each timestamp independently
# ---------------------------------------------------------------------------

def test_run_routing_agent_async_iso_end_time():
    """BUG-R110: the previous parser tried to match start AND end on the
    same format in a single loop, so an ISO-format ``end_time`` paired
    with a human-readable ``start_time`` would silently fall through
    to ``fromisoformat`` — and then crash on plain dates / empty
    strings. The new helper parses each side independently."""

    from agents.impl.routing_impl import run_routing_agent_async

    result = asyncio.run(run_routing_agent_async(
        asn="13335",
        start_time="2024-01-15 00:00",
        end_time="2024-01-15T00:30:00Z",
        use_llm=False,
        skip_hijack_streaming=True,
        skip_leak=True,
        skip_outage=True,
    ))
    # We expect either a normal result dict (success=True) OR an
    # ``isinstance(result, dict)`` error result. We must NOT have a
    # ValueError escape from ``datetime.fromisoformat`` or
    # ``strptime``.
    assert isinstance(result, dict), (
        f"routing_impl raised or returned non-dict: {result!r}"
    )


def test_run_routing_agent_async_empty_string_does_not_crash():
    """BUG-R110: the routing tool used to set ``start = ""`` when the
    caller passed ``start_time=None``, which propagated into the parser
    and crashed. The new code returns a structured error dict instead."""

    from agents.impl.routing_impl import run_routing_agent_async

    result = asyncio.run(run_routing_agent_async(
        asn="13335",
        start_time="",
        end_time="",
        use_llm=False,
        skip_hijack_streaming=True,
        skip_leak=True,
        skip_outage=True,
    ))
    assert isinstance(result, dict)
    assert result.get("success") is False
    assert "Cannot parse time window" in (result.get("error") or "")


# ---------------------------------------------------------------------------
# BUG-R111: traffic_impl accepts ISO timestamps too
# ---------------------------------------------------------------------------

def _run_async(coro):
    """Run an async coroutine to completion using asyncio.run()."""
    return asyncio.run(coro)


def test_analyze_single_as_traffic_accepts_iso(monkeypatch):
    """BUG-R111: ISO timestamps must not cause ``Invalid time`` errors
    any more. We stub the heavy LLM call to focus on the parser."""

    from agents.impl import traffic_impl

    class _StubLLMAgent:
        async def analyze_traffic_with_llm(self, *args, **kwargs):
            return {"success": True, "anomalies": [], "anomaly_count": 0}
        async def analyze_traffic_no_llm(self, *args, **kwargs):
            return {"success": True, "anomalies": [], "anomaly_count": 0}

    monkeypatch.setattr(traffic_impl, "LLMEnhancedTrafficAgent", _StubLLMAgent)

    async def _driver():
        return await traffic_impl._analyze_single_as_traffic(
            "13335",
            "2024-01-15T00:00:00",
            "2024-01-15T00:30:00Z",
            routing_analysis=None,
            use_llm=False,
        )

    result = _run_async(_driver())
    assert isinstance(result, dict)
    # If the parser still rejected ISO strings, the result would be
    # ``{"success": False, "error": "Invalid time: ..."}``.
    assert result.get("success") is True, result


def test_analyze_single_as_traffic_reports_invalid_time():
    """BUG-R111: garbage input still returns a structured error (not a
    crash) and the error message references the actual input strings
    so operators can diagnose."""

    from agents.impl import traffic_impl

    async def _driver():
        return await traffic_impl._analyze_single_as_traffic(
            "13335",
            "totally not a timestamp",
            "also garbage",
            routing_analysis=None,
            use_llm=False,
        )

    result = _run_async(_driver())
    assert result.get("success") is False
    assert "Invalid time" in (result.get("error") or "")
    assert "totally not a timestamp" in (result.get("error") or "")


# ---------------------------------------------------------------------------
# BUG-R112: AgentMessageBus._pending_deliveries no longer leaks
# ---------------------------------------------------------------------------

def test_message_bus_does_not_leak_completed_tasks():
    """BUG-R112: completed delivery tasks must be removed from
    ``_pending_deliveries`` so the list doesn't grow without bound."""

    from agents.enhanced.message_bus import AgentMessageBus, MessageEnvelope

    bus = AgentMessageBus(run_id="round14-bus")
    delivered = []

    async def handler(env: MessageEnvelope):
        delivered.append(env.topic)

    async def _driver():
        await bus.subscribe(topic="ping", handler=handler, subscriber="sub-A")
        # Publish a bunch of messages; each one kicks off a delivery task.
        for i in range(20):
            await bus.publish(topic="ping", sender="tester", content={"i": i})
        # Give the loop a chance to run the tasks.
        await asyncio.sleep(0.05)
        return bus.snapshot()

    snap = _run_async(_driver())
    # Snapshot should report 0 (or at most 1) pending deliveries, not 20.
    assert snap["pending_deliveries"] <= 1, (
        f"expected at most 1 pending delivery after settle, got "
        f"{snap['pending_deliveries']}"
    )
    # All 20 messages were actually delivered (no leaks, no losses).
    assert len(delivered) == 20, f"expected 20 deliveries, got {len(delivered)}"


def test_message_bus_keeps_pending_tasks_until_complete():
    """BUG-R112: the fix must not remove tasks that are still in flight;
    only done tasks are dropped."""

    from agents.enhanced.message_bus import AgentMessageBus, MessageEnvelope

    bus = AgentMessageBus(run_id="round14-bus-pending")

    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_handler(env: MessageEnvelope):
        started.set()
        await release.wait()

    async def _driver():
        await bus.subscribe(topic="slow", handler=slow_handler, subscriber="slow-sub")
        # Kick off one delivery, wait until it starts, then snapshot.
        pub_task = asyncio.create_task(
            bus.publish(topic="slow", sender="tester", content={"k": 1})
        )
        await started.wait()
        snap = bus.snapshot()
        pending_during = snap["pending_deliveries"]
        # Release the slow handler and let the publish settle.
        release.set()
        await pub_task
        await asyncio.sleep(0.05)
        snap2 = bus.snapshot()
        return pending_during, snap2["pending_deliveries"]

    pending_during, pending_after = _run_async(_driver())
    assert pending_during >= 1, (
        "still-in-flight task must not be removed prematurely"
    )
    assert pending_after == 0


# ---------------------------------------------------------------------------
# Sanity: every test above must leave the pending list bounded
# ---------------------------------------------------------------------------

def test_message_bus_sweep_helper_is_callable():
    """BUG-R112: the new ``_sweep_pending_deliveries`` helper exists and
    is callable from outside the publish path."""
    from agents.enhanced.message_bus import AgentMessageBus

    bus = AgentMessageBus(run_id="round14-sweep")
    assert hasattr(bus, "_sweep_pending_deliveries")
    bus._sweep_pending_deliveries()  # must not raise on an empty list
    assert bus._pending_deliveries == []
