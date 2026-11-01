"""A failing tool must cost one observation, not the whole analysis.

The ReAct loop calls optional external sources (BGPView, Spamhaus, RIPE,
RDAP, CIRCL).  Those sources fail routinely: DNS stops resolving, a
connection resets, a response body changes shape.  None of that is a
reason to abandon an incident analysis that already holds routing and
traffic evidence.

Every one of these tools used to guard its network call with a bare
``except (AttributeError)``.  ``requests``/``httpx`` raise
``ConnectionError``/``ConnectError``/``HTTPStatusError``, none of which
are ``AttributeError``, so a single DNS failure escaped the tool, escaped
the registry, and aborted the event.  On the ground-truth run this made
34 of 40 events unscoreable, which is exactly the silent-failure mode
these tests exist to prevent.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from tools.tool_registry import Tool, ToolParameter, ToolRegistry


def make_registry_with_failing_tool(exc: Exception):
    registry = ToolRegistry()

    async def failing_handler(tool_input, session):
        raise exc

    registry.register(Tool(
        name="flaky_probe",
        description="test tool that always raises",
        parameters=[ToolParameter(name="asn", type="string", description="ASN")],
        handler=failing_handler,
    ))
    return registry


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError("[Errno -2] Name or service not known"),
        httpx.HTTPStatusError(
            "500 Internal Server Error",
            request=httpx.Request("GET", "https://example.invalid"),
            response=httpx.Response(500),
        ),
        httpx.ReadTimeout("timed out"),
        OSError("network is unreachable"),
        ValueError("Expecting value: line 1 column 1"),
        KeyError("prefixes"),
    ],
)
def test_network_failure_returns_failed_result_instead_of_raising(exc):
    registry = make_registry_with_failing_tool(exc)

    result = asyncio.run(registry.call("flaky_probe", {"asn": "16509"}, session=None))

    assert result.success is False
    assert result.error
    # The observation must be non-empty so the ReAct loop has something to
    # read in the next round rather than silently losing the step.
    assert result.observation


def test_attribute_error_still_returns_failed_result():
    registry = make_registry_with_failing_tool(AttributeError("no such attribute"))

    result = asyncio.run(registry.call("flaky_probe", {"asn": "16509"}, session=None))

    assert result.success is False


def test_registered_tool_still_works():
    registry = ToolRegistry()

    async def ok_handler(tool_input, session):
        return {"success": True, "observation": "all good", "asn": tool_input["asn"]}

    registry.register(Tool(
        name="good_probe",
        description="test tool that succeeds",
        parameters=[ToolParameter(name="asn", type="string", description="ASN")],
        handler=ok_handler,
    ))

    result = asyncio.run(registry.call("good_probe", {"asn": "16509"}, session=None))

    assert result.success is True
    assert result.observation == "all good"
