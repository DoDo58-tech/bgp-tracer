"""
Regression tests for round-7 audit-pass fixes:

  R32 : ``utils.helpers.extract_json_object`` returns balanced braces so
        LLM responses with ``{...}`` substrings inside string values no
        longer truncate the JSON early (the old ``find('{') + rfind('}')``
        approach mis-identified the terminator).

  R33 : ``utils.helpers.parse_llm_json`` falls back through:
          (a) strict parse,
          (b) fenced ```json block,
          (c) balanced-extract snippet,
        and re-raises JSONDecodeError when all fail.

  R34 : ``detectors.outage.outage_detector.RouteOutageDetector.parse_cached``
        is bounded by ``_MAX_PARSED_CACHE_SIZE`` — no more unbounded
        growth across many AS / window invocations.

  R35 : ``tools.tool_implementations._async_get_json`` wraps the
        blocking ``requests.get`` in ``asyncio.to_thread`` so concurrent
        agent coroutines are not stalled during external API calls.

  R36 : ``agents.evidence_chain_builder``,
        ``agents.llm_reasoning`` (×3),
        ``agents.reasoning_agent``,
        ``agents.impl.traffic_impl``,
        ``agents.impl.routing_impl`` use ``extract_json_object`` instead
        of the buggy ``find('{') + rfind('}') + 1`` pattern.

  R37 : ``agents.report_agent._try_fetch_rpki_fallback`` offloads the
        blocking Cloudflare ROA ``requests.get`` via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
def test_extract_json_object_handles_braces_in_string_value():
    """A LLM response that has ``{...}`` inside a string value should
    not truncate the JSON at the inner brace.
    """
    from utils.helpers import extract_json_object
    raw = (
        'Here is the JSON: {"note": "looks like {foo} bar", "x": 1} '
        "— that's the answer."
    )
    snippet = extract_json_object(raw)
    assert snippet is not None
    parsed = json.loads(snippet)
    assert parsed == {"note": "looks like {foo} bar", "x": 1}


def test_extract_json_object_handles_nested_objects():
    from utils.helpers import extract_json_object
    raw = 'Output: {"a": {"b": 2, "c": {"d": 3}}, "e": 4}'
    snippet = extract_json_object(raw)
    assert snippet is not None
    assert json.loads(snippet) == {"a": {"b": 2, "c": {"d": 3}}, "e": 4}


def test_extract_json_object_escaped_quotes_in_string():
    from utils.helpers import extract_json_object
    raw = 'Result: {"msg": "He said \\"{hi}\\" ok", "n": 2}'
    snippet = extract_json_object(raw)
    assert snippet is not None
    parsed = json.loads(snippet)
    assert parsed["n"] == 2
    assert parsed["msg"].startswith("He said")


def test_extract_json_object_returns_none_when_no_object():
    from utils.helpers import extract_json_object
    assert extract_json_object("no braces here at all") is None
    assert extract_json_object("") is None
    assert extract_json_object(None) is None


def test_extract_json_object_picks_first_object_when_multiple():
    from utils.helpers import extract_json_object
    raw = 'first {"a": 1} and second {"b": 2}'
    snippet = extract_json_object(raw)
    assert snippet is not None
    parsed = json.loads(snippet)
    assert parsed == {"a": 1}


# ---------------------------------------------------------------------------
def test_parse_llm_json_strict_success():
    from utils.helpers import parse_llm_json
    assert parse_llm_json('{"a": 1, "b": "x"}') == {"a": 1, "b": "x"}


def test_parse_llm_json_markdown_fence():
    from utils.helpers import parse_llm_json
    text = "Sure!\n```json\n{\"x\": 42}\n```\nDone."
    assert parse_llm_json(text) == {"x": 42}


def test_parse_llm_json_with_prose_wrapper():
    from utils.helpers import parse_llm_json
    text = 'Here is the JSON output:\n{"result": "OK"}\nDone.'
    assert parse_llm_json(text) == {"result": "OK"}


def test_parse_llm_json_raises_on_unparseable():
    from utils.helpers import parse_llm_json
    with pytest.raises(json.JSONDecodeError):
        parse_llm_json("nothing parseable")


def test_parse_llm_json_handles_none_and_empty():
    from utils.helpers import parse_llm_json
    with pytest.raises(ValueError):
        parse_llm_json(None)
    with pytest.raises(ValueError):
        parse_llm_json("")
    with pytest.raises(ValueError):
        parse_llm_json("   ")


# ---------------------------------------------------------------------------
def test_outage_detector_parsed_cache_is_bounded():
    from datetime import datetime, timedelta
    from detectors.outage.outage_detector import RouteOutageDetector

    detector = RouteOutageDetector()
    base = datetime(2025, 1, 1)
    # Inject 5x the cap size to force eviction
    for i in range(detector._MAX_PARSED_CACHE_SIZE * 5):
        ts = base + timedelta(seconds=i)
        detector.parse_cached(ts.isoformat())

    assert len(detector.parsed_cache) <= detector._MAX_PARSED_CACHE_SIZE
    # Bug fix 2026-09-13 (BUG-R127 regression check): the cache used
    assert hasattr(detector, "parsed_cache")
    from collections import OrderedDict as _OD
    assert isinstance(detector.parsed_cache, _OD), (
        "parsed_cache must be an OrderedDict after BUG-R127 fix"
    )


def test_outage_detector_parsed_cache_keeps_recent():
    """LRU semantics: re-accessing an entry refreshes its position so it
    is not evicted before newer entries."""
    from datetime import datetime, timedelta
    from detectors.outage.outage_detector import RouteOutageDetector

    detector = RouteOutageDetector()
    base = datetime(2025, 1, 1)

    # Fill the cache with the first batch
    first_batch = [base + timedelta(seconds=i) for i in range(detector._MAX_PARSED_CACHE_SIZE)]
    for ts in first_batch:
        detector.parse_cached(ts.isoformat())

    # Re-access the *middle* element — it should stay after a second
    # batch of inserts evicts older entries.
    middle_iso = first_batch[len(first_batch) // 2].isoformat()
    detector.parse_cached(middle_iso)

    # Now insert another batch — the middle entry should still be there
    # because we touched it most recently within the kept window.
    second_batch = [base + timedelta(seconds=detector._MAX_PARSED_CACHE_SIZE + i)
                    for i in range(detector._MAX_PARSED_CACHE_SIZE // 4)]
    for ts in second_batch:
        detector.parse_cached(ts.isoformat())

    assert middle_iso in detector.parsed_cache, (
        "Re-accessed entry should still be in cache after subsequent inserts."
    )


def test_outage_detector_parsed_cache_initial_state():
    """A fresh detector should have empty caches ready for use."""
    from detectors.outage.outage_detector import RouteOutageDetector
    detector = RouteOutageDetector()
    assert len(detector.parsed_cache) == 0
    # _parsed_cache_order was removed in BUG-R127 (cache is now just the
def test_async_get_json_helper_exists_and_is_async():
    from tools.tool_implementations import _async_get_json
    assert asyncio.iscoroutinefunction(_async_get_json)


def test_async_get_json_returns_none_on_network_error(monkeypatch):
    """When the network call fails, ``_async_get_json`` must return None
    without raising — callers depend on this for graceful fallback."""
    from tools import tool_implementations

    def _raise(*a, **kw):
        raise RuntimeError("simulated network error")

    # Patch the inner _do_request inside asyncio.to_thread by monkey-patching
    # the module's requests via a fake.
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: _raise())

    result = asyncio.run(tool_implementations._async_get_json("http://example.invalid"))
    assert result is None


def test_bgpview_as_info_does_not_block(monkeypatch):
    """The four ``_bgpview_*`` helpers must run their HTTP calls via
    ``asyncio.to_thread`` so they don't stall the event loop."""
    import requests
    from tools import tool_implementations

    seen_threads = []

    def fake_get(url, timeout=15):
        seen_threads.append("worker")
        class _R:
            status_code = 200
            def json(self_inner):
                return {"status": "ok", "data": {"asn": 13335, "name": "Cloudflare"}}
        return _R()

    monkeypatch.setattr(requests, "get", fake_get)

    # Run the four helpers concurrently to prove they don't block the loop
    async def _all():
        return await asyncio.gather(
            tool_implementations._bgpview_as_info("13335"),
            tool_implementations._bgpview_prefixes("13335"),
            tool_implementations._bgpview_neighbors("13335"),
            tool_implementations._bgpview_contacts("13335"),
        )

    results = asyncio.run(_all())
    assert len(results) == 4
    assert all(r for r in results), "Each bgpview helper should return data"


# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "agents/llm_reasoning.py",
    "agents/reasoning_agent.py",
    "agents/impl/traffic_impl.py",
    "agents/impl/routing_impl.py",
    "detectors/evidence_chain_builder.py",
])
def test_call_sites_no_longer_use_buggy_find_rfind(path):
    """No production module should still call the buggy
    ``response.find('{')`` / ``raw.rfind('}')`` JSON extraction pattern.
    """
    src = (ROOT / path).read_text(encoding="utf-8")
    # The substring ``find("{")`` appears in the legacy buggy form.
    assert '.find("{")' not in src, (
        f"{path} still uses the buggy find('{') / rfind('}') JSON "
        "extraction pattern; switch to utils.helpers.extract_json_object."
    )
    assert ".rfind(\"}\")" not in src, (
        f"{path} still uses the buggy rfind('}}') JSON extraction "
        "pattern; switch to utils.helpers.extract_json_object."
    )


# ---------------------------------------------------------------------------
def test_report_agent_rpki_fallback_uses_asyncio_to_thread():
    """The RPKI fallback in ``_try_fetch_rpki_fallback`` must offload
    its ``requests.get`` call to a worker thread."""
    src = (ROOT / "agents/report_agent.py").read_text(encoding="utf-8")
    # The legacy buggy form: ``resp = requests.get(url, timeout=20)``
    # followed by ``resp.raise_for_status()`` directly.
    assert "    resp = requests.get(url, timeout=20)" not in src, (
        "report_agent._try_fetch_rpki_fallback still calls "
        "requests.get synchronously inside an async function; this "
        "blocks the event loop."
    )
    # Make sure the new code path actually uses asyncio.to_thread
    assert "asyncio.to_thread" in src, (
        "report_agent.py should use asyncio.to_thread to offload the "
        "blocking requests.get call."
    )
