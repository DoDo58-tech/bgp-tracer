"""Regression tests for Round 10 fixes.

Bug fixes validated here:

  * BUG-R44 (P0)  ``workflow_engine.async_retry``:
      Previously raised ``None`` when ``max_retries == 0`` because the
      post-loop statement was ``raise last_exception`` and ``last_exception``
      was still the initial ``None``. Also, ``max_retries=0`` skipped the
      function call entirely. The fix always invokes the wrapped function
      at least once (effective_attempts = max(max_retries, 1)) and only
      raises when a RetryableError was actually captured.

  * BUG-R45 (P1)  ``EvidenceChainBuilder._identify_evidence_gaps``:
      Previously named a local ``causal`` from
      ``traffic_result["multi_scale_analysis"]["is_anomaly"]`` and used it
      to decide whether causal-association evidence was missing — wrong
      data, wrong conclusion. Also, the caller in ``build()`` was passing
      only 2 args so the function couldn't see ``causal_analysis``. The
      fix renames the logic to use the actual ``causal_analysis`` dict.

  * BUG-R47 (P0)  ``tools.tool_implementations._parse_json``:
      Re-introduced ``raw.index("{") + raw.rindex("}") + 1`` fallback that
      truncates JSON when string values contain literal braces (e.g.
      ``"note": "{foo}"``). The fix swaps the legacy fallback for the
      brace-balanced ``extract_json_object``.

These tests are deterministic and exercise the exact regression paths.
"""

import asyncio
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ──────────────────────────── BUG-R44: async_retry ────────────────────────────


class _Sentinel(Exception):
    pass


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_async_retry_max_retries_zero_propagates_exception():
    """max_retries=0 should still invoke the function and propagate the first RetryableError."""

    from workflow_engine import async_retry, RetryableError

    calls = []

    @async_retry(max_retries=0)
    async def always_fails():
        calls.append(1)
        raise RetryableError("boom")

    with pytest.raises(RetryableError):
        _run(always_fails())
    assert len(calls) == 1, f"function should be invoked exactly once, got {len(calls)}"


def test_async_retry_max_retries_zero_with_success_returns_value():
    from workflow_engine import async_retry

    @async_retry(max_retries=0)
    async def just_succeeds():
        return "fast"

    assert _run(just_succeeds()) == "fast"


def test_async_retry_eventually_succeeds():
    from workflow_engine import async_retry, RetryableError

    counter = {"n": 0}

    @async_retry(max_retries=3, backoff_base=0.001)
    async def flaky():
        counter["n"] += 1
        if counter["n"] < 2:
            raise RetryableError("not yet")
        return "ok"

    assert _run(flaky()) == "ok"
    assert counter["n"] == 2


def test_async_retry_exhausts_and_raises_last():
    from workflow_engine import async_retry, RetryableError

    counter = {"n": 0}

    @async_retry(max_retries=2, backoff_base=0.001)
    async def always_fails():
        counter["n"] += 1
        raise RetryableError(f"attempt {counter['n']}")

    with pytest.raises(RetryableError) as ei:
        _run(always_fails())
    assert "attempt 2" in str(ei.value)
    assert counter["n"] == 2


def test_async_retry_non_retryable_exception_propagates_immediately():
    """Non-RetryableError exceptions should not be silently swallowed."""
    from workflow_engine import async_retry

    counter = {"n": 0}

    @async_retry(max_retries=5, backoff_base=0.001)
    async def raises_type_error():
        counter["n"] += 1
        raise _Sentinel("oops")

    with pytest.raises(_Sentinel):
        _run(raises_type_error())
    assert counter["n"] == 1, f"non-retryable error should NOT retry, got {counter['n']}"


# ──────────────────────────── BUG-R45: evidence gaps ──────────────────────────


def test_identify_evidence_gaps_uses_causal_analysis_parameter():
    """causal_analysis must drive the gap, not multi_scale_analysis.is_anomaly."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    eb = EvidenceChainBuilder()
    traffic = {"anomaly_count": 5, "data_available": True}
    routing = {"success": True}

    # No causal_analysis -> gap should appear
    gaps = eb._identify_evidence_gaps(traffic, routing, None)
    assert "缺少因果关联分析" in gaps

    # Empty dict -> gap should appear
    gaps = eb._identify_evidence_gaps(traffic, routing, {})
    assert "缺少因果关联分析" in gaps

    # has_association=True -> no gap
    gaps = eb._identify_evidence_gaps(
        traffic, routing, {"has_association": True, "association_score": 0.7},
    )
    assert "缺少因果关联分析" not in gaps

    # association_score alone -> no gap
    gaps = eb._identify_evidence_gaps(
        traffic, routing, {"association_score": 0.5},
    )
    assert "缺少因果关联分析" not in gaps


def test_identify_evidence_gaps_signature_accepts_causal_analysis():
    """Signature must accept the optional causal_analysis parameter."""
    import inspect
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    sig = inspect.signature(EvidenceChainBuilder._identify_evidence_gaps)
    assert "causal_analysis" in sig.parameters
    # Default should be None so old call sites still work
    assert sig.parameters["causal_analysis"].default is None


def test_build_propagates_causal_analysis_to_gap_detector():
    """When LLM is disabled and causal_analysis is supplied, the gap must be detected."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    eb = EvidenceChainBuilder()
    eb.use_llm = False
    eb.hypothesis_identifier = None

    chain = eb.build(
        traffic_result={"anomaly_count": 3, "data_available": True},
        routing_result={"success": True},
        causal_analysis=None,  # explicitly missing
    )

    assert any("因果关联" in g for g in chain.evidence_gaps), chain.evidence_gaps


# ──────────────────────────── BUG-R47: _parse_json ────────────────────────────


def test_parse_json_handles_braces_in_string_values():
    """Literal braces inside string values must not truncate the JSON."""
    from tools.tool_implementations import _parse_json

    # The legacy code `raw.index('{') + raw.rindex('}') + 1` would
    # produce ``{"a": "looks like {foo}` here and fail to parse.
    raw = '{"a": "looks like {foo} bar", "b": 2}'
    result = _parse_json(raw)
    assert result == {"a": "looks like {foo} bar", "b": 2}


def test_parse_json_handles_nested_braces():
    from tools.tool_implementations import _parse_json

    raw = '{"outer": {"inner": "value", "list": [1, 2, 3]}, "n": 1}'
    result = _parse_json(raw)
    assert result == {"outer": {"inner": "value", "list": [1, 2, 3]}, "n": 1}


def test_parse_json_strips_markdown_fences():
    from tools.tool_implementations import _parse_json

    raw = "```json\n{\"x\": 1}\n```"
    assert _parse_json(raw) == {"x": 1}


def test_parse_json_handles_trailing_prose():
    from tools.tool_implementations import _parse_json

    raw = "Here is the analysis: {\"y\": 2}. I hope this helps."
    assert _parse_json(raw) == {"y": 2}


def test_parse_json_returns_empty_dict_on_garbage():
    from tools.tool_implementations import _parse_json

    assert _parse_json("no json here at all") == {}
    assert _parse_json("") == {}
