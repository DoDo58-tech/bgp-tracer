"""Integration tests: verify the budget tracker is wired into the LLM call paths.

These tests mock the OpenAI client to count actual LLM calls and verify
that the budget guard fires before each call (raises BudgetExhausted
when the budget is exhausted).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))


pytestmark = pytest.mark.fast


def _mock_openai_response(content="mock"):
    """Build a MagicMock that looks like an OpenAI ChatCompletion."""
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = content
    response.choices[0].message.role = "assistant"
    response.usage.prompt_tokens = 10
    response.usage.completion_tokens = 20
    return response


def test_budget_guard_blocks_llm_complete_call():
    """When budget is exhausted, llm.complete() raises BudgetExhausted
    before doing any HTTP request."""
    os.environ["LLM_BUDGET_MAX_CALLS"] = "2"
    try:
        from llm import llm_factory as lf_mod
        lf_mod.get_budget_tracker().reset()

        llm = lf_mod.OpenAICompatibleLLM(
            model="glm-5", api_key="test", base_url="https://example.com/v1",
        )

        # Mock the client so we can detect any HTTP attempt
        with patch.object(llm, "_client", create=True) as mock_client:
            # First 2 calls: budget ok, mock returns content
            for i in range(2):
                llm._client = MagicMock()
                llm._client.chat.completions.create.return_value = _mock_openai_response(f"r{i}")
                result = llm.complete(f"prompt {i}")
                assert result.text == f"r{i}", f"call {i}: unexpected {result.text}"

            # 3rd call: budget exhausted, should raise BEFORE http call
            llm._client = MagicMock()
            with pytest.raises(lf_mod.BudgetExhausted):
                llm.complete("prompt 3")
            # Verify the mock HTTP was never called for the 3rd call
            assert not llm._client.chat.completions.create.called, "HTTP was attempted despite budget exhaustion"
    finally:
        os.environ.pop("LLM_BUDGET_MAX_CALLS", None)


def test_budget_guard_blocks_llm_chat_call():
    """Same as above but for llm.chat() (multi-message path)."""
    os.environ["LLM_BUDGET_MAX_CALLS"] = "1"
    try:
        from llm import llm_factory as lf_mod
        lf_mod.get_budget_tracker().reset()

        llm = lf_mod.OpenAICompatibleLLM(
            model="glm-5", api_key="test", base_url="https://example.com/v1",
        )

        # 1st call: ok
        llm._client = MagicMock()
        llm._client.chat.completions.create.return_value = _mock_openai_response("hi")
        llm.chat([{"role": "user", "content": "hello"}])
        assert llm._client.chat.completions.create.called

        # 2nd call: budget exhausted
        llm._client = MagicMock()
        with pytest.raises(lf_mod.BudgetExhausted):
            llm.chat([{"role": "user", "content": "hello"}])
        assert not llm._client.chat.completions.create.called
    finally:
        os.environ.pop("LLM_BUDGET_MAX_CALLS", None)


def test_budget_guard_blocks_streaming_call():
    """Budget guard also blocks streaming calls."""
    os.environ["LLM_BUDGET_MAX_CALLS"] = "1"
    try:
        from llm import llm_factory as lf_mod
        lf_mod.get_budget_tracker().reset()

        llm = lf_mod.OpenAICompatibleLLM(
            model="glm-5", api_key="test", base_url="https://example.com/v1",
        )

        # 1st streaming call: ok (mock returns empty iterator)
        llm._client = MagicMock()
        llm._client.chat.completions.create.return_value = iter([])
        list(llm.stream_chat([{"role": "user", "content": "hello"}]))
        assert llm._client.chat.completions.create.called

        # 2nd streaming call: budget exhausted
        llm._client = MagicMock()
        with pytest.raises(lf_mod.BudgetExhausted):
            list(llm.stream_chat([{"role": "user", "content": "hello"}]))
        assert not llm._client.chat.completions.create.called
    finally:
        os.environ.pop("LLM_BUDGET_MAX_CALLS", None)


def test_budget_tracker_records_successful_calls():
    """After successful calls, the tracker records them."""
    from llm import llm_factory as lf_mod
    lf_mod.get_budget_tracker().reset()

    llm = lf_mod.OpenAICompatibleLLM(
        model="glm-5", api_key="test", base_url="https://example.com/v1",
    )

    rem_before, _ = lf_mod.get_budget_tracker().remaining_budget()
    llm._client = MagicMock()
    llm._client.chat.completions.create.return_value = _mock_openai_response("ok")
    llm.complete("test")
    rem_after, _ = lf_mod.get_budget_tracker().remaining_budget()
    assert rem_after == rem_before - 1, "Successful call should decrement budget"
