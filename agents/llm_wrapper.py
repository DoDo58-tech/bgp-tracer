"""
Unified LLM call wrapper
========================

Every LLM call inside the agent pipeline should go through ``llm_complete``
so that:

  1. Token usage is recorded into ``TokenBudget`` (per run_id, no leakage).
  2. Errors are logged uniformly with agent / round context.
  3. ``record_llm_call`` is the only place that touches ``TokenBudget``.

This replaces ad-hoc ``self.llm.complete(...)`` scattered across agents,
which previously caused ``experiment_metrics.token_count`` to be near-empty
in default ``traffic_first`` mode.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from utils.logger import logger


def llm_complete(
    llm,
    prompt: Any,
    *,
    run_id: str,
    agent_name: str,
    json_mode: bool = False,
    max_retries: int = 2,
    timeout: Optional[float] = None,
    **kwargs,
) -> Any:
    """
    Wrap ``llm.complete`` with token-budget recording and uniform error handling.

    Args:
        llm: an LLM client exposing ``complete(prompt, ...)``.
        prompt: str or chat-format list.
        run_id: workflow run identifier (used by TokenBudget).
        agent_name: short name of the caller for token-budget attribution.
        json_mode, max_retries, timeout: forwarded to ``llm.complete``.
        **kwargs: forwarded to ``llm.complete``.

    Returns:
        The LLM response object. Token usage (if available) is recorded.
    """
    _t0 = time.perf_counter()
    try:
        response = llm.complete(
            prompt,
            json_mode=json_mode,
            max_retries=max_retries,
            timeout=timeout,
            **kwargs,
        )
    except Exception as exc:
        logger.error(f"[{agent_name}] LLM call failed: {type(exc).__name__}: {exc}")
        raise

    elapsed_ms = (time.perf_counter() - _t0) * 1000
    prompt_text = prompt if isinstance(prompt, str) else str(prompt)

    # Record token usage
    try:
        from agents.payload_builder import record_llm_call
        record_llm_call(run_id, agent_name, prompt_text, response)
    except Exception as exc:
        logger.debug(f"[{agent_name}] record_llm_call skipped: {exc}")

    logger.info(
        f"[{agent_name}] LLM call completed in {elapsed_ms:.0f}ms (run_id={run_id[:8] if run_id else 'n/a'})"
    )
    return response