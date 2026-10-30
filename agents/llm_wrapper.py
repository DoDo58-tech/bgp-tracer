"""Unified LLM call wrapper
========================"""

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
    """Wrap ``llm.complete`` with token-budget recording and uniform error handling.
    
    Returns:
    The LLM response object. Token usage (if available) is recorded."""
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
    except (AttributeError) as exc:
        logger.debug(f"[{agent_name}] record_llm_call skipped: {exc}")

    logger.info(
        f"[{agent_name}] LLM call completed in {elapsed_ms:.0f}ms (run_id={run_id[:8] if run_id else 'n/a'})"
    )
    return response