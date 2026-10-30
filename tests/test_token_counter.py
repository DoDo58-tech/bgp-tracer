"""Regression tests for the process-wide token counter.

Two defects are covered here, both of which made the per-run token
figures meaningless:

1. ``setup_llm_settings`` used to build and register a *new* counter on
   every call, and ``_record_token_usage_to_budget`` appends each
   response's usage to *every* registered counter. A pipeline that builds
   one model per stage (traffic, routing, reasoning, hypothesis, report)
   therefore reported roughly 5x its real spend.

2. ``setup_llm_settings`` also called ``reset_counts()`` on the shared
   counter. Since the function runs once per agent stage, each new stage
   wiped the spend of every earlier stage, so no per-run total could be
   reconstructed from the counter at all.

The fix is one canonical counter per process, registered once, never reset
by the setup path.
"""
from __future__ import annotations

import llm.llm_factory as F


def counter_impl():
    return F.build_token_counter()


def test_single_counter_per_process():
    """Repeated setup calls must not multiply the counter."""
    F._GLOBAL_TOKEN_HANDLER = None
    F._GLOBAL_TOKEN_HANDLERS.clear()

    first = F.build_token_counter()
    second = F.build_token_counter()

    assert first is second
    assert len(F._GLOBAL_TOKEN_HANDLERS) == 1
    assert F._GLOBAL_TOKEN_HANDLER is first


def test_setup_llm_settings_does_not_register_extra_handlers():
    """The setup path must not append the counter a second time."""
    F._GLOBAL_TOKEN_HANDLER = None
    F._GLOBAL_TOKEN_HANDLERS.clear()

    for _ in range(5):
        F.setup_llm_settings(
            model="qwen3.5", api_key="x", base_url="http://localhost:1"
        )

    assert len(F._GLOBAL_TOKEN_HANDLERS) == 1


def test_setup_llm_settings_does_not_reset_the_counter():
    """Setting up a later stage must not erase an earlier stage's spend."""
    F._GLOBAL_TOKEN_HANDLER = None
    F._GLOBAL_TOKEN_HANDLERS.clear()

    counter = F.build_token_counter()
    counter.reset_counts()

    # Simulate one completed call's usage.
    counter.llm_token_counts.append(
        type(
            "Ev",
            (),
            {
                "prompt_token_count": 100,
                "completion_token_count": 20,
                "total_token_count": 120,
            },
        )()
    )
    before = F.get_global_token_counter()
    assert before == 120

    # A new agent stage sets up its own model; the running total must survive.
    F.setup_llm_settings(
        model="qwen3.5", api_key="x", base_url="http://localhost:1"
    )

    assert F.get_global_token_counter() == before


def test_get_global_token_counter_is_not_double_counted():
    """The aggregate must not count the same usage twice."""
    F._GLOBAL_TOKEN_HANDLER = None
    F._GLOBAL_TOKEN_HANDLERS.clear()

    counter = F.build_token_counter()
    counter.reset_counts()
    counter.llm_token_counts.append(
        type(
            "Ev",
            (),
            {
                "prompt_token_count": 10,
                "completion_token_count": 5,
                "total_token_count": 15,
            },
        )()
    )

    assert F.get_global_token_counter() == 15
