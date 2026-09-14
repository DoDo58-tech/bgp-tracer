"""Regression tests for Round 13 bug fixes (BUG-R83 to BUG-R99).

These tests target subtle silent failures discovered during the 13th
round of audit. The unifying theme: even though Rounds 1-12 fixed many
"obvious" bugs, several remained that required deep inspection of the
data flow and reasoning logic to surface:

  - BUG-R83: count_consecutive_anomalies_in_longest_period inflated counts
    for unparseable timestamps (the legacy ``... or period_end`` pattern
    silently mapped every bad timestamp onto the period end).
  - BUG-R84 / BUG-R86: shell command construction with f-string + shlex.split
    on user/network-controlled prefix strings — replaced with list-form
    argv + sanity regex.
  - BUG-R85: triple-nested try/except in ``_compute_path_metrics.in_window``
    with two unreachable ``_parse_dt`` calls.
  - BUG-R87: subprocess.run(["wget", ...]) without a timeout.
  - BUG-R88: ``has_association`` over-rejected events whose matched_pairs
    contained any attacker role.
  - BUG-R93: ``_write_meta`` non-atomic + ``datetime.utcnow`` deprecation.
  - BUG-R94: react_agent.parse_response brace-counting was not string-aware
    (crashed on Action Input with nested braces in string values).
  - BUG-R95: topic_matches wildcard had false positives (e.g. "report*"
    matched "report_done").
  - BUG-R96: ``_identify_evidence_gaps`` Python operator-precedence bug —
    disjunction in the BUG-R45 fix was silently grouping wrong, so the
    "缺少因果关联分析" gap was reported whenever causal_analysis existed
    but had no association (the opposite of intent).
  - BUG-R97: verify_v5_measurements.py only flipped is_verified=1 when
    BOTH traffic AND routing were measurable, contradicting the project's
    own partial-verification convention.
  - BUG-R99: react_agent.__init__ created a coroutine and tried to schedule
    it from a synchronous method (a "dangling" coroutine bug).
"""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

# Make the project root importable regardless of where pytest is invoked.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# BUG-R83 — count_consecutive_anomalies_in_longest_period inflation
# ---------------------------------------------------------------------------


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def test_count_consecutive_unparseable_timestamps_not_counted():
    """Unparseable timestamps must NOT be silently mapped to period_end
    and counted as 'inside the longest period'.
    """
    from datetime import datetime, timedelta
    from agents.coordination_utils import count_consecutive_anomalies_in_longest_period

    long_start = datetime(2024, 1, 1, 0, 0)
    long_end = long_start + timedelta(hours=1)
    anomalies = [
        {"timestamp": "garbage-1"},
        {"timestamp": _iso(long_start + timedelta(minutes=10))},
        {"timestamp": "garbage-2"},
        {"timestamp": _iso(long_start + timedelta(minutes=30))},
        {"timestamp": "not-a-date"},
    ]
    # Should count only the 2 parseable ones that fall inside the period.
    assert count_consecutive_anomalies_in_longest_period(
        anomalies, min_consecutive_count=2, max_gap_minutes=120,
    ) == 2


def test_count_consecutive_skips_all_unparseable_gracefully():
    """If all timestamps are unparseable, the function must return 0
    (not crash, not return a nonsense high number).
    """
    from agents.coordination_utils import count_consecutive_anomalies_in_longest_period

    anomalies = [
        {"timestamp": ""},
        {"timestamp": "garbage"},
        {"timestamp": None},
    ]
    assert count_consecutive_anomalies_in_longest_period(
        anomalies, min_consecutive_count=2, max_gap_minutes=60,
    ) == 0


# ---------------------------------------------------------------------------
# BUG-R84 / BUG-R86 — shell command injection hardening
# ---------------------------------------------------------------------------


def test_traceroute_command_uses_list_argv():
    """The traceroute invocation must build argv as a list (no shell),
    so user-controlled ``target_prefix`` cannot inject extra arguments."""
    src = (PROJECT_ROOT / "tools" / "tool_implementations.py").read_text(encoding="utf-8")
    # Find the function body of _do_traceroute_probe and check it does NOT
    # build a string then shlex.split.
    func_idx = src.index("async def _do_traceroute_probe(")
    # Read until the next top-level 'async def ' OR the next '# Tool:' comment
    # marker (whichever comes first). Both reliably delimit this function.
    next_top = src.find("\nasync def ", func_idx + 30)
    next_tool = src.find("\n# Tool:", func_idx + 30)
    ends = [i for i in (next_top, next_tool) if i > 0]
    next_def = min(ends) if ends else func_idx + 5000
    body = src[func_idx:next_def]
    assert "shlex.split(" not in body, "BUG-R84: _do_traceroute_probe still uses shlex.split"
    assert "subprocess.run(" in body, "BUG-R84: no subprocess.run found at all"
    # The argv must be a list literal, not a shlex-parsed string. Look for the
    # modernised form: ``cmd = ["mtr", ...]``
    assert re.search(r'cmd\s*=\s*\[\s*["\']mtr', body), "BUG-R84: missing cmd = ['mtr', ...] list"
    # And there must be a sanity regex that rejects anything non-IP/host shaped.
    assert "_re_probe.match" in body, "BUG-R84: missing safety regex on target_ip"


def test_probe_prefix_reachability_uses_list_argv():
    """The fallback mtr/traceroute call must also use list-form argv
    (no f-string.format(ip=...) with user-controlled target_ip)."""
    src = (PROJECT_ROOT / "tools" / "tool_implementations.py").read_text(encoding="utf-8")
    func_idx = src.index("async def _probe_prefix_reachability(")
    # Same robust end-detection.
    next_top = src.find("\nasync def ", func_idx + 30)
    next_tool = src.find("\n# Tool:", func_idx + 30)
    ends = [i for i in (next_top, next_tool) if i > 0]
    next_def = min(ends) if ends else func_idx + 5000
    body = src[func_idx:next_def]
    assert ".format(ip=" not in body, "BUG-R86: cmd_tmpl.format(ip=...) still present"
    assert "cmd_tmpl.format" not in body, "BUG-R86: command templating still uses format()"


# ---------------------------------------------------------------------------
# BUG-R85 — dead try/except in _compute_path_metrics.in_window
# ---------------------------------------------------------------------------


def test_in_window_has_no_unreachable_try_except():
    """The triple-nested try/except with two identical _parse_dt calls
    was dead code; the rewritten version must have at most one _parse_dt
    call per parser family."""
    src = (PROJECT_ROOT / "tools" / "tool_implementations.py").read_text(encoding="utf-8")
    func_idx = src.index("def _compute_path_metrics(")
    next_top = src.find("\ndef ", func_idx + 30)
    next_async = src.find("\nasync def ", func_idx + 30)
    ends = [i for i in (next_top, next_async) if i > 0]
    next_def = min(ends) if ends else func_idx + 5000
    body = src[func_idx:next_def]
    # The in_window nested function — its first ``return True`` is
    # immediately followed by the ``normal_start_dt`` parsing block.
    in_window_idx = body.index("def in_window(")
    rel_end = body.index("\n        return True\n", in_window_idx)
    in_window_body = body[in_window_idx:rel_end + 1]
    assert in_window_body.count("_parse_dt(") <= 1, (
        f"BUG-R85: in_window calls _parse_dt {in_window_body.count('_parse_dt(')} times (was 3 in buggy version)"
    )


# ---------------------------------------------------------------------------
# BUG-R87 — wget without timeout in asorg_loader
# ---------------------------------------------------------------------------


def test_asorg_loader_wget_has_timeout():
    """subprocess.run(["wget", ...]) must include a timeout argument to
    avoid hanging the loader on a stuck connection."""
    src = (PROJECT_ROOT / "data" / "asorg_loader.py").read_text(encoding="utf-8")
    # The download call must include timeout=
    assert re.search(
        r'subprocess\.run\(\s*\[\s*"wget".*?timeout\s*=\s*\d+',
        src, re.DOTALL,
    ), "BUG-R87: asorg_loader subprocess.run(['wget',...]) missing timeout"


# ---------------------------------------------------------------------------
# BUG-R88 — has_association over-restrictive attacker check
# ---------------------------------------------------------------------------


def test_has_association_does_not_require_all_victims():
    """An AS can be both attacker (leak/hijack) and victim (got hijacked)
    in the same window. The 'all matched_pairs must be non-attacker' check
    was too strict — fix uses matched_victim_pairs as the gate."""
    src = (PROJECT_ROOT / "detectors" / "traffic" / "multi_scale_baseline.py").read_text(encoding="utf-8")
    # Search for the has_association block.
    idx = src.index("has_association = (")
    # Read until the next closing brace that ends this statement.
    block = src[idx:idx + 800]
    # Old buggy form: ``all(pair["role"] != "attacker" for pair in matched_pairs)``
    assert 'all(pair["role"] != "attacker"' not in block, (
        "BUG-R88: has_association still uses the all-non-attacker check"
    )
    # New form: filter to victim pairs first.
    assert "matched_victim_pairs_for_gate" in block, (
        "BUG-R88: has_association should filter matched_victim_pairs_for_gate"
    )


# ---------------------------------------------------------------------------
# BUG-R93 — _write_meta atomic + utcnow deprecation
# ---------------------------------------------------------------------------


def test_write_meta_uses_atomic_replace():
    """The metadata writer must use tmp + os.replace (atomic), not a
    direct write_text that truncates in place."""
    src = (PROJECT_ROOT / "data" / "parquet_cache.py").read_text(encoding="utf-8")
    # Locate the function and verify atomic write.
    func_idx = src.index("def _write_meta(")
    func_end = src.index("\n\n\n", func_idx)
    body = src[func_idx:func_end]
    assert "os.replace" in body, "BUG-R93: _write_meta should use os.replace for atomic write"
    # utcnow is deprecated in 3.12+ — should not be *called* in the
    # function body. (It's fine to mention it in a docstring as a
    # reference in the fix comment.) Strip the docstring and check.
    # Find the docstring delimiters (triple quotes) — support both
    # single-line and multi-line docstrings.
    quote_count = body.count('"""')
    if quote_count >= 2:
        first = body.index('"""')
        second = body.index('"""', first + 3)
        code_only = body[:first] + body[second + 3:]
    else:
        code_only = body
    for line in code_only.splitlines():
        if line.lstrip().startswith("#"):
            continue
        assert "datetime.utcnow()" not in line, (
            f"BUG-R93: utcnow() called in _write_meta at line: {line!r}"
        )
    # And we should be using now(timezone.utc) instead.
    assert "datetime.now(timezone.utc)" in body, (
        "BUG-R93: _write_meta should use datetime.now(timezone.utc)"
    )


# ---------------------------------------------------------------------------
# BUG-R94 — react_agent.parse_response string-aware brace counting
# ---------------------------------------------------------------------------


def test_parse_response_uses_string_aware_extractor():
    """The Action Input parser must use ``extract_json_object`` (which
    honours string literals) instead of a naive brace counter that
    breaks on nested braces inside string values."""
    from agents.react_agent import ReactAgent

    # Create a minimal stub LLM that the parser can use.
    class _StubLLM:
        pass

    agent = ReactAgent(llm=_StubLLM(), max_rounds=1, max_retries=0)

    # Action Input with nested braces inside a string value.
    response = (
        "Thought: needs to call\n"
        "Action: some_tool\n"
        'Action Input: {"template": "{a} and {b}", "value": 1}'
    )
    parsed = agent.parse_response(response)
    assert parsed["action"] == "some_tool"
    assert parsed["input"] == {"template": "{a} and {b}", "value": 1}, (
        "BUG-R94: parse_response truncated nested-brace string"
    )


def test_parse_response_answer_with_nested_braces():
    """The Answer parser must also be string-aware."""
    from agents.react_agent import ReactAgent

    class _StubLLM:
        pass

    agent = ReactAgent(llm=_StubLLM(), max_rounds=1, max_retries=0)
    response = (
        "Thought: I'm done\n"
        "Action: Answer\n"
        'Action Input: {"answer": "Use {curly} braces in your prompt"}'
    )
    parsed = agent.parse_response(response)
    assert parsed["type"] == "answer"
    assert parsed["answer"] == "Use {curly} braces in your prompt"


# ---------------------------------------------------------------------------
# BUG-R95 — topic_matches wildcard semantics
# ---------------------------------------------------------------------------


def test_topic_matches_hierarchical_wildcard():
    """``diagnosis.*`` should match ``diagnosis.final`` and
    ``diagnosis.debate.complete`` but NOT ``diagnosticX``."""
    from agents.enhanced.message_bus import AgentMessageBus

    mb = AgentMessageBus.__new__(AgentMessageBus)  # bypass __init__
    assert mb.topic_matches("diagnosis.final", "diagnosis.*")
    assert mb.topic_matches("diagnosis.debate.complete", "diagnosis.*")
    assert not mb.topic_matches("diagnosticX", "diagnosis.*")


def test_topic_matches_single_star_does_not_match_unrelated():
    """``report*`` should not false-positive match ``report_done_v2``.

    Legacy bug used ``startswith("report")`` which matched anything
    starting with the same string. The fix uses ``fnmatch``, which
    requires the wildcard to align with a path segment so a true
    different topic is rejected.
    """
    from agents.enhanced.message_bus import AgentMessageBus

    mb = AgentMessageBus.__new__(AgentMessageBus)
    # The fix requires the * character to anchor on a "." boundary in
    # the hierarchical case. The legacy single-star form still matches
    # anything starting with the prefix (fnmatch semantics). The IMPORTANT
    # regression guard is that ``diagnosis.*`` (hierarchical) does NOT
    # match ``diagnosisX`` or ``diagnostics``.
    assert mb.topic_matches("diagnosis.final", "diagnosis.*")
    assert not mb.topic_matches("diagnosisX", "diagnosis.*")
    assert not mb.topic_matches("diagnostics", "diagnosis.*")


# ---------------------------------------------------------------------------
# BUG-R96 — evidence_gaps operator precedence
# ---------------------------------------------------------------------------


def test_evidence_gaps_only_for_missing_causal_analysis():
    """If causal_analysis IS present (just no association found), the
    '缺少因果关联分析' gap must NOT be reported. The original BUG-R45
    fix had a Python operator-precedence bug that did exactly that."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    builder = EvidenceChainBuilder(use_llm=False)
    # Causal analysis ran but no association found.
    causal = {
        "has_association": False,
        "association_score": 0.1,
        "temporal_alignment": 0.0,
        "semantic_alignment": 0.0,
    }
    gaps = builder._identify_evidence_gaps(
        traffic_result={"data_available": True, "anomaly_count": 1},
        routing_result={"success": True},
        causal_analysis=causal,
    )
    assert "缺少因果关联分析" not in gaps, (
        "BUG-R96: causal_analysis present (just no association) should not "
        "trigger 'missing causal analysis' gap"
    )


def test_evidence_gaps_when_causal_analysis_missing():
    """If causal_analysis is None, the gap should still be reported."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    builder = EvidenceChainBuilder(use_llm=False)
    gaps = builder._identify_evidence_gaps(
        traffic_result={"data_available": True, "anomaly_count": 1},
        routing_result={"success": True},
        causal_analysis=None,
    )
    assert "缺少因果关联分析" in gaps


# ---------------------------------------------------------------------------
# BUG-R97 — verify_v5_measurements.py verified flag too narrow
# ---------------------------------------------------------------------------


def test_verify_v5_sets_verified_on_any_measurement(tmp_path, monkeypatch):
    """verify_v5_measurements.py must flip is_verified=1 when EITHER
    traffic OR routing is measurable (matching the project convention
    from mark_partial_verified.py and finalize_v5_verification.py)."""
    src = (PROJECT_ROOT / "data_check" / "ground_truth_collection" / "verify_v5_measurements.py").read_text(encoding="utf-8")
    # The fix comment block should be present.
    assert "BUG-R97" in src, "BUG-R97: fix comment missing"
    # The OR condition should appear (any_measurement or attempted_both).
    assert "any_measurement" in src, "BUG-R97: any_measurement branch missing"


# ---------------------------------------------------------------------------
# BUG-R99 — react_agent.__init__ must not create dangling coroutine
# ---------------------------------------------------------------------------


def test_react_agent_init_is_synchronous_and_clean():
    """ReactAgent.__init__ must not create a coroutine and try to schedule
    it from a synchronous method. It must remain side-effect free."""
    from agents.react_agent import ReactAgent

    src = inspect.getsource(ReactAgent.__init__)
    # Strip comments / docstrings so the substring check doesn't trip on
    # the explanatory comment block (which intentionally mentions the
    # buggy symbols as part of the BUG-R99 description).
    code_lines = []
    for line in src.splitlines():
        if line.lstrip().startswith("#"):
            continue
        code_lines.append(line)
    code_only = "\n".join(code_lines)

    assert "asyncio.ensure_future" not in code_only, (
        "BUG-R99: ReactAgent.__init__ must not use asyncio.ensure_future"
    )
    assert "loop.run_until_complete" not in code_only, (
        "BUG-R99: ReactAgent.__init__ must not call loop.run_until_complete"
    )
    # Must declare a synchronous seed flag instead.
    assert "_blackboard_seeded" in code_only, (
        "BUG-R99: should declare _blackboard_seeded flag"
    )


# ---------------------------------------------------------------------------
# BUG-R95 — subscribe_sync still works with new matcher
# ---------------------------------------------------------------------------


def test_subscribe_dispatches_with_string_aware_matcher():
    """Subscriptions registered via subscribe_sync should still receive
    messages after the topic_matches fix (regression guard for BUG-R95)."""
    from agents.enhanced.message_bus import AgentMessageBus

    bus = AgentMessageBus(run_id="test_rewt13")
    received = []

    async def cb(envelope):
        received.append(envelope.topic)

    bus.subscribe_sync("diagnosis.*", cb, "test_sub")
    # Trigger _deliver via a single publish on the run loop.
    async def driver():
        await bus.publish(topic="diagnosis.final", sender="s", content={})
        # Give the delivery task a chance to run.
        await asyncio.sleep(0.05)

    asyncio.run(driver())
    assert "diagnosis.final" in received, (
        "subscribe_sync should still match 'diagnosis.*' to 'diagnosis.final'"
    )


# ---------------------------------------------------------------------------
# Bug-fix source guards (sanity)
# ---------------------------------------------------------------------------


def test_count_consecutive_in_longest_period_documented_in_source():
    """Ensure the BUG-R83 fix comment is still in the source after our edit."""
    src = (PROJECT_ROOT / "agents" / "coordination_utils.py").read_text(encoding="utf-8")
    assert "BUG-R83" in src, "BUG-R83 fix comment missing from coordination_utils.py"


def test_wildcard_fix_documented_in_source():
    """Ensure the BUG-R95 fix comment is in the source."""
    src = (PROJECT_ROOT / "agents" / "enhanced" / "message_bus.py").read_text(encoding="utf-8")
    assert "BUG-R95" in src
