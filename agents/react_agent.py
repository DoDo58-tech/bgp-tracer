"""
React Agent - LLM-driven coordinator with streaming support
=========================================================

This module implements a ReAct (Reasoning + Acting) style agent that:
1. Uses LLM to decide next action based on current context
2. Executes tools and observes results
3. Feeds observations back to LLM for next decision
4. Supports streaming output for real-time feedback

The agent runs in a loop until the LLM decides to provide a final answer.
"""

from __future__ import annotations

import json
import re
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from llm.prompt import build_react_coordinator_prompt
from tools.tool_implementations import (
    _analyze_traffic as analyze_traffic,
    _analyze_routing as analyze_routing,
    _check_correlation as check_traffic_routing_correlation,
    _query_as_info as query_as_info,
    _reason_and_classify as reason_and_classify,
    _generate_report as generate_report,
    _analyze_prefix_traffic as analyze_prefix_traffic,
    _classify_traffic_anomaly as classify_traffic_anomaly,
    _compute_traffic_routing_correlation_score as compute_traffic_routing_correlation_score,
    _analyze_as_path_delta as analyze_as_path_delta,
    _analyze_as_relationships as analyze_as_relationships,
    _probe_prefix_reachability as probe_prefix_reachability,
    _validate_roa_status as validate_roa_status,
    _lookup_as_threat_intel as lookup_as_threat_intel,
)
from tools.threat_intelligence import _threat_intel_lookup as threat_intelligence_handler
from tools.news_context import _news_context_search as news_context_handler
from tools.irr_registry import _irr_registry_lookup as irr_registry_handler
from tools.historical_behavior import _historical_behavior_lookup as historical_behavior_handler
from utils.helpers import extract_json_object
from utils.logger import logger

# Maximum number of React rounds before forcing termination
DEFAULT_MAX_ROUNDS = 15

# Max retries per tool within a single round (when tool returns success=False)
DEFAULT_MAX_RETRIES = 2

# Available tools mapping
AVAILABLE_TOOLS = {
    "analyze_traffic": analyze_traffic,
    "analyze_routing": analyze_routing,
    "check_correlation": check_traffic_routing_correlation,
    "query_as_info": query_as_info,
    "reason_and_classify": reason_and_classify,
    "generate_report": generate_report,
    "analyze_prefix_traffic": analyze_prefix_traffic,
    "classify_traffic_anomaly": classify_traffic_anomaly,
    "compute_traffic_routing_correlation_score": compute_traffic_routing_correlation_score,
    "analyze_as_path_delta": analyze_as_path_delta,
    "analyze_as_relationships": analyze_as_relationships,
    "probe_prefix_reachability": probe_prefix_reachability,
    "validate_roa_status": validate_roa_status,
    "lookup_as_threat_intel": lookup_as_threat_intel,
    # New auxiliary tools for human-like investigation
    "threat_intelligence": threat_intelligence_handler,
    "news_context": news_context_handler,
    "irr_registry": irr_registry_handler,
    "historical_behavior": historical_behavior_handler,
}

# Shared evidence dict — populated by each tool execution so generate_report
# can read data from earlier tools in the same run.  Keys are run_id so
# parallel --parallel>1 invocations don't trample each other. Cleared when
# an agent.run() starts with a matching run_id.
_SHARED_EVIDENCE: Dict[str, Dict[str, Any]] = {}


def shared_evidence(run_id: str) -> Dict[str, Any]:
    """Get or create the per-run shared evidence bucket."""
    if run_id not in _SHARED_EVIDENCE:
        _SHARED_EVIDENCE[run_id] = {}
    return _SHARED_EVIDENCE[run_id]


def clear_shared_evidence(run_id: str) -> None:
    """Drop the per-run bucket after agent.run() finishes."""
    _SHARED_EVIDENCE.pop(run_id, None)


def _finalize_run(result: "ReactResult") -> "ReactResult":
    """Release per-run resources once a React run is done.

    Wrapping the cleanup behind a helper keeps every ``return ReactResult``
    branch in ``ReactAgent.run`` (and any future call site) honest about
    freeing ``_SHARED_EVIDENCE`` — without it, every analysis run leaves
    behind a full bucket of tool output that lives for the lifetime of
    the Python process.
    """
    try:
        clear_shared_evidence(getattr(result, "run_id", "") or "")
    except Exception:
        # Cleanup must never fail a finished run.
        pass
    return result


def valid_llm_html_report(report_path: str) -> bool:
    """Return True only for a saved, complete, non-fallback LLM HTML report.

    Checks:
    1. File exists and has sufficient content (>=300 bytes)
    2. Not a deterministic fallback
    3. Has proper DOCTYPE/html structure
    4. Has matching <html>...</html> tags
    5. CRITICAL: Has valid HTML tag structure (not missing '<' like 'div>' instead of '<div>')
    """
    if not report_path:
        return False
    try:
        html = Path(report_path).read_text(encoding="utf-8").strip()
    except OSError:
        return False
    lowered = html.lower()
    if len(html) < 300:
        return False
    if "deterministic fallback" in lowered:
        return False
    has_doctype = lowered.startswith("<!doctype") or lowered.startswith("<html")
    if not has_doctype or not ("</html>" in lowered or "<html" in lowered):
        return False

    # CRITICAL CHECK: Verify HTML tags have proper '<' prefix.
    # LLM (Qwen/GLM) often drops '<' from tags, producing 'div class="x">'
    # instead of '<div class="x">'. Such files display as raw text in browsers.
    #
    # Strategy: Strip CSS <style> blocks first (they contain tag-like patterns
    # that are NOT broken HTML), then check the remaining HTML for bare tags.

    # 1. Remove CSS <style>...</style> blocks (CSS contains tag selectors like
    #    `body { ... }` and `h1, h2 { ... }` which are not broken HTML).
    html_no_style = re.sub(r"<style\b[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)

    # 2. Now look for known HTML tag patterns that are NOT preceded by '<'.
    #    We use SIMPLE patterns with (?<!<) lookbehind to avoid false matches
    #    inside CSS or normal text. Each pattern is checked independently.
    broken_count = 0
    broken_examples = []

    # Patterns for "tag class=" / "tag id=" - these ALWAYS need a '<' in well-formed HTML
    check_patterns = [
        (r"(?<!<)div\s+class\s*=", "div class="),
        (r"(?<!<)div\s+id\s*=", "div id="),
        (r"(?<!<)h1\s+class\s*=", "h1 class="),
        (r"(?<!<)h2\s+class\s*=", "h2 class="),
        (r"(?<!<)h3\s+class\s*=", "h3 class="),
        (r"(?<!<)h4\s+class\s*=", "h4 class="),
        (r"(?<!<)h5\s+class\s*=", "h5 class="),
        (r"(?<!<)h6\s+class\s*=", "h6 class="),
        (r"(?<!<)p\s+class\s*=", "p class="),
        (r"(?<!<)span\s+class\s*=", "span class="),
        (r"(?<!<)span\s+id\s*=", "span id="),
        (r"(?<!<)table\s+class\s*=", "table class="),
        (r"(?<!<)tr\s+class\s*=", "tr class="),
        (r"(?<!<)td\s+class\s*=", "td class="),
        (r"(?<!<)th\s+class\s*=", "th class="),
        (r"(?<!<)thead\s+class\s*=", "thead class="),
        (r"(?<!<)tbody\s+class\s*=", "tbody class="),
        (r"(?<!<)ul\s+class\s*=", "ul class="),
        (r"(?<!<)ol\s+class\s*=", "ol class="),
        (r"(?<!<)li\s+class\s*=", "li class="),
        (r"(?<!<)section\s+class\s*=", "section class="),
        (r"(?<!<)article\s+class\s*=", "article class="),
        (r"(?<!<)header\s+class\s*=", "header class="),
        (r"(?<!<)footer\s+class\s*=", "footer class="),
        (r"(?<!<)main\s+class\s*=", "main class="),
    ]
    for pat, label in check_patterns:
        count = len(re.findall(pat, html_no_style))
        if count > 0:
            broken_count += count
            if len(broken_examples) < 5:
                broken_examples.append(f"{label}x{count}")

    # 3. Also detect broken close tags - "/tag>" without leading '<'
    _BROKEN_CLOSE_RE = re.compile(
        r"(?<![\w</])"  # NOT preceded by word, '<', or '/'
        r"/(?:div|p|table|tr|td|th|thead|tbody|ul|ol|li|section|"
        r"article|header|footer|main|body|head|html|span|strong|em|code|pre|h[1-6])>"
    )
    close_matches = _BROKEN_CLOSE_RE.findall(html_no_style)
    if close_matches:
        broken_count += len(close_matches)
        if len(broken_examples) < 5:
            broken_examples.append(f"/tag>x{len(close_matches)}")

    if broken_count > 3:
        logger.warning(
            f"[valid_llm_html_report] {report_path} appears broken: "
            f"found {broken_count} bare tag patterns without '<' prefix. "
            f"Examples: {', '.join(broken_examples)}"
        )
        return False

    return True

# ── DEPRECATED globals ──────────────────────────────────────────────────────────
# These module-level variables are maintained only for backward compatibility
# with any external code that still reads them via sys.modules.  New code
# MUST NOT read them.  Instead, pass `run_context` explicitly to tools via
# `_SessionShim.run_context` (set from ReactAgent instance attributes).
# Using these globals makes concurrent runs and re-entrancy unsafe.
_RUN_ASN: str = ""
_RUN_START: str = ""
_RUN_END: str = ""


@dataclass
class ReactTraceEntry:
    """Single step in the ReAct reasoning trace."""
    round_num: int
    thought: str = ""
    action: str = ""
    action_input: Dict[str, Any] = field(default_factory=dict)
    observation: str = ""
    error: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ReactResult:
    """Result of React agent execution."""
    success: bool
    answer: str = ""
    report_path: str = ""
    trace: List[ReactTraceEntry] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    error: str = ""
    total_rounds: int = 0
    # 添加 evidence 字段，携带 run() 期间的完整工具输出。
    evidence: Dict[str, Any] = field(default_factory=dict)
    # run_id 让外部消费者（chief_agent 等）能定位对应的共享 evidence bucket。
    run_id: str = ""


class StreamingBuffer:
    """Accumulates streaming chunks for real-time display."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None):
        self.callback = callback
        self.content = ""

    def write(self, chunk: str):
        """Write a chunk and optionally notify callback."""
        self.content += chunk
        if self.callback:
            self.callback(chunk)

    def flush(self):
        """Flush any pending content."""
        if self.callback:
            self.callback("")


class ReactAgent:
    """
    React-style coordinator agent with streaming support.

    The agent runs a Think -> Action -> Observe loop where:
    - Think: LLM reasons about what to do next
    - Action: LLM calls a tool or provides final answer
    - Observe: Tool result is fed back to LLM for next decision

    Args:
        llm: LLM instance for reasoning
        max_rounds: Maximum number of React rounds (default: 15)
        streaming_callback: Optional callback for streaming output
    """

    def __init__(
        self,
        llm,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        streaming_callback: Optional[Callable[[str], None]] = None,
        precomputed_routing: Optional[dict] = None,
        precomputed_traffic: Optional[dict] = None,
        enhanced: bool = False,
    ):
        self.llm = llm
        # If the upstream LLM is unreachable / disabled, collapse the ReAct
        # loop so we don't burn time on per-round calls that will all fail.
        # The agent will still run one round and emit whatever evidence was
        # gathered before the LLM was called.
        import os
        if os.environ.get("BGP_TRACER_DISABLE_LLM_REPORT", "").strip() in ("1", "true", "yes"):
            max_rounds = min(max_rounds, 2)
            max_retries = 1
        self.max_rounds = max_rounds
        self.max_retries = max_retries
        self.MAX_CONTEXT_CHARS = int(os.environ.get("REACT_MAX_CONTEXT_CHARS", "50000"))
        self.OBSERVATION_MAX_CHARS = int(os.environ.get("REACT_OBSERVATION_MAX_CHARS", "4000"))
        self.streaming_callback = streaming_callback
        self.precomputed_routing = precomputed_routing
        self.precomputed_traffic = precomputed_traffic
        # enhanced 模式启用 LLMDebateAgent + MultiAgentReportAgent
        self.enhanced = enhanced
        self._evidence: Dict[str, Any] = {}
        self.trace: List[ReactTraceEntry] = []
        self.tools_used: set = set()
        self._round = 0
        import uuid as _uuid
        self.run_id: str = str(_uuid.uuid4())
        self._asn: str = ""
        self._start_time: str = ""
        self._end_time: str = ""

        # ── enhanced 模式共用 Blackboard ────────────────────────────────────────
        # Create a blackboard BEFORE the loop so LLMDebateAgent can read claims/
        # routing/traffic written progressively by tools. The blackboard is the
        # same shared-memory substrate the traffic_first_enhanced workflow uses,
        # which is why debate results are now interoperable between the two
        # enhanced modes.
        self._blackboard = None
        if self.enhanced:
            try:
                from agents.core import Blackboard as _BB
                # Bug fix 2026-09-13 (BUG-R98): the previous code created
                # a coroutine inside __init__ and tried to schedule or
                # run it from this synchronous method. ``asyncio.ensure_future``
                # would only schedule it without awaiting, leaving a
                # "dangling" coroutine that may never complete before the
                # agent starts; ``loop.run_until_complete`` is unsafe to
                # call from inside a running loop; and the silent defer
                # path meant the seed never ran. ``__init__`` must remain
                # synchronous and side-effect free — defer the blackboard
                # seeding to the first awaitable method (``run``) where a
                # proper event loop is guaranteed.
                self._blackboard = _BB()
                # Placeholder so downstream code can check existence without
                # relying on the agent being "fully seeded". The actual
                # seeding happens in ``_ensure_blackboard_seeded`` at the
                # top of ``run``.
                self._blackboard_seeded = False
            except Exception as e:
                logger.warning(f"[ReactAgent] Blackboard init failed: {e}; "
                               f"debate will fall back to dict-based evidence.")
                self._blackboard = None
                self._blackboard_seeded = False

    async def run(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        user_input: Optional[str] = None,
    ) -> ReactResult:
        """
        Run the React agent to analyze the given AS and time window.

        Args:
            asn: Autonomous System number
            start_time: Analysis window start (ISO format)
            end_time: Analysis window end (ISO format)
            user_input: Optional natural language request

        Returns:
            ReactResult with answer and trace
        """
        self.trace = []
        self.tools_used = set()
        self._round = 0
        report_path = ""

        # Reset instance evidence so each run starts clean (fixes concurrent run contamination)
        self._evidence.clear()

        # Store run context as instance attributes — explicit and thread-safe.
        # The legacy module globals (_RUN_ASN etc.) are still written for
        # backward-compat with any external reader, but new code MUST use
        # session.run_context instead.
        self._asn = asn or ""
        self._start_time = start_time or ""
        self._end_time = end_time or ""
        global _RUN_ASN, _RUN_START, _RUN_END
        _RUN_ASN = self._asn
        _RUN_START = self._start_time
        _RUN_END = self._end_time

        # enhanced 模式：把运行上下文写入 Blackboard 让辩论 Agent 能拿到
        if self.enhanced and self._blackboard is not None:
            try:
                await self._blackboard.update_section(
                    "config",
                    {
                        "asn": self._asn,
                        "start_time": self._start_time,
                        "end_time": self._end_time,
                    },
                )
                # Mark the blackboard as seeded so any post-run debug
                # logging can confirm the BUG-R98 fix took effect.
                self._blackboard_seeded = True
            except Exception as e:
                logger.debug(f"[ReactAgent] bb config seed at run start failed: {e}")

        # ── Pre-inject pre-computed evidence (annotation_package) ────────────
        # When the orchestrator passes precomputed_routing/traffic, populate
        # the per-run shared evidence dict so the corresponding tool calls become
        # cheap cache lookups instead of running live BGP detection (which
        # can take 10+ minutes on ASes with thousands of announcements).
        bucket = shared_evidence(self.run_id)
        if self.precomputed_routing:
            self._evidence["precomputed_routing"] = self.precomputed_routing
            bucket["precomputed_routing"] = self.precomputed_routing
            logger.info(f"[ReactAgent] Injected precomputed_routing "
                        f"({len(str(self.precomputed_routing))//1024} KB, run_id={self.run_id[:8]})")
        if self.precomputed_traffic:
            self._evidence["precomputed_traffic"] = self.precomputed_traffic
            bucket["precomputed_traffic"] = self.precomputed_traffic

        # Track routing + traffic results for InvestigationSupervisor auto-trigger
        self._traffic_result: Optional[dict] = None
        self._routing_result: Optional[dict] = None
        self._supervisor_enrichment_done: bool = False
        self._supervisor_enrichment_result: Optional[dict] = None

        # Build initial context
        context = self.build_initial_context(asn, start_time, end_time, user_input)

        # React loop
        for round_num in range(self.max_rounds):
            self._round = round_num + 1
            entry = ReactTraceEntry(round_num=self._round)
            self.trace.append(entry)

            # Step 1: LLM Think
            self.stream_print(f"\n{'='*60}\n")
            self.stream_print(f"Round {self._round}/{self.max_rounds}\n")
            self.stream_print(f"{'='*60}\n\n")

            response = await self.llm_think(context)
            entry.thought = response
            logger.info(f"[ReAct][Round {self._round}] Thought: {response}")

            # Step 2: Parse Action or Answer
            parsed = self.parse_response(response)

            if parsed["type"] == "answer":
                self.stream_print(f"\n[Final Answer]\n{parsed['answer']}\n")

                # 当 LLM 直接输出 Answer 时，也要检查是否需要运行
                # InvestigationSupervisor 自动增强。
                if (
                    not self._supervisor_enrichment_done
                    and self._traffic_result is not None
                    and self._routing_result is not None
                ):
                    logger.info("[ReAct] Answer reached before supervisor enrichment — running it now")
                    try:
                        context_for_supervisor = ""
                        context_for_supervisor = await self.run_supervisor_enrichment(
                            context_for_supervisor, self._asn, self._traffic_result, self._routing_result
                        )
                        self._supervisor_enrichment_done = True
                        # Supervisor enrichment 结果不会被写回 Answer（Answer 已由 LLM 给出），
                        # 但 enrich_result 可以通过 self._supervisor_enrichment_result 传递给 generate_report。
                        logger.info("[ReAct] Supervisor enrichment complete before Answer return")
                    except Exception as e:
                        logger.warning(f"[ReAct] Supervisor enrichment in Answer path failed: {e}")

                # Generate HTML report even when LLM directly outputs Answer
                # (LLM often skips calling generate_report, so we auto-generate it)
                if "generate_report" not in self.tools_used and self._evidence:
                    try:
                        inp = {
                            "asn": self._asn or None,
                            "start_time": self._start_time or None,
                            "end_time": self._end_time or None,
                        }
                        report_result = await self.execute_tool("generate_report", inp)
                        candidate_path = report_result.get("report_path", "")
                        if report_result.get("success") and valid_llm_html_report(candidate_path):
                            report_path = candidate_path
                            logger.info(f"[ReAct] Auto-generated verified LLM report: {report_path}")
                        elif report_result.get("success"):
                            logger.error("[ReAct] Auto-generated report failed HTML acceptance checks")
                    except Exception as e:
                        logger.error(f"[ReAct] Auto report generation failed: {e}")
                
                return _finalize_run(ReactResult(
                    success=True,
                    answer=parsed["answer"],
                    trace=self.trace,
                    tools_used=list(self.tools_used),
                    total_rounds=self._round,
                    evidence=dict(self._evidence),
                    run_id=self.run_id,
                ))

            # Step 3: Execute tool with retry on failure
            action_name = parsed["action"]
            action_input = parsed["input"]
            # Bug #9 fix: if LLM produced an empty action (e.g. JS safety guard
            # refused the role), pick the next sensible tool so the workflow
            # doesn't loop forever on "Unknown tool: .".
            if not action_name:
                action_name, action_input = self._pick_fallback_action(context)
                logger.warning(
                    f"[ReAct][Round {self._round}] empty action → fallback to "
                    f"'{action_name}' with input={action_input}"
                )
            entry.action = action_name
            entry.action_input = action_input
            retry_count = 0
            tool_failed = False

            while retry_count <= self.max_retries:
                self.stream_print(f"\n[Action] {action_name}\n")
                self.stream_print(f"[Input] {json.dumps(action_input, ensure_ascii=False, indent=2)}\n\n")
                logger.info(f"[ReAct][Round {self._round}] Action: {action_name}")
                logger.info(f"[ReAct][Round {self._round}] Action Input: {json.dumps(action_input, ensure_ascii=False)}")

                try:
                    result = await self.execute_tool(action_name, action_input)
                    entry.observation = self.format_observation(result)
                    self.stream_print(f"[Observation]\n{entry.observation}\n")
                    logger.info(f"[ReAct][Round {self._round}] Observation: {entry.observation}")

                    # Tool succeeded — update context and proceed to next round
                    context = self.update_context(context, entry)

                    # ── Track routing/traffic results for Supervisor ─────────────────
                    # Cache results so we can run enrichment once both are available
                    if action_name == "analyze_traffic":
                        self._traffic_result = result
                    elif action_name == "analyze_routing":
                        self._routing_result = result

                    # Auto-trigger InvestigationSupervisor once both traffic + routing are done
                    if (
                        not self._supervisor_enrichment_done
                        and self._traffic_result is not None
                        and self._routing_result is not None
                    ):
                        context = await self.run_supervisor_enrichment(
                            context, asn, self._traffic_result, self._routing_result
                        )
                        self._supervisor_enrichment_done = True

                    # Check if we should stop early (report generated)
                    if action_name == "generate_report" and result.get("success"):
                        candidate_path = result.get("report_path", "")
                        if not valid_llm_html_report(candidate_path):
                            return _finalize_run(ReactResult(
                                success=False,
                                answer=entry.observation,
                                trace=self.trace,
                                tools_used=list(self.tools_used),
                                total_rounds=self._round,
                                error="generate_report did not produce an acceptable LLM HTML file",
                                evidence=dict(self._evidence),
                                run_id=self.run_id,
                            ))
                        return _finalize_run(ReactResult(
                            success=True,
                            answer=candidate_path,
                            report_path=candidate_path,
                            trace=self.trace,
                            tools_used=list(self.tools_used),
                            total_rounds=self._round,
                            evidence=dict(self._evidence),
                            run_id=self.run_id,
                        ))
                    break  # normal exit from retry loop

                except Exception as e:
                    error_msg = f"Tool execution error: {str(e)}\n{traceback.format_exc()}"
                    entry.error = error_msg
                    self.stream_print(f"[Error] {error_msg}\n")
                    logger.error(f"[ReAct][Round {self._round}] Tool exception: {e}")
                    tool_failed = True
                    # Honour max_retries so transient errors (network, resource
                    # contention) can recover instead of silently killing the round.
                    if retry_count < self.max_retries:
                        retry_count += 1
                        logger.warning(
                            f"[ReAct][Round {self._round}] Tool '{action_name}' raised, "
                            f"retrying ({retry_count}/{self.max_retries})"
                        )
                        context = self.update_context_with_retry(
                            context, entry, action_name, {"error": str(e)}
                        )
                        try:
                            response = await self.llm_think(context)
                            entry.thought += f"\n[Retry {retry_count}] Thought: {response}"
                            parsed = self.parse_response(response)
                            if parsed.get("type") == "action":
                                action_name = parsed["action"]
                                action_input = parsed.get("input", {})
                                # Bug fix 2026-09-13 (BUG-R79): ``self.trace``
                                # is a plain ``List[ReactTraceEntry]`` and
                                # does not have an ``add_entry`` method
                                # (only ``append``). The previous code
                                # called the missing method, which raised
                                # ``AttributeError`` every time the retry
                                # path executed — the exception was caught
                                # by the outer ``except Exception`` and
                                # silently logged as ``Retry think
                                # failed``, so the retry never actually
                                # appended the new entry nor ``continue``d
                                # the retry loop. It fell through to the
                                # ``break`` and the outer round exited,
                                # losing the partial retry state.
                                new_entry = ReactTraceEntry(
                                    round_num=self._round,
                                    thought=parsed.get("thought", response),
                                    action=action_name,
                                    action_input=action_input,
                                )
                                self.trace.append(new_entry)
                                entry = new_entry
                                continue
                        except Exception as retry_err:
                            logger.error(
                                f"[ReAct][Round {self._round}] Retry think failed: {retry_err}"
                            )
                        # If we couldn't form a new action, fall through to outer
                        # round handler so the round terminates cleanly.
                    break  # exit retry loop after exception (or retries exhausted)

                # Check if tool returned success=False (e.g. bad params) — retry allowed
                if result.get("success") is False and retry_count < self.max_retries:
                    retry_count += 1
                    tool_failed = True
                    logger.warning(f"[ReAct][Round {self._round}] Tool '{action_name}' returned failure, retrying ({retry_count}/{self.max_retries})")
                    self.stream_print(f"\n[Retry] Tool '{action_name}' returned an error. Retrying with corrected parameters ({retry_count}/{self.max_retries})...\n")
                    # Force a new LLM think for this round with the error context
                    context = self.update_context_with_retry(context, entry, action_name, result)
                    response = await self.llm_think(context)
                    entry.thought += f"\n[Retry {retry_count}] Thought: {response}"
                    logger.info(f"[ReAct][Round {self._round}] Retry {retry_count} Thought: {response}")
                    parsed = self.parse_response(response)
                    if parsed["type"] == "answer":
                        self.stream_print(f"\n[Final Answer]\n{parsed['answer']}\n")
                        
                        # Generate HTML report even when LLM directly outputs Answer
                        if "generate_report" not in self.tools_used and self._evidence:
                            try:
                                inp = {
                                    "asn": _RUN_ASN or None,
                                    "start_time": _RUN_START or None,
                                    "end_time": _RUN_END or None,
                                }
                                report_result = await self.execute_tool("generate_report", inp)
                                if report_result.get("success"):
                                    logger.info(f"[ReAct] Auto-generated report: {report_result.get('report_path', '')}")
                            except Exception as e:
                                logger.error(f"[ReAct] Auto report generation failed: {e}")
                        
                        return _finalize_run(ReactResult(
                            success=True,
                            answer=parsed["answer"],
                            trace=self.trace,
                            tools_used=list(self.tools_used),
                            total_rounds=self._round,
                            # Bug fix 2026-09-13 (BUG-R55): previously this
                            # retry-after-answer return path dropped
                            # ``evidence`` and ``run_id``. As a result, when
                            # a tool returned ``success=False`` and the
                            # follow-up retry thought decided to answer,
                            # the chief_agent's HCAF post-processing
                            # (``_post_react_hcaf``) read an empty evidence
                            # dict and ran HCAF over an unrelated fallback.
                            # Mirror the same fields every other return
                            # site includes so the result shape is
                            # consistent.
                            evidence=dict(self._evidence),
                            run_id=self.run_id,
                        ))
                    action_name = parsed["action"]
                    action_input = parsed.get("input", {})
                    entry.action = action_name
                    entry.action_input = action_input
                    self.trace[-1] = entry
                else:
                    # No more retries or tool succeeded
                    break

        # Max rounds reached — generate report from whatever evidence was collected
        logger.warning(f"[ReAct] Max rounds ({self.max_rounds}) reached, forcing report generation")
        bucket = shared_evidence(self.run_id)
        if "generate_report" not in self.tools_used and bucket:
            try:
                inp = {
                    "asn": _RUN_ASN or None,
                    "start_time": _RUN_START or None,
                    "end_time": _RUN_END or None,
                }
                result = await self.execute_tool("generate_report", inp)
                if result.get("success"):
                    logger.info(f"[ReAct] Forced report generated: {result.get('report_path', '')}")
            except Exception as e:
                logger.error(f"[ReAct] Forced report generation failed: {e}")

        return _finalize_run(ReactResult(
            success=False,
            answer="Maximum rounds reached without final answer.",
            trace=self.trace,
            tools_used=list(self.tools_used),
            total_rounds=self._round,
            error=f"Reached max rounds ({self.max_rounds})",
            evidence=dict(self._evidence),
                            run_id=self.run_id,
        ))

    async def llm_think(self, context: str) -> str:
        """Send context to LLM and get response (with streaming)."""
        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": context},
        ]

        try:
            # Try streaming first
            if hasattr(self.llm, "stream_chat"):
                full_response = ""
                async for chunk in self.stream_chat(messages):
                    full_response += chunk
                return full_response
            else:
                # Fallback to non-streaming
                response = self.llm.chat(messages)
                return response.message.content
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            raise

    async def stream_chat(self, messages) -> str:
        """Stream chat response chunk by chunk."""
        try:
            stream = self.llm.stream_chat(messages)
            for chunk in stream:
                if hasattr(chunk, "delta") and chunk.delta:
                    content = chunk.delta
                elif hasattr(chunk, "message") and chunk.message:
                    content = chunk.message.content or ""
                else:
                    content = str(chunk)

                self.stream_print(content)
                yield content
        except Exception as e:
            logger.error(f"Stream chat failed: {e}")
            # Fallback to non-streaming
            response = self.llm.chat(messages)
            content = response.message.content
            self.stream_print(content)
            yield content

    def stream_print(self, content: str):
        """Send content to streaming callback if available."""
        if self.streaming_callback and content:
            try:
                self.streaming_callback(content)
            except Exception as e:
                logger.warning(f"Streaming callback error: {e}")

    def get_system_prompt(self) -> str:
        """Get the React coordinator system prompt."""
        prompt_template = build_react_coordinator_prompt()
        tools_description = self.format_tools_description()
        return prompt_template.format(available_tools=tools_description)

    def format_tools_description(self) -> str:
        """Format available tools with parameters for the prompt."""
        tool_descriptions = []
        tool_params = {
            "analyze_traffic": "  Params: asn (str|list), start_time, end_time, country (optional)",
            "analyze_routing": "  Params: asn, start_time, end_time, detail_level ('light'=fast/skips leak+outage detection, 'full'=comprehensive, default 'light')",
            "check_correlation": "  Params: asn, start_time, end_time, traffic_result (optional), routing_result (optional)",
            "query_as_info": "  Params: asn",
            "reason_and_classify": "  Params: asn, traffic_result, routing_result, asn_info (optional)",
            "generate_report": "  Params: asn, start_time, end_time",
            "analyze_prefix_traffic": "  Params: prefixes, hijacker_asn, victim_asn, start_time, end_time (auto-extracts from routing_result)",
            "classify_traffic_anomaly": "  Params: traffic_result, routing_result (optional), victim_prefix_traffic (optional)",
            "compute_traffic_routing_correlation_score": "  Params: traffic_result, routing_result, victim_traffic (optional), prefix_traffic (optional)",
            "analyze_as_path_delta": "  Params: routing_result, start_time, end_time (auto-detects historical vs recent, skips traceroute for old events)",
            "analyze_as_relationships": "  Params: attacker_asn, victim_asn, start_time (uses CAIDA as-rel data + AS-path inference)",
            "probe_prefix_reachability": "  Params: prefixes, start_time, end_time (time-aware: live traceroute for recent, RIPE RIS+Looking Glass for historical)",
            "validate_roa_status": "  Params: announcements (or auto-extract from routing_result), validates prefix+origin against RPKI ROA (Cloudflare API, 5-min cache)",
            "lookup_as_threat_intel": "  Params: attacker_asn, victim_asn (optional), BGPView.io + historical hijack evidence + risk scoring",
            # New auxiliary tools
            "threat_intelligence": "  Params: asn, prefix (optional), check_asn_history (bool, default True). "
                                  "Checks Spamhaus DROP/EDROP, CINS, GRIP historical incidents, Team Cymru. "
                                  "Use when: you detect a suspicious AS and want to know if it's a known bad actor.",
            "news_context": "  Params: asn, event_type (origin_hijack/route_leak/outage/unknown), "
                            "prefix (optional), country (optional). "
                            "Searches DuckDuckGo + RIPE NCC incident reports. "
                            "Use when: you want to verify if this was a real incident and find the root cause.",
            "irr_registry": "  Params: asn, prefix (optional), servers (list, default ['RADB','RIPE','APNIC']). "
                             "Queries IRR databases for registered prefixes and routing policy. "
                             "Use when: you detect a hijack and want to know if the prefix was legitimately authorized.",
            "historical_behavior": "  Params: asn, timeframe_days (default 730). "
                                  "Checks BGPView events + RIPEstat + local ground truth. "
                                  "Identifies repeat offenders vs first-time offenders. "
                                  "Use when: you detect a hijack and want to know if this AS has done this before.",
        }
        for name in AVAILABLE_TOOLS:
            desc = tool_params.get(name, "")
            tool_descriptions.append(f"- {name}{desc}")
        return "\n".join(tool_descriptions)

    def build_initial_context(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        user_input: Optional[str] = None,
    ) -> str:
        """Build the initial context for React analysis."""
        context = f"""## Analysis Request

AS Number: {asn}
Time Window: {start_time} to {end_time}
"""

        if user_input:
            context += f"\nUser Request: {user_input}\n"

        context += f"""
## Available Tools
{self.format_tools_description()}

## Your Task
Analyze the BGP security for AS{asn} in the given time window.
Use the ReAct format (Thought/Action/Action Input) to decide your next step.

Begin by using query_as_info to understand the target AS, then proceed with analysis.
"""
        return context

    def parse_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response into thought, action, and input.

        Expected formats:
        - Thought: ... Action: tool_name Action Input: {{"param": "value"}}
        - Thought: ... Action: Answer Action Input: {{"answer": "final answer"}}
        """
        result = {
            "type": "unknown",
            "thought": "",
            "action": "",
            "input": {},
            "answer": "",
        }

        # Extract Thought
        thought_match = re.search(
            r"Thought:\s*(.+?)(?=\nAction:|\nAction Input:|$)",
            response,
            re.DOTALL,
        )
        if thought_match:
            result["thought"] = thought_match.group(1).strip()

        # Extract Action
        action_match = re.search(r"Action:\s*(\w+)", response)
        if action_match:
            result["action"] = action_match.group(1).strip()

        # Check if it's a final Answer
        if result["action"].lower() == "answer":
            result["type"] = "answer"
            # Extract Action Input using string-aware brace counting.
            # Bug fix 2026-09-13 (BUG-R94): see the parallel fix below
            # for the non-answer Action Input branch — same string-
            # awareness issue applied here.
            input_match = re.search(r"Action Input:\s*(?:```json\s*)?", response)
            if input_match:
                json_start = input_match.end()
                json_text = extract_json_object(response[json_start:]) or response[json_start:].strip()
                if json_text.startswith("{") and json_text.endswith("}"):
                    try:
                        parsed = json.loads(json_text)
                        result["answer"] = parsed.get("answer", "")
                    except json.JSONDecodeError:
                        result["answer"] = ""
            return result

        # Extract Action Input using string-aware brace counting
        if result["action"]:
            result["type"] = "action"
            # Bug fix 2026-09-13 (BUG-R94): the previous brace counter
            # was not string-aware — when an Action Input contained
            # nested literal braces inside a string value (e.g.
            # ``{"template": "{a} and {b}"}``) the counter would open
            # on the inner ``{`` and close early on the inner ``}``,
            # handing back a truncated JSON object that fails to
            # parse. Use the project-wide balanced-brace extractor
            # (``utils.helpers.extract_json_object``) which honours
            # string literals and escape sequences.
            input_match = re.search(r"Action Input:\s*(?:```json\s*)?", response)
            if input_match:
                json_start = input_match.end()
                json_text = extract_json_object(response[json_start:]) or response[json_start:].strip()
                if json_text.startswith("{") and json_text.endswith("}"):
                    try:
                        result["input"] = json.loads(json_text)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse Action Input JSON: {json_text[:200]}")
                        result["input"] = {}
                elif json_text:
                    logger.warning(f"Action Input has no JSON braces: {json_text[:100]}")

        return result

    async def execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool by name and given input."""
        # Shared evidence dict so tools can pass data to each other (e.g.
        # analyze_traffic → generate_report).  Class variable keeps the same
        # dict across all _SessionShim instances created during a run.

        runContext = {
            "asn": self._asn or _RUN_ASN or "",
            "start_time": self._start_time or _RUN_START or "",
            "end_time": self._end_time or _RUN_END or "",
        }

        class _SessionShim:
            """
            Lightweight session-like object passed to each tool.
            """
            def __init__(self, evidence_dict, run_id):
                # Instance-level evidence replaces the module-global _SHARED_EVIDENCE
                # so concurrent --parallel>1 runs don't share state.
                self.evidence = evidence_dict
                self.run_id = run_id
                self.run_context = dict(runContext)

        session = _SessionShim(self._evidence, self.run_id)

        if tool_name == "generate_report":
            traffic = self._evidence.get("analyze_traffic", {})
            routing = self._evidence.get("analyze_routing", {})

            def has_displayable_evidence(value: Any) -> bool:
                if not isinstance(value, dict) or value.get("success") is False:
                    return False
                candidate = value.get("results") or value.get("result") or value
                if not isinstance(candidate, dict) or not candidate:
                    return False
                # Require non-empty events list OR a traffic plot.
                # Without either, the LLM will produce a misleading "no anomaly"
                # report even though the data source was unavailable or returned
                # empty results (e.g. Cloudflare Radar for AS13335 returns HTTP 200
                # but timestamps/values are []).
                anomalies = candidate.get("anomalies") or []
                plot_path = candidate.get("plot_path")
                return bool(anomalies) or bool(plot_path)

            traffic_ready = has_displayable_evidence(traffic)
            routing_ready = has_displayable_evidence(routing)
            if not (traffic_ready and routing_ready):
                missing = []
                if not traffic_ready:
                    missing.append("traffic analysis")
                if not routing_ready:
                    missing.append("routing analysis")
                return {
                    "success": False,
                    "error": "Report requires completed " + " and ".join(missing),
                    "observation": "Report deferred until completed traffic and routing evidence is available.",
                }

            # enhanced 模式：先触发 LLMDebateAgent 对抗辩论（如果还没有跑过），
            # 然后交给 MultiAgentReportAgent 多专家生成报告。
            #
            # 关键设计变更：辩论阶段从原来的"质量门检测到争议时才触发"
            # 改为"只要 enhanced=True 且 evidence 充分就跑一次"，与
            # traffic_first_enhanced 的设计对齐。两边都用同一个 Blackboard
            # → LLMDebateAgent → verdict 写入 self._evidence["debate_outcome"]
            # 的数据流，因此多 Agent 报告可以共享同一个 debate verdict。
            if self.enhanced:
                try:
                    if "debate_outcome" not in self._evidence and self._blackboard is not None:
                        await self._run_enhanced_debate(
                            traffic, routing
                        )
                    multi_path = await self.try_enhanced_report(tool_input, session)
                    if multi_path:
                        return {
                            "success": True,
                            "report_path": multi_path,
                            "report_mode": "multi_agent_enhanced",
                            "observation": f"Enhanced report saved to: {multi_path}",
                        }
                except Exception as e:
                    logger.warning(f"[ReactAgent] enhanced report path failed, "
                                   f"falling back: {e}")

        if tool_name in AVAILABLE_TOOLS:
            tool_func = AVAILABLE_TOOLS[tool_name]
            self.tools_used.add(tool_name)

            try:
                result = await tool_func(tool_input, session)
                # Store result so generate_report can read earlier tools' output
                self._evidence[tool_name] = result
                logger.info(f"[execute_tool] stored '{tool_name}', keys now: {list(self._evidence.keys())}")

                # enhanced 模式：把关键 evidence 写入 Blackboard，
                # 让后续的 LLMDebateAgent / MultiAgentReportAgent 能拿到。
                if self.enhanced and self._blackboard is not None:
                    try:
                        await self._sync_evidence_to_blackboard(tool_name, result)
                    except Exception as e:
                        logger.debug(f"[ReactAgent] blackboard sync failed: {e}")

                return result
            except Exception as e:
                logger.error(f"Tool {tool_name} failed: {e}")
                return {"success": False, "error": str(e)}
        else:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}. Available tools: {list(AVAILABLE_TOOLS.keys())}",
            }

    def _pick_fallback_action(self, context: Dict[str, Any]) -> tuple:
        """Bug #9 fix: pick the next sensible tool when the LLM returns an
        empty action (e.g. JS safety guard refuses the role).

        Walks a deterministic tool pipeline in priority order, skipping any
        tool whose evidence is already present. The pipeline mirrors the
        reasoning flow that a thoughtful analyst would take:

            analyze_traffic → analyze_routing → check_correlation →
            generate_report
        """
        pipeline = [
            ("analyze_traffic", {
                "asn": self._asn or None,
                "start_time": self._start_time or None,
                "end_time": self._end_time or None,
            }),
            ("analyze_routing", {
                "asn": self._asn or None,
                "start_time": self._start_time or None,
                "end_time": self._end_time or None,
                "detail_level": "light",  # skip slow outage baseline; quick path covers it
            }),
            ("check_correlation", {
                "asn": self._asn or None,
            }),
            ("generate_report", {
                "asn": self._asn or None,
                "start_time": self._start_time or None,
                "end_time": self._end_time or None,
            }),
        ]
        for name, default_input in pipeline:
            if name not in self._evidence:
                return name, default_input
        # Everything done — final call is generate_report (idempotent).
        return "generate_report", {
            "asn": self._asn or None,
            "start_time": self._start_time or None,
            "end_time": self._end_time or None,
        }

    def format_observation(self, result: Dict[str, Any]) -> str:
        """Format tool result as observation string.

        修 P1-#2：原始 tool 结果（如 analyze_traffic 返回的 traffic_timeline 数
        千个数据点）会随每次 round 进入 context，几个 round 就触发 LLM 拒绝
        (400 token 限制)。这里统一做证据摘要：
        - 把 dict 列表压成 count + first/last + 关键字段摘要
        - 长度上限 OBSERVATION_MAX_CHARS（默认 4000）
        - 时序（timestamp）和数值（score/drop_ratio/anomaly_score）保留
        - _SHARED_EVIDENCE 原始数据保留给后续工具读，不丢；只 slim 回写 context 的 observation 字符串
        """
        if not result:
            return "No result returned."

        if result.get("error"):
            return f"Error: {result['error']}"

        # Direct observation field — slim very long strings
        if "observation" in result:
            obs = str(result["observation"])
            cap = getattr(self, "OBSERVATION_MAX_CHARS", 4000)
            if len(obs) > cap:
                return obs[:cap] + f"...[省略 {len(obs) - cap} 字符，原始数据保留在 _SHARED_EVIDENCE]"
            return obs

        # Generic formatting with slimming
        parts = []
        if "success" in result:
            parts.append(f"Success: {result['success']}")

        # Slim dict-list values (timeline / events)
        for key, value in result.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                count = len(value)
                first = value[0]
                last = value[-1]
                # Bug fix 2026-09-13 (BUG-R100): the previous code called
                # ``json.dumps(first, ensure_ascii=False)[:200]`` directly.
                # If ``first`` contained non-JSON-serialisable values
                # (datetime, set, numpy scalars, custom dataclasses) the
                # call would raise ``TypeError`` and propagate up to
                # ``entry.observation = self.format_observation(result)``
                # at the call site, which had no surrounding try/except,
                # crashing the entire tool execution and turning a
                # successful tool call into a generic "Tool X failed:
                # TypeError" message. The fix uses ``default=str`` so any
                # non-serialisable object is converted to its string form
                # (e.g. ``datetime(2024, ...)`` becomes ``"2024-..."``)
                # and silently truncates very long strings.
                def _safe(obj):
                    try:
                        return json.dumps(obj, ensure_ascii=False, default=str)[:200]
                    except Exception:
                        return f"<unserialisable {type(obj).__name__}>"
                # When count == 1 we would otherwise print the same item
                # twice — emit a single-line form to save context tokens.
                if count == 1:
                    parts.append(f"{key}: 总数={count}, 唯一条目={_safe(first)}")
                else:
                    parts.append(
                        f"{key}: 总数={count}, 第一条={_safe(first)}, "
                        f"最后一条={_safe(last)}"
                    )
            elif key in ("success",):
                continue
            elif key in ("results",):
                try:
                    parts.append(f"Results: {json.dumps(value, ensure_ascii=False, default=str)[:2000]}")
                except Exception:
                    parts.append(f"Results: <unserialisable {type(value).__name__}>")
            elif key in ("message", "summary"):
                parts.append(f"{key.capitalize()}: {str(value)[:1500]}")
            elif key == "data" and isinstance(value, dict):
                parts.append(f"Data keys: {list(value.keys())}")
            elif isinstance(value, (str, int, float, bool)):
                if key not in ("_source", "_from_annotation_package"):
                    parts.append(f"{key}: {value}")
            else:
                parts.append(f"{key}: <{type(value).__name__} {len(str(value))} chars>")

        summary = "\n".join(parts) if parts else json.dumps(result, ensure_ascii=False)[:2000]
        # Final cap
        cap = getattr(self, "OBSERVATION_MAX_CHARS", 4000)
        if len(summary) > cap:
            return summary[:cap] + f"...[原始数据更详细]"
        return summary

    def update_context(self, old_context: str, entry: ReactTraceEntry) -> str:
        """Update context with new observation for next round.

        修 P1-#1：context 字符串会随轮次无界增长，触发 489K token 爆炸。
        这里硬性截断到 MAX_CONTEXT_CHARS（约 50K chars ≈ 13K tokens），
        保留最近若干轮次的 trace。早期的 trace 写到 trace summary 供报告使用。

        修 B-#10：把 observation 用 [Tool Observation] ... [/Tool Observation]
        显式 fence 包裹。这有两个作用：
          1. 让 LLM 一眼看出这是工具输出而非用户消息，避免 chat-completion
             安全护栏（GLM-5 / 部分 GPT 部署）把 observation 内容误判为
             "用户试图注入指令"，导致后续 round 拒绝角色扮演。
          2. 防止 observation 中夹带的"我是 glm-5"等身份确认文本污染后续推理。
        """
        new_context = old_context

        # Add the completed action and its result, with explicit observation
        # fencing so the LLM never mistakes it for a user instruction.
        new_context += f"""

## Round {entry.round_num} Completed

Thought: {entry.thought}
Action: {entry.action}
Action Input: {json.dumps(entry.action_input, ensure_ascii=False)}
[Tool Observation]
{entry.observation}
[/Tool Observation]
"""
        return self.cap_context(new_context)

    def cap_context(self, context: str) -> str:
        """对 context 字符串做硬截断，保留系统消息和最近的轮次。

        MAX_CONTEXT_CHARS 在 __init__ 已设为 50000（约 13K tokens），低于 LLM
        context window 的安全余量。任何时候 context 超出该阈值就丢弃最早
        的轮次段，保留头部（system + initial query）和最新部分。
        """
        cap = getattr(self, "MAX_CONTEXT_CHARS", 50000)
        if len(context) <= cap:
            return context
        # 头部 = system + initial query；尾部 = 最近轮次
        # 按 round 分段保留
        rounded = context.split("\n## Round ")
        # rounded[0] = 头部（system + 初始指令），rounded[1:] = 各 round 块
        head = rounded[0]
        body_parts = [f"## Round {p}" for p in rounded[1:]]
        # 从尾部保留
        kept = []
        total = len(head)
        for part in reversed(body_parts):
            total += len(part) + 2
            if total > cap:
                break
            kept.append(part)
        kept.reverse()
        dropped = len(body_parts) - len(kept)
        if dropped > 0:
            logger.warning(
                f"[ReAct] context 超过 {cap} 字符，丢弃最早 {dropped} 轮，"
                f"trace summary 中保留完整 {dropped + len(kept)} 轮记录"
            )
        return head + "\n" + "\n".join(kept)

    def update_context_with_error(self, old_context: str, entry: ReactTraceEntry, action_name: str = "") -> str:
        """Update context with error information (for exceptions during tool execution)."""
        action_str = f" (action: {action_name})" if action_name else ""
        new_context = old_context

        # Use the same Tool Observation fence so the LLM treats the error as
        # tool output rather than a fresh user instruction.
        new_context += f"""

## Round {entry.round_num} Completed (with Error{action_str})

Thought: {entry.thought}
Action: {entry.action}
[Tool Observation]
Error: {entry.error}

Please continue with an alternative approach or adjust the parameters.
[/Tool Observation]
"""

        return self.cap_context(new_context)

    def update_context_with_retry(
        self,
        old_context: str,
        entry: ReactTraceEntry,
        failed_action: str,
        result: Dict[str, Any],
    ) -> str:
        """
        Update context for a retry round after a tool returned success=False.

        Tells the LLM exactly what went wrong so it can fix the parameters.
        """
        error_msg = result.get("error", "Unknown error")
        new_context = old_context

        # Match the Tool Observation fence used elsewhere.
        new_context += f"""

## Round {entry.round_num} — Tool Execution Failed

[Tool Observation]
The tool "{failed_action}" returned an error:
Error: {error_msg}

This means the parameters you passed were invalid or incomplete.
Please correct the parameters and retry the same tool, or choose a different tool.

Current evidence already collected: {list(self._evidence.keys())}
[/Tool Observation]
"""

        return self.cap_context(new_context)

    async def run_supervisor_enrichment(
        self,
        context: str,
        asn: str,
        traffic_result: dict,
        routing_result: dict,
    ) -> str:
        """
        Run InvestigationSupervisor after both traffic and routing analysis are complete.

        This is the key "human-like" enhancement for the ReAct mode:
        - Automatically triggers auxiliary tools based on detected patterns
        - Injects enriched evidence into the LLM context
        - Saves LLM from having to "decide" whether to use each tool
        """
        from agents.investigation_supervisor import InvestigationSupervisor
        import asyncio

        # Infer suspected type from routing data
        suspected_type = "unknown"
        if routing_result.get("origin_hijacked") or routing_result.get("origin_hijacking"):
            suspected_type = "origin_hijack"
        elif routing_result.get("forge_hijacked") or routing_result.get("forge_hijacking"):
            suspected_type = "forge_hijack"
        elif routing_result.get("route_leaks"):
            suspected_type = "route_leak"
        elif routing_result.get("outage_suspected"):
            suspected_type = "outage"

        # Skip if no meaningful anomaly detected
        has_routing = any([
            routing_result.get("origin_hijacked"),
            routing_result.get("forge_hijacked"),
            routing_result.get("route_leaks"),
        ])
        has_traffic = traffic_result.get("anomalies_detected") or traffic_result.get("anomalies")
        if not has_routing and not has_traffic:
            self.stream_print("[InvestigationSupervisor] No anomalies detected — skipping auxiliary enrichment\n")
            logger.info("[ReAct][Supervisor] No anomalies — skipping")
            return context

        self.stream_print("\n" + "=" * 60 + "\n")
        self.stream_print("[InvestigationSupervisor] Auto-triggering auxiliary enrichment...\n")
        self.stream_print(f"  Suspected type: {suspected_type}\n")
        self.stream_print("=" * 60 + "\n\n")
        logger.info(f"[ReAct][Supervisor] Running enrichment for AS{asn}, type={suspected_type}")

        try:
            supervisor = InvestigationSupervisor()
            result = await supervisor.enrich(
                routing_data=routing_result,
                traffic_data=traffic_result,
                asn=str(asn),
                context={"suspected_type": suspected_type},
                skip_pattern="no_anomaly",
            )

            # Store for later use
            self._supervisor_enrichment_result = result

            tool_count = result.get("tool_count", 0)
            confidence_boost = result.get("total_confidence_boost", 0.0)
            narrative = result.get("auxiliary_narrative", "")

            self.stream_print(f"[InvestigationSupervisor] Done. {tool_count} tools executed, confidence_boost=+{confidence_boost:.2f}\n")
            self.stream_print("=" * 60 + "\n")

            # Inject enrichment into context
            enrichment_section = f"""

## ⚡ Auxiliary Enrichment (Auto-Injected by InvestigationSupervisor)

The following evidence was automatically gathered because routing/traffic anomalies were detected.
You MUST incorporate this evidence into your final reasoning.

This section is NOT part of the original conversation — it was automatically enriched
based on the detected patterns (type: {suspected_type}).

{narrative}

Confidence boost from auxiliary tools: +{confidence_boost:.2f}
Number of auxiliary tools executed: {tool_count}
"""

            return context + enrichment_section

        except Exception as e:
            self.stream_print(f"[InvestigationSupervisor] Enrichment failed: {e}\n")
            logger.warning(f"[ReAct][Supervisor] Failed: {e}")
            return context

    def get_trace_summary(self) -> str:
        """Get a human-readable summary of the React trace."""
        lines = [f"React Agent Trace Summary (Total Rounds: {len(self.trace)})"]
        lines.append("=" * 60)

        for entry in self.trace:
            lines.append(f"\nRound {entry.round_num}:")
            lines.append(f"  Thought: {entry.thought[:100]}..." if len(entry.thought) > 100 else f"  Thought: {entry.thought}")
            lines.append(f"  Action: {entry.action}")
            if entry.observation:
                lines.append(f"  Observation: {entry.observation[:100]}..." if len(entry.observation) > 100 else f"  Observation: {entry.observation}")
            if entry.error:
                lines.append(f"  Error: {entry.error}")
        return "\n".join(lines)


    async def _sync_evidence_to_blackboard(self, tool_name: str, result: Any):
        """Mirror key tool outputs into the Blackboard so downstream agents
        (LLMDebateAgent, MultiAgentReportAgent) can read them.

        Only the 3 evidence sources that DebateAgent itself inspects are
        mirrored; everything else stays in self._evidence to avoid paying
        the BB async-write cost on every round.
        """
        if self._blackboard is None:
            return
        bb = self._blackboard

        async def _unwrap(d):
            """Pull out the inner {'success':..., 'result':...} flatten to result."""
            if isinstance(d, dict):
                return d.get("results") or d.get("result") or d
            return d

        if tool_name == "analyze_traffic":
            payload = await _unwrap(result)
            await bb.update_section("traffic", {"result": payload})
        elif tool_name == "analyze_routing":
            payload = await _unwrap(result)
            await bb.update_section("routing", {"result": payload})
        elif tool_name == "reason_and_classify":
            # ReasonAndClassify produces a final diagnosis with claims[].
            # We expose it to debate via two BB locations so the agent
            # picks it up whether it reads from diagnosis or evidence.
            payload = await _unwrap(result)
            if isinstance(payload, dict):
                claims = payload.get("claims") or payload.get("diagnosis_claims") or []
                final_claim = payload.get("final_claim") or payload.get("diagnosis")
                # ReasoningAgent in traffic_first writes claims to diagnosis.claims;
                # match that convention here.
                if claims:
                    await bb.write("diagnosis", "claims", claims)
                await bb.write("diagnosis", "result", payload)
                if final_claim:
                    await bb.write("diagnosis", "final_claim", final_claim)

    async def _run_enhanced_debate(self, traffic, routing):
        """Run the LLMDebateAgent on the current evidence so verdict is available
        before the multi-agent report is generated.

        Mirrors the workflow_engine.step path (cf. traffic_first_enhanced):
          - reads reasoning claims from Blackboard
          - runs Prosecutor + Defense + Judge debate rounds (default 2)
          - writes the winner to self._evidence["debate_outcome"]
        """
        if self._blackboard is None:
            logger.debug("[ReactAgent] debate skipped: no blackboard")
            return
        # Make sure config carries asn/start/end so debate agent can read them
        try:
            await self._blackboard.update_section(
                "config",
                {
                    "asn": self._asn or "",
                    "start_time": self._start_time or "",
                    "end_time": self._end_time or "",
                },
            )
        except Exception as e:
            logger.debug(f"[ReactAgent] bb config update failed: {e}")

        try:
            from agents.enhanced.debate_agent import LLMDebateAgent
            debate_agent = LLMDebateAgent(bb=self._blackboard, max_rounds=2)
            debate_result = await debate_agent.step()
            if not (debate_result and getattr(debate_result, "success", False)):
                logger.debug(f"[ReactAgent] debate returned no result: "
                             f"success={getattr(debate_result, 'success', None)}")
                return
            data = getattr(debate_result, "data", None) or {}
            debate_results = data.get("debate_results", [])
            if not debate_results:
                return
            best = debate_results[0]
            verdict = {
                "debate_results": debate_results,
                "winner": best.get("winner"),
                "conclusion": best.get("conclusion") or best.get("winner"),
                "original_claim": best.get("original_claim"),
                "final_confidence": best.get("final_confidence", 0.5),
                "rounds": data.get("rounds", len(debate_results)),
            }
            self._evidence["debate_outcome"] = verdict
            logger.info(
                f"[ReactAgent] debate complete: winner={verdict['winner']!r} "
                f"confidence={verdict['final_confidence']:.2f} rounds={verdict['rounds']}"
            )
            # Also publish on blackboard so subsequent debate rounds / reports
            # can read it without needing self._evidence.
            try:
                await self._blackboard.write("evidence", "debate_outcome", verdict)
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"[ReactAgent] debate failed: {e}")

    def run_enhanced_quality_gate(self, traffic, routing):
        """Run OnlineEvaluationAgent quality gate before report generation.

        Returns dict with:
          - quality_score (float)
          - gate_passed (bool)
          - issues (list of strings)
        """
        try:
            from agents.enhanced.evaluation_loop import OnlineEvaluationAgent
            agent = OnlineEvaluationAgent()
            metrics, gate_passed, corrections = asyncio.run(agent.evaluate_stage(
                stage_name="report",
                agent_output={"traffic": traffic, "routing": routing},
                context={},
            ))
            metrics_dict = metrics.to_dict() if hasattr(metrics, "to_dict") else {}
            return {
                "quality_score": metrics_dict.get("overall_score", 0.0),
                "gate_passed": gate_passed,
                "issues": [i.get("description", str(i)) for i in metrics_dict.get("issues", [])],
            }
        except Exception as e:
            logger.debug(f"[ReactAgent] quality gate unavailable: {e}")
            return {"quality_score": 0.0, "gate_passed": True, "issues": []}

    async def try_enhanced_report(self, tool_input, session):
        """Generate report via MultiAgentReportAgent in enhanced mode.

        Returns the saved HTML path on success, None on failure so the caller
        falls back to the default `_generate_report` tool.
        """
        try:
            from agents.enhanced.multi_report import MultiAgentReportAgent
            from agents.report_agent import analyze_temporal_correlation

            rc = getattr(session, "run_context", {}) or {}
            traffic = self._evidence.get("analyze_traffic", {})
            routing = self._evidence.get("analyze_routing", {})
            traffic_data = traffic.get("results") or traffic.get("result") or traffic
            routing_data = routing.get("results") or routing.get("result") or routing
            correlation = analyze_temporal_correlation(
                traffic_raw=traffic_data,
                routing_result=routing_data,
                target_as=rc.get("asn", "unknown"),
            )

            # Bug fix: MultiAgentReportAgent extends Agent whose __init__
            # requires a `blackboard` argument. Passing self._blackboard
            # (the run-scoped Blackboard instance set up in ReactAgent.run)
            # makes the multi-agent pipeline actually execute instead of
            # raising "missing 1 required positional argument: 'blackboard'"
            # in the except branch — previously the entire enhanced-report
            # path silently fell back to the plain generate_report tool.
            multi = MultiAgentReportAgent(blackboard=self._blackboard)
            # 在 enhanced 模式下，把辩论结果也作为 reasoning_result 的
            # 优先输入传给多 Agent 报告生成器，让 ConflictResolver /
            # ConfidenceCalibrator 看到辩论结论而不是只有 LLM 单方面分类。
            #
            # 注意：如果辩论比 reason_and_classify 更具信息量，则用辩论版本；
            # 反之保留原本的 reason_and_classify。绝大多数情况下辩论会补充置信度。
            reasoning_input = self._evidence.get("reason_and_classify")
            debate_outcome = self._evidence.get("debate_outcome")
            if isinstance(debate_outcome, dict):
                reasoning_input = {
                    **(reasoning_input if isinstance(reasoning_input, dict) else {}),
                    "debate_verdict": debate_outcome,
                    "debate_winner": debate_outcome.get("winner"),
                    "debate_confidence": debate_outcome.get("final_confidence"),
                }
            # Bug fix 2026-09-13 (BUG-R101): this method is now ``async``
            # so we can directly ``await`` ``multi.generate``. The
            # previous synchronous version wrapped the coroutine in
            # ``asyncio.run`` from inside the React loop, which raised
            # ``RuntimeError: asyncio.run() cannot be called from a
            # running event loop``; the exception was swallowed by the
            # surrounding ``except Exception`` and the enhanced-report
            # path silently fell back to the plain ``generate_report``
            # tool, defeating the whole point of ``--enhanced``.
            result = await multi.generate(
                traffic_data=traffic_data,
                routing_data=routing_data,
                correlation_analysis=correlation,
                reasoning_result=reasoning_input,
                user_analysis_window=f"{rc.get('start_time', '')} to {rc.get('end_time', '')}",
            )
            if result is None:
                return None
            return getattr(result, "report_path", None) or (
                result.get("report_path") if isinstance(result, dict) else None
            )
        except Exception as e:
            logger.debug(f"[ReactAgent] MultiAgentReportAgent unavailable: {e}")
            return None


def create_react_agent(
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
    streaming_callback: Optional[Callable[[str], None]] = None,
) -> ReactAgent:
    """
    Factory function to create a ReactAgent with LLM.

    Args:
        model: Model name (defaults to config.MODEL)
        api_key: API key (defaults to config.API_KEY)
        base_url: API base URL (defaults to config.BASE_URL)
        max_rounds: Maximum React rounds
        streaming_callback: Optional callback for streaming output

    Returns:
        Configured ReactAgent instance
    """
    try:
        from config import MODEL, API_KEY, BASE_URL

        llm, _ = setup_llm_settings(
            model=model or MODEL,
            api_key=api_key or API_KEY,
            base_url=base_url or BASE_URL,
            temperature=DEFAULT_TEMP_REASONING,
            timeout=120.0,
            max_retries=1,
        )
    except ImportError:
        # Fallback for testing without full config
        llm = None

    return ReactAgent(
        llm=llm,
        max_rounds=max_rounds,
        max_retries=max_retries,
        streaming_callback=streaming_callback,
    )
