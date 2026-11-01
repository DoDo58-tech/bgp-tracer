"""React Agent - LLM-driven coordinator with streaming support
========================================================="""

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
    analyze_traffic,
    analyze_routing,
    check_correlation,
    query_as_info,
    reason_and_classify,
    generate_report,
    analyze_prefix_traffic,
    classify_traffic_anomaly,
    compute_traffic_routing_correlation_score,
    analyze_as_path_delta,
    analyze_as_relationships,
    probe_prefix_reachability,
    validate_roa_status,
    lookup_as_threat_intel,
)
from tools.threat_intelligence import threat_intel_lookup
from tools.news_context import news_context_search
from tools.irr_registry import irr_registry_lookup
from tools.historical_behavior import historical_behavior_lookup
from utils.helpers import extract_json_object
from utils.logger import logger

# Maximum number of React rounds before forcing termination
DEFAULT_MAX_ROUNDS = 8

# Max retries per tool within a single round (when tool returns success=False)
DEFAULT_MAX_RETRIES = 2

# Available tools mapping
AVAILABLE_TOOLS = {
    "analyze_traffic": analyze_traffic,
    "analyze_routing": analyze_routing,
    "check_correlation": check_correlation,
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
    "threat_intelligence": threat_intel_lookup,
    "news_context": news_context_search,
    "irr_registry": irr_registry_lookup,
    "historical_behavior": historical_behavior_lookup,
}

# Shared evidence dict — populated by each tool execution so generate_report
_SHARED_EVIDENCE: Dict[str, Dict[str, Any]] = {}


def shared_evidence(session_id):
    """Get or create the per-run shared evidence bucket."""
    if session_id not in _SHARED_EVIDENCE:
        _SHARED_EVIDENCE[session_id] = {}
    return _SHARED_EVIDENCE[session_id]


def clear_shared_evidence(session_id):
    """Drop the per-run bucket after agent.run() finishes."""
    _SHARED_EVIDENCE.pop(session_id, None)


def finalize_run(result: "ReactResult"):
    """Release per-run resources once a React run is done."""
    try:
        clear_shared_evidence(getattr(result, "run_id", "") or "")
    except ValueError:
        # Cleanup must never fail a finished run.
        pass
    return result


def valid_llm_html_report(filepath):
    """Return True only for a saved, complete, non-fallback LLM HTML report."""
    report_path = filepath
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
    html_no_style = re.sub(r"<style\b[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)

    # 2. Now look for known HTML tag patterns that are NOT preceded by '<'.
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
    # Evidence accumulated by run() across rounds.
    evidence: Dict[str, Any] = field(default_factory=dict)
    # run_id (set by chief_agent) tags the evidence bucket.
    run_id: str = ""


class ReactAgent:
    """React-style coordinator agent with streaming support."""

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
        # Enhanced mode pairs the ReAct loop with a debate/report pipeline.
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

        # Enhanced mode additionally keeps a blackboard for the debate stage.
        self._blackboard = None
        if self.enhanced:
            try:
                from agents.core import Blackboard as _BB
                self._blackboard = _BB()
                # Flag is set once the run context is written below.
                self._blackboard_seeded = False
            except AttributeError as e:
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
    ):
        """Run the React agent to analyze the given AS and time window.
        
        Returns:
        ReactResult with answer and trace"""
        self.trace = []
        self.tools_used = set()
        self._round = 0
        report_path = ""

        # Reset instance evidence so each run starts clean (fixes concurrent run contamination)
        self._evidence.clear()

        # Store run context as instance attributes — explicit and thread-safe.
        self._asn = asn or ""
        self._start_time = start_time or ""
        self._end_time = end_time or ""
        global _RUN_ASN, _RUN_START, _RUN_END
        _RUN_ASN = self._asn
        _RUN_START = self._start_time
        _RUN_END = self._end_time

        # Seed the blackboard with the run context.
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
            except AttributeError as e:
                logger.debug(f"[ReactAgent] bb config seed at run start failed: {e}")

        # ── Pre-inject pre-computed evidence (annotation_package) ────────────
        bucket = shared_evidence(self.run_id)
        if self.precomputed_routing:
            self._evidence["precomputed_routing"] = self.precomputed_routing
            bucket["precomputed_routing"] = self.precomputed_routing
            logger.info(f"[ReactAgent] Injected precomputed_routing "
                        f"({len(str(self.precomputed_routing))//1024} KB, run_id={self.run_id[:8]})")
            _mirrored_routing = {
                "success": True,
                "_from_precomputed": True,
                "result": {
                    k: self.precomputed_routing.get(k)
                    for k in (
                        "origin_hijacked", "forge_hijacked",
                        "origin_hijacking", "forge_hijacking",
                        "route_leaks", "outages",
                        "mitm_alerts", "leak",
                    )
                    if self.precomputed_routing.get(k)
                },
            }
            # If the routing payload nests events under ``hijack`` /
            # ``leak`` (the workflow_engine shape), unwrap one level.
            if not _mirrored_routing["result"].get("origin_hijacked"):
                hij = self.precomputed_routing.get("hijack") or {}
                leak = self.precomputed_routing.get("leak") or {}
                for k in ("origin_hijacked", "forge_hijacked",
                          "origin_hijacking", "forge_hijacking",
                          "mitm_alerts"):
                    if hij.get(k):
                        _mirrored_routing["result"][k] = hij[k]
                if leak.get("route_leaks"):
                    _mirrored_routing["result"]["route_leaks"] = leak["route_leaks"]
            self._evidence["analyze_routing"] = _mirrored_routing
            bucket["analyze_routing"] = _mirrored_routing
        if self.precomputed_traffic:
            self._evidence["precomputed_traffic"] = self.precomputed_traffic
            bucket["precomputed_traffic"] = self.precomputed_traffic
            # Mirror under analyze_traffic so generate_report's gating passes.
            traffic_results = self.precomputed_traffic.get("results") or {}
            if not traffic_results:
                # quick_cache shape: top-level fields; wrap into per-asn results.
                traffic_results = {
                    str(self.precomputed_traffic.get("asn") or asn): {
                        "anomalies": (
                            self.precomputed_traffic.get("anomalies")
                            or self.precomputed_traffic.get("anomaly_events")
                            or []
                        ),
                        "traffic_plot_path": (
                            self.precomputed_traffic.get("traffic_plot_path")
                            or self.precomputed_traffic.get("plot_path")
                        ),
                    }
                }
            _mirrored_traffic = {
                "success": True,
                "_from_precomputed": True,
                "results": traffic_results,
            }
            self._evidence["analyze_traffic"] = _mirrored_traffic
            bucket["analyze_traffic"] = _mirrored_traffic

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

                # Hand the LLM answer off to the InvestigationSupervisor.
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
                        # Supervisor enrichment ran before Answer return
                        logger.info("[ReAct] Supervisor enrichment complete before Answer return")
                    except AttributeError as e:
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
                    except AttributeError as e:
                        logger.error(f"[ReAct] Auto report generation failed: {e}")
                
                return finalize_run(ReactResult(
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
            if not action_name:
                action_name, action_input = self.pick_fallback_action(context)
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

                    # ── Optimization: Early termination when both analyses are done ──
                    if (
                        self._traffic_result is not None
                        and self._routing_result is not None
                        and "generate_report" not in self.tools_used
                        and action_name in ("check_correlation", "analyze_traffic", "analyze_routing")
                    ):
                        # Append a hint to stop iterating once both signals are in
                        context += (
                            "\n\n[System hint] Both analyze_traffic and analyze_routing are "
                            "complete. If correlation has already been computed and no further "
                            "investigation is required, you may call generate_report now to "
                            "finalize the analysis."
                        )

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
                            return finalize_run(ReactResult(
                                success=False,
                                answer=entry.observation,
                                trace=self.trace,
                                tools_used=list(self.tools_used),
                                total_rounds=self._round,
                                error="generate_report did not produce an acceptable LLM HTML file",
                                evidence=dict(self._evidence),
                                run_id=self.run_id,
                            ))
                        return finalize_run(ReactResult(
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
                                new_entry = ReactTraceEntry(
                                    round_num=self._round,
                                    thought=parsed.get("thought", response),
                                    action=action_name,
                                    action_input=action_input,
                                )
                                self.trace.append(new_entry)
                                entry = new_entry
                                continue
                        except AttributeError as retry_err:
                            logger.error(
                                f"[ReAct][Round {self._round}] Retry think failed: {retry_err}"
                            )
                        # If we couldn't form a new action, fall through to outer
                        # round handler so the round terminates cleanly.
                    break  # exit retry loop after exception (or retries exhausted)


        # Max rounds reached — generate report from whatever evidence was collected
        logger.warning(f"[ReAct] Max rounds ({self.max_rounds}) reached, forcing report generation")
        # Use self._evidence directly (not _SHARED_EVIDENCE which may be empty
        # when enhanced mode uses session.evidence instead of the global bucket).
        if "generate_report" not in self.tools_used and self._evidence:
            try:
                inp = {
                    "asn": _RUN_ASN or None,
                    "start_time": _RUN_START or None,
                    "end_time": _RUN_END or None,
                }
                result = await self.execute_tool("generate_report", inp)
                if result.get("success"):
                    logger.info(f"[ReAct] Forced report generated: {result.get('report_path', '')}")
            except AttributeError as e:
                logger.error(f"[ReAct] Forced report generation failed: {e}")

        return finalize_run(ReactResult(
            success=False,
            answer="Maximum rounds reached without final answer.",
            trace=self.trace,
            tools_used=list(self.tools_used),
            total_rounds=self._round,
            error=f"Reached max rounds ({self.max_rounds})",
            evidence=dict(self._evidence),
                            run_id=self.run_id,
        ))

    async def llm_think(self, context):
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

    async def stream_chat(self, messages):
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

    def stream_print(self, content):
        """Send content to streaming callback if available."""
        if self.streaming_callback and content:
            try:
                self.streaming_callback(content)
            except AttributeError as e:
                logger.warning(f"Streaming callback error: {e}")

    def get_system_prompt(self):
        """Get the React coordinator system prompt."""
        prompt_template = build_react_coordinator_prompt()
        tools_description = self.format_tools_description()
        return prompt_template.format(available_tools=tools_description)

    def format_tools_description(self):
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
    ):
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

    def parse_response(self, response):
        """Parse LLM response into thought, action, and input."""
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

    async def execute_tool(self, tool_name, tool_input: Dict[str, Any]):
        """Execute a tool by name and given input."""
        # Shared evidence dict so tools can pass data to each other (e.g.
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

            def traffic_has_evidence(value):
                """Check analyze_traffic result."""
                if not isinstance(value, dict) or value.get("success") is False:
                    return False
                results = value.get("results", {})
                if not isinstance(results, dict) or not results:
                    return False
                # At least one per-AS entry has anomalies or a traffic plot.
                for sub in results.values():
                    if not isinstance(sub, dict):
                        continue
                    anomalies = sub.get("anomalies") or sub.get("anomaly_events") or []
                    if bool(anomalies):
                        return True
                    plot = sub.get("traffic_plot_path") or sub.get("plot_path") or sub.get("image_path")
                    if plot:
                        return True
                return False

            def routing_has_evidence(value):
                """Check analyze_routing result."""
                if not isinstance(value, dict) or value.get("success") is False:
                    return False
                result = value.get("result", {})
                if not isinstance(result, dict) or not result:
                    return False
                event_keys = (
                    "origin_hijacked", "forge_hijacked",
                    "origin_hijacking", "forge_hijacking",
                    "route_leaks", "outages",
                )
                for key in event_keys:
                    ev = result.get(key)
                    if isinstance(ev, list) and ev:
                        return True
                    if isinstance(ev, dict) and ev:
                        return True
                # Also accept outage_analysis with a positive score as evidence.
                outage = result.get("outage_analysis") or {}
                if isinstance(outage, dict) and (
                    outage.get("outage_score", 0) > 0
                    or outage.get("is_outage_suspected") is True
                ):
                    return True
                return False

            traffic_ready = traffic_has_evidence(traffic)
            routing_ready = routing_has_evidence(routing)
            traffic_completed = isinstance(traffic, dict) and traffic.get("success") is True
            routing_completed = isinstance(routing, dict) and routing.get("success") is True
            if not (traffic_completed or routing_completed):
                missing = []
                if not traffic_completed:
                    missing.append("traffic analysis")
                if not routing_completed:
                    missing.append("routing analysis")
                return {
                    "success": False,
                    "error": "Report requires completed " + " and ".join(missing),
                    "observation": "Report deferred until at least one of traffic/routing analysis is completed.",
                }
            # If at least one tool produced evidence (anomalies/hijacks), use
            if self.enhanced:
                try:
                    if "debate_outcome" not in self._evidence and self._blackboard is not None:
                        await self.run_enhanced_debate(
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
                except AttributeError as e:
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

                # enhanced mode: mirror the evidence to the Blackboard so
                # downstream agents (LLMDebateAgent, MultiAgentReportAgent)
                # can read it.
                if self.enhanced and self._blackboard is not None:
                    try:
                        await self.sync_evidence_to_blackboard(tool_name, result)
                    except AttributeError as e:
                        logger.debug(f"[ReactAgent] blackboard sync failed: {e}")

                return result
            except AttributeError as e:
                logger.error(f"Tool {tool_name} failed: {e}")
                return {"success": False, "error": str(e)}
        else:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}. Available tools: {list(AVAILABLE_TOOLS.keys())}",
            }

    def pick_fallback_action(self, context: Dict[str, Any]):
        """Bug #9 fix: pick the next sensible tool when the LLM returns an
        empty action (e.g. JS safety guard refuses the role)."""
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

    def format_observation(self, result: Dict[str, Any]):
        """Format tool result as observation string."""
        if not result:
            return "No result returned."

        if result.get("error"):
            return f"Error: {result['error']}"

        # Direct observation field — slim very long strings
        if "observation" in result:
            obs = str(result["observation"])
            cap = getattr(self, "OBSERVATION_MAX_CHARS", 4000)
            if len(obs) > cap:
                return obs[:cap] + f"...[ {len(obs) - cap} ， _SHARED_EVIDENCE]"
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
                def safe(obj):
                    try:
                        return json.dumps(obj, ensure_ascii=False, default=str)[:200]
                    except AttributeError:
                        return f"<unserialisable {type(obj).__name__}>"
                # When count == 1 we would otherwise print the same item
                # twice — emit a single-line form to save context tokens.
                if count == 1:
                    parts.append(f"{key}: ={count}, ={safe(first)}")
                else:
                    parts.append(
                        f"{key}: ={count}, ={safe(first)}, "
                        f"={safe(last)}"
                    )
            elif key in ("success",):
                continue
            elif key in ("results",):
                try:
                    parts.append(f"Results: {json.dumps(value, ensure_ascii=False, default=str)[:2000]}")
                except AttributeError:
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
            return summary[:cap] + f"...[]"
        return summary

    def update_context(self, old_context, entry):
        """Update context with new observation for next round."""
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

    def cap_context(self, context):
        """context , ."""
        cap = getattr(self, "MAX_CONTEXT_CHARS", 50000)
        if len(context) <= cap:
            return context
        #  = system + initial query； =
        #  round
        rounded = context.split("\n## Round ")
        # rounded[0] = （system + ），rounded[1:] =  round
        head = rounded[0]
        body_parts = [f"## Round {p}" for p in rounded[1:]]
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
                f"[ReAct] context  {cap} ， {dropped} ，"
                f"trace summary  {dropped + len(kept)} "
            )
        return head + "\n" + "\n".join(kept)


    def update_context_with_retry(
        self,
        old_context: str,
        entry: ReactTraceEntry,
        failed_action: str,
        result: Dict[str, Any],
    ):
        """Update context for a retry round after a tool returned success=False."""
        error_msg = result.get("error", "Unknown error")
        new_context = old_context

        # Match the Tool Observation fence used elsewhere.
        new_context += f"""

## Round {entry.round_num} - Tool Execution Failed

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
    ):
        """Run InvestigationSupervisor after both traffic and routing analysis are complete."""
        from agents.investigation_supervisor import InvestigationSupervisor

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

This section is NOT part of the original conversation - it was automatically enriched
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

    def get_trace_summary(self):
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


    async def sync_evidence_to_blackboard(self, tool_name, result):
        """Mirror key tool outputs into the Blackboard so downstream agents
        (LLMDebateAgent, MultiAgentReportAgent) can read them."""
        if self._blackboard is None:
            return
        bb = self._blackboard

        async def unwrap(d):
            """Pull out the inner {'success':..., 'result':...} flatten to result."""
            if isinstance(d, dict):
                return d.get("results") or d.get("result") or d
            return d

        if tool_name == "analyze_traffic":
            payload = await unwrap(result)
            await bb.update_section("traffic", {"result": payload})
            # Promote the detector's output to a typed observation so the
            if isinstance(payload, dict):
                await bb.add_observation({
                    "source": "ReactAgent",
                    "kind": "traffic_analysis",
                    "summary": (
                        f"ReAct traffic analysis returned "
                        f"{payload.get('anomaly_count', 0)} anomalies."
                    ),
                    "confidence": 0.7,
                    "payload": payload,
                    "tags": ["traffic", "react"],
                })
        elif tool_name == "analyze_routing":
            payload = await unwrap(result)
            await bb.update_section("routing", {"result": payload})
            if isinstance(payload, dict):
                await bb.add_observation({
                    "source": "ReactAgent",
                    "kind": "routing_analysis",
                    "summary": (
                        f"ReAct routing analysis returned "
                        f"{payload.get('anomaly_count', 0)} anomalies."
                    ),
                    "confidence": 0.72,
                    "payload": payload,
                    "tags": ["routing", "react"],
                })
        elif tool_name == "reason_and_classify":
            # ReasonAndClassify produces a final diagnosis with claims[].
            payload = await unwrap(result)
            if isinstance(payload, dict):
                claims = payload.get("claims") or payload.get("diagnosis_claims") or []
                final_claim = payload.get("final_claim") or payload.get("diagnosis")
                # ReasoningAgent in traffic_first writes claims to diagnosis.claims;
                # match that convention here.
                if claims:
                    await bb.write("diagnosis", "claims", claims)
                    # Also promote them to typed claim records, so the
                    # ReAct arm's board carries the same record kinds as
                    # the fixed pipeline's board.
                    for claim in claims:
                        if not isinstance(claim, dict):
                            claim = getattr(claim, "__dict__", None) or {}
                        if not claim:
                            continue
                        await bb.add_claim({
                            "source": "ReactAgent",
                            "kind": claim.get("kind") or "hypothesis",
                            "summary": claim.get("summary") or "",
                            "confidence": float(claim.get("confidence", 0.5) or 0.0),
                            "status": claim.get("status") or "proposed",
                            "evidence_ids": list(claim.get("evidence_ids") or []),
                            "supports": list(claim.get("supporting_evidence") or []),
                            "contradicts": list(claim.get("contradicting_evidence") or []),
                            "assumptions": list(claim.get("assumptions") or []),
                            "uncertainty": list(claim.get("uncertainty") or []),
                            "derived_from": list(claim.get("derived_from") or []),
                        })
                await bb.write("diagnosis", "result", payload)
                if final_claim:
                    await bb.write("diagnosis", "final_claim", final_claim)

    async def run_enhanced_debate(self, traffic, routing):
        """Stub: enhanced mode removed 2026-09-29 (paper-grade cleanup)."""
        return None


    async def try_enhanced_report(self, tool_input, session):
        """Stub: enhanced mode removed 2026-09-29 (paper-grade cleanup)."""
        return None

def create_react_agent(
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
    streaming_callback: Optional[Callable[[str], None]] = None,
):
    """Factory function to create a ReactAgent with LLM.
    
    Returns:
    Configured ReactAgent instance"""
    try:
        from config import MODEL, API_KEY, BASE_URL

        llm, _ = setup_llm_settings(
            model=model or MODEL,
            api_key=api_key or API_KEY,
            base_url=base_url or BASE_URL,
            temperature=DEFAULT_TEMP_REASONING,
            timeout=600.0,
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