"""
RouterAgent — ReAct-driven conversation and tool router.
=======================================================

The RouterAgent uses the ReAct (Reasoning + Acting) pattern to:
1. Think through the problem step by step
2. Take actions (call tools) based on reasoning
3. Observe results and incorporate them into next thoughts
4. Continue until a comprehensive analysis is complete

ReAct Loop:
    Thought: <reasoning about what to do next>
    Action: <tool_name>
    Action Input: <parameters>
    Observation: <result from tool>
    ... (repeat until done)
    Thought: I have enough information to answer.
    Answer: <final response>

Architecture:
    ChatInterface → RouterAgent.step(user_message, session)
                         ↓
                    ReAct Loop:
                      ↓
                    LLM thinks: "I need to gather traffic data first..."
                    ↓
                    Thought → Action → Observation
                    ↓
                    Continue until complete
                    ↓
                    Final Answer
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from agents.traffic_agent import parse_multiple_as_input
from agents.coordination_utils import normalize_time
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from tools.session_manager import SessionManager
from tools.tool_registry import REGISTRY
from utils.logger import logger
from config import MODEL, API_KEY, BASE_URL

# ── Re-export so external code only imports from tools ─────────────────────────
from tools.session_manager import SessionManager as Session

# Max analysis rounds before forcing a report
MAX_ANALYSIS_ROUNDS = 15


class RouterAgent:
    """
    ReAct-driven conversation router.

    Usage:
        router = RouterAgent()
        session = SessionManager()
        response = await router.step("analyze AS135826 from 2025-06-21 to 2025-06-22")
        print(response)
    """

    def __init__(self, model: Optional[str] = None, temperature: Optional[float] = None):
        self.model = model or MODEL
        # Default to the project's reasoning temperature (0.1) instead of 1.0 to
        # keep routing analysis outputs deterministic enough for security use.
        self.temperature = temperature if temperature is not None else DEFAULT_TEMP_REASONING
        self.llm, _ = setup_llm_settings(
            model=self.model,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=temperature,
            timeout=120.0,
        )
        self._round = 0
        self._react_trace = []  # Stores the ReAct thought/action/observation trace

    # ── Public API ────────────────────────────────────────────────────────────

    async def step(
        self,
        user_message: str,
        session: SessionManager,
    ) -> str:
        """
        Process one user message using ReAct loop.

        ReAct Loop:
          1. LLM thinks about what to do
          2. LLM decides action (tool call or final answer)
          3. Execute action, get observation
          4. Repeat until done
        """
        self._round = 0
        self._react_trace = []
        session.add_user_turn(user_message)

        # Parse AS + time from user input
        parsed = self._parse_user_input(user_message)
        if parsed["asn"]:
            session.set_asn(parsed["asn"])
        if parsed["start"] and parsed["end"]:
            session.set_time_window(parsed["start"], parsed["end"])

        # Run ReAct loop
        return await self._react_loop(session, user_message)

    # ── ReAct Loop ───────────────────────────────────────────────────────────

    async def _react_loop(
        self,
        session: SessionManager,
        user_message: str,
    ) -> str:
        """
        The core ReAct loop: Think → Action → Observe → repeat.

        Each iteration:
          - Build context with all previous thoughts/actions/observations
          - Ask LLM to think about next step
          - Parse Thought + Action from response
          - Execute action if it's a tool call
          - Add observation to trace
          - Continue until LLM provides final Answer
        """
        context = self._build_context(session, user_message)

        for round_num in range(MAX_ANALYSIS_ROUNDS):
            self._round = round_num + 1
            logger.info(f"[ReAct] Round {self._round}/{MAX_ANALYSIS_ROUNDS}")

            # Ask LLM for next step
            response = await self._react_think(context, session)

            # Parse response: either Action or Answer
            parsed = self._parse_react_response(response)

            if parsed["type"] == "answer":
                # LLM has completed the analysis
                final_answer = parsed["answer"]
                session.add_agent_turn(f"[Final Answer]\n{final_answer}")
                return final_answer

            elif parsed["type"] == "action":
                thought = parsed["thought"]
                action_name = parsed["action"]
                action_input = parsed["input"]

                # Record thought
                self._react_trace.append({
                    "round": self._round,
                    "thought": thought,
                    "action": action_name,
                    "input": action_input,
                    "observation": None,
                })

                # Execute the tool
                inp = self._inject_defaults(action_input, session)
                logger.info(f"[ReAct] Executing: {action_name}({inp})")

                result = await REGISTRY.call(action_name, inp, session)
                session.add_tool_turn(action_name, inp, result.to_llm_dict())

                # Build observation
                if result.success:
                    observation = result.observation or f"Tool '{action_name}' completed successfully."
                else:
                    observation = f"Tool '{action_name}' failed: {result.error}"

                # Update trace with observation
                self._react_trace[-1]["observation"] = observation
                self._react_trace[-1]["result"] = result.to_llm_dict()

                # Critical tool failure check
                if not result.success and action_name in ("analyze_traffic", "analyze_routing"):
                    return f"Analysis interrupted — {action_name} failed: {result.error}"

                # Update context for next round
                context = self._build_context(session, user_message)

        # Max rounds hit - try to generate report
        logger.warning(f"[ReAct] Max rounds ({MAX_ANALYSIS_ROUNDS}) hit")
        return await self._generate_final_report(session)

    async def _react_think(
        self,
        context: str,
        session: SessionManager,
    ) -> str:
        """Ask the LLM to think about the next step using ReAct format."""

        prompt = f"""You are a BGP network analysis expert using the ReAct (Reasoning + Acting) pattern.

{context}

## Your Task
Analyze BGP network events by thinking step by step, then taking actions.

## ReAct Format
You MUST respond in this EXACT format:

```
Thought: <your reasoning about what to do next>
Action: <tool_name>  (or "Answer" if you're done)
Action Input: <JSON object with parameters>  (or empty for Answer)
```

## Tool Selection Strategy
- Treat the analysis like an investigative workflow: gather core evidence first, then enrich with context when the evidence is weak, ambiguous, or conflicting.
- If traffic evidence is weak or missing, you SHOULD consider calling query_as_info, rpki_validation, as_business_profile, as_topology_position, or long_term_baseline before concluding.
- If routing evidence is incomplete or suspicious but not yet explainable, you SHOULD consider rpki_validation, as_business_profile, as_topology_position, or long_term_baseline to test alternative explanations.
- If the evidence still looks mixed after core analysis, call the reasoning tool and ask it to weigh the evidence; do not force a label.
- Use tool evidence to inform your judgment, but do NOT let any tool make the final causal conclusion for you.
- You are expected to think like an analyst: gather more evidence when needed, compare it, consider alternative explanations, then decide.

## Examples

Example 1 (tool call):
```
Thought: The user wants to analyze AS8422 for hijacking events. I should first gather traffic anomaly data to understand the traffic patterns, then check routing data for BGP anomalies.
Action: analyze_traffic
Action Input: {{"asn": "8422", "start_time": "2025-02-12 10:56", "end_time": "2025-02-12 19:56"}}
```

Example 2 (final answer):
```
Thought: I have gathered comprehensive evidence from traffic analysis, routing analysis, and correlation checks. The data shows a traffic anomaly with z-score of 3.2 coinciding with a BGP path change event. This appears to be a legitimate route change based on the AS relationship analysis.
Action: Answer
Action Input: {{"summary": "Traffic anomaly (z=3.2) detected at 14:32, correlated with BGP path change involving AS1234. Analysis complete with high confidence."}}
```

## Rules
- ALWAYS start with a Thought explaining your reasoning
- If you need data → call analyze_traffic or analyze_routing FIRST
- If the initial evidence is weak, missing, or conflicting → proactively gather context with query_as_info, rpki_validation, as_business_profile, as_topology_position, or long_term_baseline
- If you have traffic data → proceed to routing analysis
- If you have both → compare evidence yourself, decide whether they are related, then provide final answer
- NEVER rely on a tool to make the final causal judgment for you
- NEVER skip gathering evidence before giving a final answer
- NEVER say "insufficient data" without first trying to get data
- Use the session context (ASN, time window) from the context above
- When calling tools, DO NOT rename or shorten required fields

Now, what is your next step?"""

        try:
            resp = await asyncio.to_thread(self.llm.complete, prompt)
            return resp.text if hasattr(resp, "text") else str(resp)
        except Exception as e:
            logger.error(f"[ReAct] LLM think failed: {e}")
            return "Thought: I encountered an error. Let me try to generate a report with what we have.\nAction: Answer\nAction Input: {}"

    def _parse_react_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM's ReAct response into thought, action, and input."""

        # Extract Thought
        thought_match = re.search(r"Thought:\s*(.+?)(?=\nAction:|\nAction Input:|$)", response, re.DOTALL)
        thought = thought_match.group(1).strip() if thought_match else ""

        # Extract Action
        action_match = re.search(r"Action:\s*(\w+)", response)
        action = action_match.group(1).strip() if action_match else ""

        # Extract Action Input. We avoid the lazy ``\{.*?\}`` form here:
        input_match = re.search(r"Action Input:\s*\{", response)
        action_input = {}

        if input_match:
            input_str = response[input_match.end() - 1:].strip()
            # Handle empty or incomplete JSON
            if input_str and input_str != "{}":
                # Bug fix 2026-09-13 (BUG-R107): the previous code did
                from utils.helpers import extract_json_object
                parsed = extract_json_object(input_str)
                if isinstance(parsed, dict):
                    action_input = parsed
                else:
                    # Last-ditch: try ``json.loads`` on the raw string
                    try:
                        action_input = json.loads(input_str)
                    except json.JSONDecodeError:
                        action_input = {}

        # Determine response type
        if action.lower() == "answer":
            # Extract answer from various possible formats
            answer = ""
            if "Action Input:" in response:
                input_part = response.split("Action Input:")[1].strip()
                # Try to parse as JSON with "summary" or "answer" field
                try:
                    parsed = json.loads(input_part)
                    answer = parsed.get("summary") or parsed.get("answer") or input_part
                except:
                    answer = input_part
            else:
                # Answer might be in the response after "Answer"
                answer = response.replace("Action: Answer", "").replace("Action:answer", "").strip()

            return {"type": "answer", "answer": answer, "thought": thought}

        return {
            "type": "action",
            "thought": thought,
            "action": action,
            "input": action_input,
        }

    def _build_context(self, session: SessionManager, user_message: str) -> str:
        """Build the context string for ReAct prompt."""

        tools = REGISTRY.list_tools()
        available_tools = "\n".join([f"- **{t['name']}**: {t['description']}" for t in tools])

        completed = sorted(session.completed_tools)
        evidence = session.get_all_evidence()
        ctx = session.get_context_summary()

        # Format evidence for display
        evidence_lines = []
        for tool_name, tool_data in evidence.items():
            obs = tool_data.get("observation", "")
            if obs:
                # Truncate long observations
                if len(obs) > 500:
                    obs = obs[:500] + "..."
                evidence_lines.append(f"## {tool_name}\n{obs}")

        evidence_str = "\n\n".join(evidence_lines) if evidence_lines else "(No evidence collected yet)"

        # Format ReAct trace
        trace_lines = []
        for entry in self._react_trace[-5:]:  # Last 5 entries
            trace_lines.append(f"- Thought: {entry['thought'][:100]}...")
            trace_lines.append(f"  Action: {entry['action']}")
            if entry['observation']:
                obs = entry['observation']
                if len(obs) > 200:
                    obs = obs[:200] + "..."
                trace_lines.append(f"  Observation: {obs}")

        trace_str = "\n".join(trace_lines) if trace_lines else "(Starting analysis)"

        context = f"""## Session Context
- ASN: {ctx['asn'] or 'Not specified'}
- Time Window: {ctx['time_window']}
- Round: {self._round}/{MAX_ANALYSIS_ROUNDS}

## User Request
{user_message}

## Available Tools
{available_tools}

## Completed Tools
{completed if completed else "(None yet)"}

## Evidence Collected
{evidence_str}

## Recent Thought/Action History (for continuity)
{trace_str}

## Completed Tools Status
- analyze_traffic: {"✓" if "analyze_traffic" in completed else "✗"}
- analyze_routing: {"✓" if "analyze_routing" in completed else "✗"}
- reason_and_classify: {"✓" if "reason_and_classify" in completed else "✗"}
- generate_report: {"✓" if "generate_report" in completed else "✗"}"""

        return context

    # ── Final report ───────────────────────────────────────────────────────────

    async def _generate_final_report(self, session: SessionManager) -> str:
        """Call generate_report and return the result path."""
        inp = {
            "asn": session.asn or "",
            "start_time": session.start_time or "",
            "end_time": session.end_time or "",
            "traffic_result": session.get_evidence("analyze_traffic", {}).get("results", {}),
            "routing_result": session.get_evidence("analyze_routing", {}).get("result", {}),
            "classification": session.get_evidence("reason_and_classify", {}).get("classification", {}),
            "asn_info": session.get_evidence("query_as_info", {}).get("info", {}),
        }

        result = await REGISTRY.call("generate_report", inp, session)
        session.add_tool_turn("generate_report", inp, result.to_llm_dict())

        if result.success and result.data.get("report_path"):
            path = result.data["report_path"]
            session.report_path = path
            session.save()
            msg = f"Analysis complete. Report saved to: {path}"
            session.add_agent_turn(msg)
            return msg
        else:
            msg = f"Report generation failed: {result.error}"
            session.add_agent_turn(msg)
            return msg

    # ── Utilities ──────────────────────────────────────────────────────────────

    def _parse_user_input(self, text: str) -> dict:
        """
        Extract AS number(s) and time window from natural language.
        """
        asn_list = []
        for m in re.finditer(r"AS(\d+)", text, re.IGNORECASE):
            asn_list.append(m.group(1))

        if not asn_list and "," in text:
            for m in re.finditer(r"(?<![A-Z])(\d{3,6})(?![A-Z0-9])", text):
                asn_list.append(m.group(1))

        start, end = None, None

        # Format: "from START to END"
        m = re.search(
            r"from\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)\s+to\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)",
            text,
        )
        if m:
            start = normalize_time(m.group(1))
            end = normalize_time(m.group(2))

        # Format: "START and END"
        if not start:
            m = re.search(
                r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)\s+(?:and|to|,)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)",
                text,
            )
            if m:
                start = normalize_time(m.group(1))
                end = normalize_time(m.group(2))

        # Format: single date "on 2025-07-24"
        if not start:
            m = re.search(r"on\s+(\d{4}-\d{2}-\d{2})", text)
            if m:
                start = normalize_time(m.group(1) + " 00:00")
                end = normalize_time(m.group(1) + " 23:59")

        return {
            "asn": asn_list[0] if asn_list else None,
            "asn_list": asn_list,
            "start": start,
            "end": end,
        }

    def _inject_defaults(self, inp: dict, session: SessionManager) -> dict:
        """Fill in session context if not already present."""
        inp = dict(inp)
        if not inp.get("asn") and session.asn:
            inp["asn"] = session.asn
        if not inp.get("start_time") and session.start_time:
            inp["start_time"] = session.start_time
        if not inp.get("end_time") and session.end_time:
            inp["end_time"] = session.end_time
        return inp
