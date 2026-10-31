from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import Optional

import polars as pl

from workflow_engine import (
    WorkflowEngine,
    WorkflowContext,
    WorkflowState,
    run_workflow,
)
from agents.traffic_agent import (
    parse_country_region_input,
    parse_multiple_as_input,
    run_traffic_agent,
)
from agents.reasoning_agent import run_reasoning_agent, run_reasoning_agent_batch
from agents.routing_agent import run_routing_agent_async
from agents.cache_compaction import compact_cache_payload
from agents.react_agent import valid_llm_html_report
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from utils.helpers import make_json_safe
from utils.logger import logger
from utils.report_exporters import generate_comprehensive_report, generate_batch_html_report
from agents.coordination_utils import (
    lookup_org_info,
    normalize_time,
    query_as_relationships,
    query_as_prefixes,
)
from config import API_KEY, BASE_URL, MODEL, MITM_DETECTION_ENABLED, JSON_OUTPUT_ENABLED

PROJECT_ROOT = Path(__file__).parent


def unwrap_result(payload):
    """Return the detector result inside a react tool's payload.

    The react tools wrap their output in ``{"success": ..., "result":
    ...}``, and the traffic tool nests it one level further under
    ``results`` keyed by AS.  The attribution needs the detector's own
    dict, so the wrappers are peeled here rather than at every call
    site.
    """
    if not isinstance(payload, dict):
        return {}
    inner = payload.get("result")
    if isinstance(inner, dict) and inner:
        return inner
    return payload


def per_asn_results(traffic_result):
    """Yield the per-AS traffic detector results."""
    if not isinstance(traffic_result, dict):
        return
    results = traffic_result.get("results")
    if isinstance(results, dict) and results:
        for value in results.values():
            if isinstance(value, dict):
                yield value
        return
    if isinstance(results, list):
        for value in results:
            if isinstance(value, dict):
                yield value
        return
    yield traffic_result


def parse_ts_value(value):
    """Parse a timestamp into the naive-UTC form the estimator works on."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        from agents.temporal import parse_timestamp
        return parse_timestamp(value)
    except (AttributeError, TypeError, ValueError):
        return None


class ChiefExpertAgent:
    """Chief Expert Agent — main orchestrator for BGP analysis."""

    def __init__(
        self,
        model,
        api_key,
        base_url,
        analysis_mode="traffic_first",
        enable_mitm=MITM_DETECTION_ENABLED,
        debate_rounds: int = 1,
        evaluation_retries: int = 2,
    ):
        # Legacy alias: strip "_enhanced" suffix (enhanced mode removed 2026-09-29).
        if analysis_mode.endswith("_enhanced"):
            analysis_mode = analysis_mode.replace("_enhanced", "")
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.analysis_mode = analysis_mode
        self.enable_mitm = enable_mitm
        # Stored for backward compat with old callers passing these kwargs.
        self.debate_rounds = debate_rounds
        self.evaluation_retries = evaluation_retries
        self.llm = None
        self.token_counter = None
        self.asrel_file = None
        self.prefix2as_file = None
        self.asorg_file = None
        self.reasoning_analysis_result = None
        self.engine_instance = None
        self._streaming_callback = None
    
    def detect_output_language(self, user_input):
        """Detect output language from user input."""
        if not user_input:
            return "en"

        text = str(user_input).lower()
        # CJK Unified Ideographs (U+4E00..U+9FFF) for common BGP-analysis
        # terms.  The list is encoded as codepoints so a bulk identifier
        # rename cannot silently rewrite them to ASCII.
        cjk_terms = [
            "\u5e2e\u6211",  # bangwo  (help me)
            "\u5206\u6790",  # fenxi   (analyze)
            "\u5f02\u5e38",  # yichang (anomaly)
            "\u60c5\u51b5",  # qingkuang (situation)
            "\u52ab\u6301",  # jiechi  (hijack)
            "\u8def\u7531",  # luyou   (routing)
            "\u6d41\u91cf",  # liuliang (traffic)
            "\u8bf7",        # qing    (please)
            "\u5230",        # dao     (arrive)
        ]
        if any(term in text for term in cjk_terms):
            return "zh"
        return "en"


    @property
    def workflow_engine(self):
        """Get or create workflow engine instance."""
        if self.engine_instance is None:
            self.engine_instance = WorkflowEngine(
                max_retries=3,
                parallel_execution=True,
                skip_unnecessary_analysis=False,
                debate_rounds=self.debate_rounds,
                evaluation_retries=self.evaluation_retries,
            )
        return self.engine_instance
    
    async def setup_llm(self):
        """Initialize the LLM client."""
        self.llm, self.token_counter = setup_llm_settings(
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=DEFAULT_TEMP_REASONING,
            timeout=300.0,
            max_retries=2
        )
    
    # ── Main Coordination ───────────────────────────────────────────────────

    async def coordinate_analysis(
        self,
        user_input = None,
        asn = None,
        start_time = None,
        end_time = None,
        streaming_callback = None,
        precomputed_routing = None,
        precomputed_traffic = None,
    ):
        """Main coordination method - dispatches to appropriate mode.
        
        Returns:
        Analysis result dictionary"""
        t0 = perf_counter()
        event_start = datetime.now()

        # Store streaming callback for React mode
        self._streaming_callback = streaming_callback

        # Handle batch/special cases first
        if user_input and not (asn and start_time and end_time):
            batch_result = await self.handle_batch_input(user_input)
            if batch_result:
                return batch_result

        output_language = self.detect_output_language(user_input)

        # Validate parameters
        if user_input:
            if not (start_time and end_time):
                return {"success": False, "error": "Missing start_time, end_time"}
        else:
            if not all([asn, start_time, end_time]):
                return {"success": False, "error": "Missing asn, start_time, end_time"}

        if self.analysis_mode == "react":
            return await self.react_analysis_flow(
                asn, start_time, end_time, user_input, t0, event_start,
                precomputed_routing=precomputed_routing,
                precomputed_traffic=precomputed_traffic,
            )
        return await self.workflow_analysis_flow(
            asn, start_time, end_time, user_input, t0, event_start,
            precomputed_routing=precomputed_routing,
            precomputed_traffic=precomputed_traffic,
        )

    async def handle_batch_input(self, user_input):
        """Handle batch analysis requests."""
        as_list, multi_start, multi_end = parse_multiple_as_input(user_input)

        if as_list and len(as_list) > 1:
            if len(as_list) > 10:
                return {
                    "success": False,
                    "error": f"Too many AS numbers ({len(as_list)}). Please select up to 10 AS.",
                    "user_input": user_input,
                    "detected_as_list": as_list
                }

            if not (multi_start and multi_end):
                return {
                    "success": False,
                    "error": "Time period required for batch analysis.",
                    "user_input": user_input,
                    "detected_as_list": as_list
                }

            # Use legacy batch for now (workflow engine batch support TBD)
            batch_result = run_reasoning_agent_batch(
                as_list=as_list,
                start_time=normalize_time(multi_start),
                end_time=normalize_time(multi_end)
            )

            html_path = None
            if batch_result.get("success"):
                try:
                    html_path = generate_batch_html_report(
                        batch_result={"batch_result": batch_result},
                        start_time=normalize_time(multi_start),
                        end_time=normalize_time(multi_end),
                        output_dir=PROJECT_ROOT / "results"
                    )
                except (AttributeError) as e:
                    logger.warning(f"Batch HTML report failed: {e}")

            return {
                "success": True,
                "batch_mode": True,
                "analysis_type": "multi_as_batch_analysis",
                "as_count": len(as_list),
                "as_list": as_list,
                "batch_result": batch_result,
                "html_report_path": html_path,
                "user_input": user_input
            }

        # Try country-based analysis - if single AS, return None to let caller handle it
        country_region, c_start, c_end, c_asn = parse_country_region_input(user_input)
        if c_asn:
            # Single AS case - don't handle here, let caller run workflow analysis
            return None

        return None

    # ── React Mode (v4.0) ─────────────────────────────────────────────────────

    @staticmethod
    def extract_react_token_count(result, tok_before=None):
        """Sum token usage across all ReAct LLM calls recorded in the trace."""
        try:
            # Prefer the explicit counter if the agent records one
            for attr in ("total_tokens", "tokens", "token_count"):
                v = getattr(result, attr, None)
                if v:
                    return int(v)
        except (ValueError):
            pass
        try:
            from llm.llm_factory import get_global_token_counter
            now = int(get_global_token_counter())
            if tok_before is not None:
                return max(0, now - int(tok_before))
            return now
        except (ValueError):
            pass
        return 0

    async def react_analysis_flow(
        self,
        asn,
        start_time,
        end_time,
        user_input,
        t0,
        event_start,
        precomputed_routing = None,
        precomputed_traffic = None,
        enhanced = False,
    ):
        """React-mode analysis (Reasoning + Acting)."""
        logger.info(f"Using React Agent for AS{asn} analysis (enhanced={enhanced})")
        logger.info(f"Analysis mode: react (streaming: {self._streaming_callback is not None})")

        try:
            from agents.react_agent import ReactAgent

            if self.llm is None:
                await self.setup_llm()

            from config import REACT_MAX_ROUNDS, REACT_STREAMING_ENABLED
            agent = ReactAgent(
                llm=self.llm,
                max_rounds=REACT_MAX_ROUNDS,
                streaming_callback=self._streaming_callback if REACT_STREAMING_ENABLED else None,
            )

            try:
                from llm.llm_factory import get_global_token_counter as _gtc
                _tok_before = int(_gtc())
            except (ValueError):
                _tok_before = None

            result = await agent.run(
                asn=str(asn),
                start_time=str(start_time),
                end_time=str(end_time),
                user_input=user_input
            )

            # Process result
            elapsed = (datetime.now() - event_start).total_seconds()

            # use result.evidence (instance variable copy) as priority, fall back to old global variable
            report_path = result.report_path or (
                getattr(result, "evidence", {}).get("generate_report", {}) or {}
            ).get("report_path", "")
            # fallback to global lookup (per-run bucket only)
            try:
                from agents.react_agent import shared_evidence
                _bucket = shared_evidence(result.run_id) if result.run_id else {}
                report_path = report_path or (
                    (_bucket.get("generate_report") or {}).get("report_path", "")
                )
            except (ValueError):
                pass
            report_generated = valid_llm_html_report(report_path)
            partial_success = bool(result.success) and report_generated

            # react mode: process HCAF causal attribution
            hcaf_attribution, hcaf_status = self.post_react_hcaf(result)

            return {
                "success": partial_success,
                "react_mode": True,
                "chief_expert_analysis": {
                    "coordination_summary": "React (Reasoning + Acting) execution completed",
                    "analysis_method": "LLM-driven ReAct pattern v4.0",
                    "analysis_mode": "react",
                    "target_as": asn,
                    "time_range": f"{start_time} to {end_time}",
                    "total_rounds": result.total_rounds,
                    "tools_used": result.tools_used,
                    "elapsed_seconds": elapsed,
                    "answer": result.answer,
                    "trace_summary": agent.get_trace_summary(),
                    "report_generated": report_generated,
                    "html_report_path": report_path,
                    "data_quality": (
                        "high" if (result.success and report_generated) else "medium"
                    ),
                    "confidence_score": (
                        0.7 if (result.success and report_generated) else 0.3
                    ),
                    "evidence_verdict": (
                        "answered" if result.answer else "no_answer"
                    ),
                    "traffic_anomaly_count": None,
                    "routing_anomaly_count": 0,
                },
                "react_result": {
                    "success": result.success,
                    "answer": result.answer,
                    "trace": [
                        {
                            "round": e.round_num,
                            "thought": e.thought[:200] + "..." if len(e.thought) > 200 else e.thought,
                            "action": e.action,
                            "observation": e.observation[:200] + "..." if len(e.observation) > 200 else e.observation,
                            "error": e.error,
                        }
                        for e in result.trace
                    ],
                    "tools_used": result.tools_used,
                    "total_rounds": result.total_rounds,
                },
                "token_count": extract_react_token_count(result, _tok_before),
                "execution_time_minutes": elapsed / 60.0,
                "execution_time_seconds": elapsed,
                # HCAF attribution result (added when fixing Bug #6)
                "hcaf_attribution": hcaf_attribution,
                "hcaf_attribution_status": hcaf_status,
                "elapsed_seconds": elapsed,
                "error": result.error if not result.success else None,
                "event_start_time": event_start.isoformat(),
                "event_end_time": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"React agent failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Fallback to legacy mode
            return await self.legacy_direct_analysis(
                asn, start_time, end_time, user_input, t0, event_start
            )

    def post_react_hcaf(self, react_result):
        """Post-React PADDLE directional attribution.

        Returns (attribution_dict, status_string). Never returns None.

        The react run leaves the *detector results* in the shared
        evidence bucket, not just a summary timeline.  PADDLE needs the
        full result: the control plane is measured on the detector's own
        routing features (the target's **own** announcements, which is
        the channel that falls silent during an outage), and the traffic
        side needs each observation's value **and** the historical mean
        it was compared against, because that pair -- not the stored
        z-score -- is what carries the direction of the departure.

        A run that left only a summary timeline cannot support a
        directional claim, and the estimator is asked to abstain rather
        than to be handed a degraded input.
        """
        try:
            from agents.paddle_runtime import run_paddle
        except ImportError:
            logger.debug("[HCAF] paddle_runtime not available; skipping post-react attribution")
            return {}, "skipped_no_engine"

        try:
            evidence = getattr(react_result, "evidence", None) or {}
            if not evidence:
                try:
                    from agents.react_agent import shared_evidence
                    if react_result.run_id:
                        evidence = shared_evidence(react_result.run_id) or {}
                except (ValueError):
                    evidence = {}

            routing_payload = evidence.get("analyze_routing") or {}
            traffic_payload = evidence.get("analyze_traffic") or {}
            if not routing_payload:
                routing_payload = evidence.get("precomputed_routing") or {}
            if not traffic_payload:
                traffic_payload = evidence.get("precomputed_traffic") or {}

            routing_result = unwrap_result(routing_payload)
            traffic_result = unwrap_result(traffic_payload)

            if not routing_result or not traffic_result:
                return {}, "skipped_no_data"

            # The traffic detector's own anomaly list carries the value
            # and the baseline it was compared against.  The serialised
            # event stream is not used here: it carries a placeholder
            # baseline, and a consumer that reads it reconstructs a
            # deviation of hundreds of standard deviations with the sign
            # inverted.
            traffic_timeline = []
            for asn_result in per_asn_results(traffic_result):
                for anomaly in (asn_result.get("anomalies") or []):
                    if not isinstance(anomaly, dict):
                        continue
                    stamp = anomaly.get("timestamp") or anomaly.get("time")
                    if not stamp:
                        continue
                    traffic_timeline.append({
                        "timestamp": stamp,
                        "event_type": "traffic_anomaly",
                        "raw_event": anomaly,
                    })
                break

            routing_timeline = []
            routing_context = {}
            for key in ("origin_hijacked", "forge_hijacked",
                        "origin_hijacking", "forge_hijacking",
                        "route_leaks"):
                for event in (routing_result.get(key) or []):
                    if not isinstance(event, dict):
                        continue
                    stamp = (event.get("timestamp") or event.get("first_seen")
                             or event.get("time"))
                    if not stamp:
                        continue
                    routing_timeline.append({
                        "timestamp": stamp,
                        "event_type": event.get("event_type") or event.get("type"),
                        "raw_event": event,
                    })

            outage = (routing_result.get("outage_analysis")
                      or routing_result.get("outage") or {})
            if outage.get("is_outage_suspected"):
                stamp = outage.get("timestamp") or outage.get("first_seen")
                if stamp:
                    routing_timeline.append({
                        "timestamp": stamp,
                        "event_type": "outage",
                        "raw_event": outage,
                    })

            if not traffic_timeline:
                return {}, "skipped_no_data"

            window_start = parse_ts_value(getattr(react_result, "start_time", None))
            window_end = parse_ts_value(getattr(react_result, "end_time", None))

            verdict, control_series, _observations = run_paddle(
                routing_analysis=outage,
                traffic_timeline=traffic_timeline,
                routing_timeline=routing_timeline,
                routing_context=routing_context,
                traffic_block=traffic_result,
                window_start=window_start,
                window_end=window_end,
            )
            attribution = {
                "direction": verdict.direction if verdict.committed else "unknown",
                "committed": verdict.committed,
                "reason": verdict.reason,
                "vetoes": dict(verdict.vetoes),
                "channel": verdict.channel,
                "lag": verdict.lag_seconds,
                "effect": verdict.effect,
                "exclusivity_ratio": verdict.exclusivity_ratio,
                "tau_traffic": (verdict.tau_response.isoformat()
                                if verdict.tau_response else None),
                "tau_routing": verdict.tau_control,
            }
            logger.info(
                f"[PADDLE post-react] direction={attribution['direction']} "
                f"reason={attribution['reason']} channel={attribution['channel']}")
            return attribution, "ok"

        except (AttributeError) as e:
            logger.warning(f"[HCAF post-react] failed: {e}")
            return {}, "failed"

    # ── Workflow Engine Mode ─────────────────────────────────────────────────

    async def workflow_analysis_flow(
        self,
        asn,
        start_time,
        end_time,
        user_input,
        t0,
        event_start: datetime,
        precomputed_routing = None,
        precomputed_traffic = None,
    ):
        """Execute analysis using the new workflow engine."""
        logger.info(f"Using Workflow Engine for AS{asn} analysis")
        logger.info(f"Analysis mode: {self.analysis_mode}")
        logger.info(f"MITM detection: {'enabled' if self.enable_mitm else 'disabled'}")

        # Snapshot the process-wide token counter so the reported figure is
        # a per-run delta rather than the process total.
        try:
            from llm.llm_factory import get_global_token_counter as _gtc
            _tok_before = int(_gtc())
        except (ValueError):
            _tok_before = None

        try:
            # Run workflow with analysis mode
            context = await run_workflow(
                user_input=user_input,
                asn=asn,
                start_time=start_time,
                end_time=end_time,
                max_retries=3,
                analysis_mode=self.analysis_mode,
                enable_mitm=self.enable_mitm,
                debate_rounds=self.debate_rounds,
                evaluation_retries=self.evaluation_retries,
                precomputed_routing=precomputed_routing,
                precomputed_traffic=precomputed_traffic,
            )

            # Process workflow result. `run_workflow` may return either a
            # WorkflowContext dataclass or, on resume / fallback, a plain
            # dict (snapshot of the same data). Handle both.
            if isinstance(context, dict):
                result = context
            else:
                result = self.process_workflow_result(
                    context, asn, start_time, end_time, t0, event_start,
                    tok_before=_tok_before,
                )
            # Mirror the saved LLM HTML path into both analysis_report and
            # report_result so downstream scripts (run_batch_reality_cases.py)
            # can verify it without reaching into chief_expert_analysis.
            saved_path = ""
            for key in ("chief_expert_analysis", "report_result", "analysis_report"):
                block = result.get(key)
                if isinstance(block, dict):
                    cand = block.get("html_report_path")
                    if isinstance(cand, str) and cand:
                        saved_path = cand
                        # Don't break — keep looping so all three blocks end
                        # up with the same value rather than leaving the
                        # downstream aliases blank.
                        for k in ("chief_expert_analysis", "report_result", "analysis_report"):
                            blk = result.get(k)
                            if isinstance(blk, dict):
                                blk.setdefault("html_report_path", cand)
                        break
            return result

        except Exception as e:
            logger.error(f"Workflow engine failed: {e}")
            # Fallback to legacy mode
            return await self.legacy_direct_analysis(
                asn, start_time, end_time, user_input, t0, event_start
            )

    def process_workflow_result(
        self,
        context: WorkflowContext,
        asn,
        start_time,
        end_time,
        t0,
        event_start: datetime,
        tok_before=None
    ):
        """Process workflow result into standard format."""
        elapsed = (datetime.now() - event_start).total_seconds()
        
        # Build result from context
        result = {
            "success": context.current_state == WorkflowState.COMPLETE,
            "chief_expert_analysis": {
                "coordination_summary": "Workflow engine execution completed",
                "analysis_method": "Graph-based workflow v3.0",
                "coordination_strategy": "Traffic first, routing on demand",
                "workflow_states": [t.from_state.name for t in context.transitions],
                "analysis_mode": context.analysis_mode.value if hasattr(context.analysis_mode, "value") else str(context.analysis_mode),
                "enhanced": getattr(context, "enhanced", False),
                "data_quality": self.derive_data_quality(context),
                "confidence_score": self.derive_confidence_score(context),
                "evidence_verdict": self.derive_verdict(context),
                "traffic_anomaly_count": (
                    (context.traffic_result or {}).get("anomaly_count")
                    if isinstance(context.traffic_result, dict) else None
                ),
                "routing_anomaly_count": self.count_routing_anomalies(context),
                "html_report_path": context.report_path,
            },
            "smart_cascade": {
                "analysis_mode": context.analysis_mode.value if hasattr(context.analysis_mode, "value") else str(context.analysis_mode),
                "screening_result": context.screening_result,
                "needs_traffic_deep_analysis": context.needs_traffic_deep_analysis,
                "needs_routing_analysis": context.needs_routing_analysis,
                "routing_analysis_detail": context.routing_analysis_detail,
                "traffic_ok_but_routing_anomaly": context.traffic_ok_but_routing_anomaly,
                "validation_notes": context.validation_notes,
            },
            "token_count": self.extract_token_count(context, tok_before=tok_before),
            "reasoning_result": context.reasoning_result or {},
            "diagnosis_result": context.diagnosis_result or {},
            "verification_result": context.verification_result or {},
            "experiment_metrics": context.experiment_metrics or {},
            "hcaf_attribution": context.hcaf_attribution or {},
            "hcaf_attribution_status": context.hcaf_attribution_status or "skipped",
            "causal_analysis": getattr(context, "causal_analysis", None) or {},
            "evidence_chain": getattr(context, "evidence_chain", None) or {},
            "joint_tier": getattr(context, "joint_tier", "") or "",
            "joint_score": round(float(getattr(context, "joint_score", 0.0) or 0.0), 3),
            "joint_evidence_cards": getattr(context, "joint_evidence_cards", []) or [],
            "joint_rationale": getattr(context, "joint_rationale", "") or "",
            # Which coordination stages ran. The ablation harness checks
            # this against the arm's intent, so an arm that disabled one
            # stage but also skipped another is caught rather than
            # silently reported as a larger delta.
            "stage_execution": getattr(context, "stage_execution", {}) or {},
            "victim_asns": getattr(context, "victim_asns", []) or [],
            "evidence_board": {
                "observations": context.evidence_records,
                "claims": context.diagnosis_claims,
                "verdicts": context.verification_records,
                "challenges": context.contradictions,
                "alternatives": getattr(context, "evidence_alternatives", []) or [],
                "gaps": getattr(context, "evidence_gaps", []) or [],
                "causal_attribution": context.hcaf_attribution or {},
            },
            "analysis_report": context.final_result or {},
            "report_result": context.final_result or {},
            "org_info": context.org_info or {},
            "relationships": context.as_relationships or {},
            "prefixes": context.as_prefixes or {},
            "reasoning_trace": self.build_trace(context),
            "errors": context.errors,
            "execution_time_minutes": elapsed / 60,
            "event_start_time": event_start.isoformat(),
            "event_end_time": datetime.now().isoformat(),
        }

        if context.report_path:
            result["chief_expert_analysis"]["html_report_path"] = context.report_path
            result["analysis_report"]["html_report_path"] = context.report_path
            result["report_result"]["html_report_path"] = context.report_path

        return result

    def extract_token_count(self, context, tok_before=None):
        """Extract total token count for this run."""
        tokens = 0

        # Method 1: From reasoning_result (per-agent breakdown)
        for result in [context.traffic_result, context.routing_result, context.reasoning_result]:
            if result and isinstance(result, dict):
                token_usage = result.get("token_usage", {})
                if isinstance(token_usage, dict):
                    if "total_across_agents" in token_usage:
                        try:
                            value = int(token_usage["total_across_agents"] or 0)
                        except (TypeError, ValueError):
                            value = 0
                        if value > tokens:
                            tokens = value
                    else:
                        for agent_tokens in token_usage.values():
                            if isinstance(agent_tokens, dict):
                                tokens += agent_tokens.get("total", 0) or agent_tokens.get("total_tokens", 0)
                            elif isinstance(agent_tokens, int):
                                tokens += agent_tokens

        # Method 2: From TokenBudget (unified tracking)
        try:
            from agents.token_budget import TokenBudget
            if context.message_bus_run_id:
                tb = TokenBudget.get_instance(context.message_bus_run_id)
                pt, ct = tb.total()
                if pt + ct > tokens:
                    tokens = pt + ct
                    tb_summary = tb.summary()
                    logger.info(
                        f"[TokenBudget] run_id={context.message_bus_run_id}: "
                        f"total={tokens} (prompt={pt}, completion={ct}), "
                        f"by_agent={list(tb_summary['by_agent'].keys())}"
                    )
        except (ValueError):
            pass

        # Method 3: process-wide counter, measured as a delta over the run
        if tok_before is not None:
            try:
                from llm.llm_factory import get_global_token_counter
                delta = max(0, int(get_global_token_counter()) - int(tok_before))
                if delta > tokens:
                    tokens = delta
            except (ValueError):
                pass

        return tokens

    # ── Quality derivation helpers (Bug fix: token/quality previously N/A) ──
    @staticmethod
    def derive_verdict(context):
        """Best-effort verdict string from the evidence chain."""
        ec = getattr(context, "evidence_chain", None)
        if isinstance(ec, dict):
            verdict = ec.get("verdict")
            if verdict:
                return str(verdict)
        return "unknown"

    @staticmethod
    def derive_confidence_score(context):
        """Best-effort confidence score in [0, 1]."""
        ec = getattr(context, "evidence_chain", None)
        if isinstance(ec, dict):
            conf = ec.get("confidence")
            if conf is not None:
                try:
                    return float(conf)
                except (TypeError, ValueError):
                    pass
        # Fallback: rough heuristic from anomaly counts
        try:
            t_anom = (context.traffic_result or {}).get("anomaly_count", 0) or 0
            r_anom = 0
            rr = context.routing_result or {}
            for k in ("anomaly_count", "hijack_count", "leak_count", "outage_count"):
                r_anom += int(rr.get(k) or 0)
            # More anomalies → higher confidence. 0 anomalies → low confidence.
            return min(1.0, 0.2 + 0.15 * min(t_anom, 4) + 0.20 * min(r_anom, 2))
        except (ValueError):
            return 0.0

    @staticmethod
    def derive_data_quality(context):
        """High/medium/low based on data availability + verdict."""
        ec = getattr(context, "evidence_chain", None)
        if isinstance(ec, dict):
            verdict = str(ec.get("verdict") or "")
            if "inconclusive" in verdict or "missing" in verdict:
                return "low"
        traffic_ok = bool(
            (context.traffic_result or {}).get("success")
            or (context.traffic_result or {}).get("data_available")
        )
        routing_ok = bool(
            (context.routing_result or {}).get("success")
            or (context.routing_result or {}).get("data_available")
        )
        if traffic_ok and routing_ok:
            return "high"
        if traffic_ok or routing_ok:
            return "medium"
        return "low"

    @staticmethod
    def count_routing_anomalies(context):
        rr = context.routing_result or {}
        try:
            count = int(rr.get("anomaly_count") or 0)
            if count > 0:
                return count
            for k in ("hijack_count", "leak_count", "outage_count"):
                count += int(rr.get(k) or 0)
            if count > 0:
                return count
            # Fallback: count entries in anomaly-style lists
            for k in ("origin_hijacked", "forge_hijacked", "path_leak",
                      "outage_events", "events"):
                lst = rr.get(k) or []
                if isinstance(lst, list) and lst:
                    return len(lst)
            return 0
        except (ValueError):
            return 0

    def build_trace(self, context):
        """Build execution trace from context transitions."""
        trace = []
        for i, transition in enumerate(context.transitions):
            trace.append({
                "step": i,
                "from_state": transition.from_state.name,
                "to_state": transition.to_state.name,
                "event": transition.event.name,
                "duration_ms": transition.duration_ms,
                "timestamp": transition.timestamp.isoformat()
            })
        return trace

    # ── Legacy Direct Mode ──────────────────────────────────────────────────

    async def legacy_direct_analysis(
        self,
        asn,
        start_time,
        end_time,
        user_input,
        t0,
        event_start: datetime,
        traffic_result=None,
        routing_result=None,
        routing_initial=None,
        reasoning_result=None,
    ):
        """Legacy direct analysis mode (original implementation).
        
        Kept for backward compatibility and as fallback."""
        logger.info(f"Using Legacy Direct Mode for AS{asn} analysis")

        # ── Stage 1: traffic ──────────────────────────────────────────
        if traffic_result is None:
            traffic_result = run_traffic_agent(
                user_input=user_input,
                asn=asn,
                start_time=start_time,
                end_time=end_time,
            )
        else:
            logger.info(f"[Resume] Skipped traffic stage for AS{asn}")

        if routing_initial is None:
            # Initial routing scan: run all 3 detectors by default. The
            routing_initial = await run_routing_agent_async(
                asn, start_time, end_time, use_llm=False, skip_outage=False,
                skip_forge=True,
            )
        else:
            logger.info(f"[Resume] Skipped initial routing stage for AS{asn}")

        traffic_anomaly_count = traffic_result.get('anomaly_count', 0)
        # BUG-R141 2026-09-29: this used to read only
        routing_anomaly_count = (
            routing_initial.get('total_prefix_hijacks', 0)
            or 0
        ) + (
            len(routing_initial.get('route_leaks') or [])
            or routing_initial.get('leak_count', 0)
            or 0
        )

        if traffic_anomaly_count + routing_anomaly_count == 0:
            return self.build_no_anomaly_result(
                asn, start_time, end_time, traffic_result, routing_initial, t0, event_start
            )

        detected_start, detected_end = self.extract_anomaly_times(
            traffic_result, start_time, end_time
        )

        # ── Stage 2: routing (with detected window) ──────────────────
        if routing_result is None:
            # Deep routing pass: run outage detection too. The Phase-1
            routing_result = await run_routing_agent_async(
                asn, detected_start, detected_end, use_llm=True, skip_outage=False,
                skip_forge=True,
            )
        else:
            logger.info(f"[Resume] Skipped routing stage for AS{asn}")

        # ── Stage 3: reasoning ────────────────────────────────────────
        if reasoning_result is None:
            reasoning_result = run_reasoning_agent(
                asn=asn,
                start_time=detected_start,
                end_time=detected_end,
                user_input=user_input,
                pre_computed_routing=routing_result,
                pre_computed_traffic=traffic_result,
            )
        else:
            logger.info(f"[Resume] Skipped reasoning stage for AS{asn}")

        if not reasoning_result.get("success", False):
            error_msg = reasoning_result.get("error", "Unknown error")
            raise RuntimeError(f"Reasoning agent failed: {error_msg}")

        self.reasoning_analysis_result = reasoning_result
        self.asrel_file = reasoning_result.get("as_rel_file")
        self.prefix2as_file = reasoning_result.get("prefix2as_file")
        self.asorg_file = reasoning_result.get("asorg_file")

        org_info = {}
        if self.asorg_file:
            org_info = lookup_org_info(str(asn), self.asorg_file)

        relationships = query_as_relationships(str(asn), self.asrel_file) if self.asrel_file else {}
        prefixes = query_as_prefixes(str(asn), self.prefix2as_file) if self.prefix2as_file else {}

        await self.setup_llm()

        report_result = await self.generate_report(
            routing_result, traffic_result, reasoning_result,
            asn, start_time, detected_end, org_info
        )

        elapsed = (datetime.now() - event_start).total_seconds()

        result = {
            "chief_expert_analysis": {
                "coordination_summary": "Direct call mode completed",
                "analysis_method": "Legacy Direct Analysis Flow",
                "target_as": asn,
                "time_range": f"{start_time} to {end_time}",
                "analysis_timestamp": datetime.now().isoformat(),
                "llm_model": self.model,
                "coordination_strategy": "Direct function calls",
                "elapsed_seconds": round(perf_counter() - t0, 3),
            },
            "token_count": self.extract_tokens(reasoning_result),
            "reasoning_result": reasoning_result,
            "analysis_report": report_result,
            "report_result": report_result,
            "org_info": org_info,
            "relationships": relationships,
            "prefixes": prefixes,
            "reasoning_trace": [{"step": 0, "action": "DirectCall", "observation": "Direct analysis"}],
            "execution_time_seconds": elapsed,
            "execution_time_minutes": elapsed / 60,
            "event_start_time": event_start.isoformat(),
            "event_end_time": datetime.now().isoformat(),
        }

        return result

    def build_no_anomaly_result(
        self,
        asn,
        start_time,
        end_time,
        traffic_result,
        routing_result,
        t0,
        event_start: datetime
    ):
        """Build result when no anomalies are detected."""
        mock_reasoning = {
            'asn': asn,
            'time_range': f"{start_time} to {end_time}",
            'confidence_score': 0.9,
            'key_findings': [f'No anomalies detected for AS{asn}'],
            'evidence_summary': {
                'data_quality': 'Good',
                'traffic_data': traffic_result,
                'routing_data': routing_result
            }
        }

        report_result = generate_comprehensive_report(
            llm=self.llm,
            routing_analysis=routing_result,
            traffic_analysis=traffic_result,
            law_analysis=None,
            reasoning_analysis=mock_reasoning,
            start_time=start_time,
            user_input_time_range=f"{start_time} to {end_time}",
            output_dir=str(PROJECT_ROOT / "results" / "html"),
            asn=asn,
        )

        elapsed = (datetime.now() - event_start).total_seconds()

        return {
            "success": True,
            "chief_expert_analysis": {
                "success": True,
                "message": f"No anomalies for AS{asn} ({start_time} to {end_time})",
                "traffic_anomalies": 0,
                "routing_anomalies": 0,
                "analysis_time": perf_counter() - t0,
                "html_report_path": report_result.get("html_report_path"),
                "json_report_path": report_result.get("json_report_path"),
                "analysis_report": report_result,
                "reasoning_trace": [],
                "analysis_timestamp": datetime.now().isoformat()
            },
            "token_count": 0,
            "reasoning_result": {},
            "analysis_report": report_result,
            "report_result": report_result,
            "reasoning_trace": [],
            "execution_time_seconds": elapsed,
            "execution_time_minutes": elapsed / 60,
            "event_start_time": event_start.isoformat(),
            "event_end_time": datetime.now().isoformat(),
        }

    def extract_anomaly_times(
        self,
        traffic_result,
        start_time,
        end_time
    ):
        """Extract anomaly time range from traffic result."""
        detected_start = None
        detected_end = None

        if traffic_result.get('expanded_windows'):
            windows = traffic_result['expanded_windows']
            first_window = windows[0]
            detected_start = first_window.get('start')
            detected_end = first_window.get('end')
        elif traffic_result.get('consecutive_anomaly_windows'):
            first_window = traffic_result['consecutive_anomaly_windows'][0]
            detected_start = first_window.get('start')
            detected_end = first_window.get('end')
        elif traffic_result.get('outage_period_anomalies'):
            try:
                from dateutil.parser import isoparse
                parsed_times = []
                for a in traffic_result['outage_period_anomalies']:
                    ts = a.get('timestamp')
                    if not ts:
                        continue
                    try:
                        parsed_times.append(isoparse(str(ts).replace('Z', '+00:00')))
                    except (ValueError):
                        continue
                if parsed_times:
                    detected_start = min(parsed_times).isoformat()
                    detected_end = max(parsed_times).isoformat()
            except (ValueError):
                pass

        detected_start = detected_start or start_time
        detected_end = detected_end or end_time

        def normalize_ts(ts_str):
            try:
                if 'T' in ts_str:
                    dt = datetime.strptime(ts_str.split('Z')[0], '%Y-%m-%dT%H:%M:%S')
                    return dt.strftime('%Y-%m-%d %H:%M')
                return ts_str
            except (ValueError):
                return ts_str

        return normalize_ts(detected_start), normalize_ts(detected_end)

    def extract_tokens(self, reasoning_result):
        """Extract token count from reasoning result."""
        tokens = 0
        token_usage = reasoning_result.get("token_usage", {})
        if isinstance(token_usage, dict):
            if "total_across_agents" in token_usage:
                tokens = token_usage["total_across_agents"]
            else:
                for agent_tokens in token_usage.values():
                    if isinstance(agent_tokens, dict):
                        tokens += agent_tokens.get("total", 0) or agent_tokens.get("total_tokens", 0)
                    elif isinstance(agent_tokens, int):
                        tokens += agent_tokens
        return tokens

    async def generate_report(
        self,
        routing_result,
        traffic_result,
        reasoning_result,
        asn,
        start_time,
        end_time,
        org_info,
        hcaf_attribution = None,
    ):
        """Generate final analysis report."""
        # Prefer the routing_result / traffic_result passed in directly from the agent
        # If empty, fall back to evidence_summary
        evidence = reasoning_result.get("evidence_summary", {}) if reasoning_result else {}

        # Use the directly passed data; if empty, extract from evidence_summary
        traffic_data = traffic_result if traffic_result else evidence.get("traffic_data", {})
        routing_data = routing_result if routing_result else evidence.get("routing_data", {})

        # Prefer the HCAF argument; otherwise take it from reasoning_result (workflow mode already filled it)
        hcaf = hcaf_attribution
        if not hcaf and isinstance(reasoning_result, dict):
            hcaf = reasoning_result.get("hcaf_attribution")

        # BUG-FIX 2026-10-01: direct call mode never invokes HCAF (it's a
        if not hcaf and isinstance(routing_data, dict) and isinstance(traffic_data, dict):
            try:
                from workflow_engine import WorkflowEngine, WorkflowContext
                we = WorkflowEngine()
                ctx = WorkflowContext(
                    asn=str(asn), start_time=start_time, end_time=end_time,
                    routing_result=routing_data, traffic_result=traffic_data,
                )
                hcaf_inline = we.compute_hcaf_attribution(ctx)
                if hcaf_inline:
                    hcaf = hcaf_inline
                    logger.info(
                        f"[_generate_report] Direct-mode HCAF computed: "
                        f"direction={hcaf.get('direction')}, "
                        f"confidence={hcaf.get('confidence', 0):.0%}"
                    )
            except (AttributeError) as _hcaf_err:
                logger.warning(f"[_generate_report] Direct-mode HCAF failed: {_hcaf_err}")

        # Debug logging
        logger.info(f"[_generate_report] Using traffic_data: {list(traffic_data.keys()) if isinstance(traffic_data, dict) else type(traffic_data)}")
        logger.info(f"[_generate_report] Using routing_data: {list(routing_data.keys()) if isinstance(routing_data, dict) else type(routing_data)}")
        logger.info(f"[_generate_report] routing_data origin_hijacked count: {len(routing_data.get('origin_hijacked', [])) if isinstance(routing_data, dict) else 'N/A'}")
        logger.info(f"[_generate_report] traffic_data anomalies_detected: {traffic_data.get('anomalies_detected') if isinstance(traffic_data, dict) else 'N/A'}")
        logger.info(f"[_generate_report] traffic_data plot_path: {traffic_data.get('plot_path') if isinstance(traffic_data, dict) else 'N/A'}")
        logger.info(f"[_generate_report] HCAF status_val: {'present' if hcaf else 'missing'}")

        # Extract plot_path for report embedding
        plot_path = traffic_data.get("plot_path") if isinstance(traffic_data, dict) else None

        return generate_comprehensive_report(
            llm=self.llm,
            routing_analysis=routing_data,
            traffic_analysis=traffic_data,
            law_analysis=None,
            reasoning_analysis=reasoning_result,
            start_time=start_time,
            output_dir=PROJECT_ROOT / "results" / "html",
            org_name=org_info.get("org_name") if org_info.get("success") else None,
            asn=asn,
            traffic_plot_path=plot_path,  # forward the plot path
            hcaf_attribution=hcaf,
        )

# Entry Points

async def analyze_traffic_outage_async(
    user_input = None,
    asn = None,
    start_time = None,
    end_time = None,
    analysis_mode = "traffic_first",
    enable_mitm: bool = MITM_DETECTION_ENABLED,
    enhanced = False,
    debate_rounds = 3,
    evaluation_retries = 2,
    time_window_extension_hours: float = 0.0,
):
    """Async entry point for BGP anomaly analysis."""
    output_dir = PROJECT_ROOT / "results"
    output_dir.mkdir(exist_ok=True, parents=True)

    if user_input and (not asn or not start_time or not end_time):
        from agents.traffic_agent import parse_traffic_outage_input
        parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(user_input)
        if not asn:
            asn = parsed_asn
        if not start_time:
            start_time = parsed_start
        if not end_time:
            end_time = parsed_end

    if not asn or not start_time or not end_time:
        return {"success": False, "error": "Missing asn, start_time, end_time"}

    analysis_file = output_dir / "json" / f"traffic_outage_analysis_{asn}_{start_time.replace(' ', '_')}.json"

    analysis_file.parent.mkdir(exist_ok=True, parents=True)

    # ── Extended time window ───────────────────────────────────────────────────────────
    if time_window_extension_hours > 0:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        start_time = (start_dt - timedelta(hours=time_window_extension_hours)).strftime("%Y-%m-%d %H:%M")
        end_time = (end_dt + timedelta(hours=time_window_extension_hours)).strftime("%Y-%m-%d %H:%M")
        logger.info(f"[TimeWindow] Extended to {start_time} ~ {end_time} (±{time_window_extension_hours}h)")

    chief_expert = ChiefExpertAgent(
        MODEL, API_KEY, BASE_URL,
        analysis_mode=analysis_mode,
        enable_mitm=enable_mitm,
        debate_rounds=debate_rounds,
        evaluation_retries=evaluation_retries,
    )
    result = await chief_expert.coordinate_analysis(
        user_input, asn, start_time, end_time,
    )

    result = make_json_safe(result)

    # Atomic write: serialise to a sibling temp file first, then rename
    try:
        tmp_path = analysis_file.with_suffix(analysis_file.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, analysis_file)
    except OSError as exc:
        logger.warning(
            f"[Output] Failed to persist analysis JSON to {analysis_file}: "
            f"{exc!r}. Returning in-memory result instead."
        )
        try:
            if 'tmp_path' in locals() and tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass

    return result

async def async_quick_routing(asn, start_time, end_time, enable_mitm,
                               skip_outage=None,
                               skip_leak=None):
    """Quick routing analysis without LLM (Phase 1)."""
    from agents.routing_agent import run_routing_agent_async

    # Phase 1 runs every detector.  The old code took a separate
    # "light" hijack pass over the update stream and then asked the
    # routing agent to skip its own hijack pass, so the window was read
    # twice for hijacking alone -- and the light pass produced false
    # accusations against the target, because it scored announcements
    # without the target's own prefix ownership.  The shared scan reads
    # the window once and gives the routing agent a hijack result that
    # is computed the same way as the batch detector's.
    #
    # `skip_leak` / `skip_outage` stay switchable so a caller that
    # genuinely cannot afford them can still opt out, but the default is
    # to run them: Phase 1 is the triage stage, and a stage that skips
    # the expensive detectors cannot triage.
    if skip_leak is None:
        skip_leak = os.environ.get("BGPT_RUN_LEAK", "1") == "0"
    if skip_outage is None:
        skip_outage = os.environ.get("BGPT_RUN_OUTAGE", "1") == "0"

    rest = await run_routing_agent_async(
        asn=asn, start_time=start_time, end_time=end_time,
        use_llm=False,
        enable_mitm=enable_mitm,
        # The detector itself does NOT look at event_type — it just runs on
        # every BGP update in the window. v17 ground-truth labels are NEVER
        # consulted here.
        skip_leak=skip_leak,
        skip_forge=True,       # forge / MITM is out of scope for now
        skip_outage=skip_outage,
        skip_hijack_streaming=False,
    )
    return rest

def light_origin_hijack(asn, start_time, end_time):
    """Single-pass vectorized origin hijack detection.
    
    Returns dict with keys `origin_hijacked` and `origin_hijacking` (lists of
    alert dicts). Empty lists on any failure (fail-safe)."""
    try:
        from datetime import datetime as _dt
        from data.parquet_cache import iter_window_chunks

        # Coerce ISO strings to UTC-naive datetimes (parquet_cache expects naive)
        def coerce(value):
            if value is None:
                return None
            if hasattr(value, "tzinfo") and value.tzinfo is not None:
                from datetime import timezone
                return value.astimezone(timezone.utc).replace(tzinfo=None)
            if hasattr(value, "strftime"):
                return value
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return _dt.strptime(str(value), fmt)
                except ValueError:
                    continue
            return None

        start_dt = coerce(start_time)
        end_dt = coerce(end_time)
        if start_dt is None or end_dt is None or end_dt <= start_dt:
            return {"origin_hijacked": [], "origin_hijacking": []}

        # ── Load all 5-min chunks into one DataFrame ─────────────────────
        parts = []
        for chunk in iter_window_chunks(start_dt, end_dt, on_missing="skip"):
            if chunk is None or chunk.is_empty():
                continue
            parts.append(chunk)
        if not parts:
            return {"origin_hijacked": [], "origin_hijacking": []}
        df = pl.concat(parts, how="vertical_relaxed")
        del parts

        # Announcements only (skip withdrawals)
        if "A/W" in df.columns:
            df = df.filter(pl.col("A/W") == "A")
        elif "announce" in df.columns:
            df = df.filter(pl.col("announce") == "A")
        if df.is_empty():
            return {"origin_hijacked": [], "origin_hijacking": []}

        # Keep only the columns detect_origin_hijacks needs.
        keep = ["prefix"]
        for col in ("as-path", "as_path"):
            if col in df.columns:
                keep.append(col)
                break
        if "timestamp" in df.columns:
            keep.append("timestamp")
        df = df.select([c for c in keep if c in df.columns])

        # ── Build prefix → owner AS mapping for target AS ────────────────
        from data.prefix2as_loader import process_prefix2as, load_prefix2as_json
        p2a_path = process_prefix2as(start_dt)
        prefix_to_as = load_prefix2as_json(p2a_path)
        if prefix_to_as is None:
            # load_prefix2as_json deleted a corrupt snapshot; rebuild it once
            # rather than silently running hijack detection against an empty
            # map, which would report "no hijack" for every event.
            p2a_path = process_prefix2as(start_dt)
            prefix_to_as = load_prefix2as_json(p2a_path) or {}

        # BUG-R-Round26: light-hijack bypassed the routing-agent IPv6 loader,
        try:
            from data.ipv6_prefix_loader import (
                load_ipv6_prefixes_for_as,
                merge_prefix2as_with_ipv6,
            )
            v6 = load_ipv6_prefixes_for_as(asn)
            if v6:
                prefix_to_as = merge_prefix2as_with_ipv6(
                    prefix_to_as, v6, asn=asn,
                )
        except (AttributeError) as _v6e:
            logger.debug(f"[light-hijack] IPv6 overlay merge skipped: {_v6e}")

        target_owned = {p for p, owners in prefix_to_as.items()
                        if str(asn) in (owners if isinstance(owners, (list, set)) else {owners})}

        prefixes_by_as = {str(asn): target_owned}

        # ── One-shot vectorized detection ───────────────────────────────
        from detectors.hijack.hijack_detector_core import detect_origin_hijacks
        alerts = detect_origin_hijacks(
            df, prefix_to_as=prefix_to_as,
            target_as=asn, prefixes_by_as=prefixes_by_as,
        )

        origin_hijacked = [a for a in alerts if a.get("hijack_type") == "origin_hijacked"]
        origin_hijacking = [a for a in alerts if a.get("hijack_type") == "origin_hijacking"]
        logger.info(
            f"[light-hijack] AS{asn}: {len(origin_hijacked)} victim / "
            f"{len(origin_hijacking)} attacker origin hijacks (single-pass)"
        )
        return {"origin_hijacked": origin_hijacked, "origin_hijacking": origin_hijacking}
    except (AttributeError) as _e:
        logger.warning(f"[light-hijack] failed (fallback to streaming): {_e}")
        return {"origin_hijacked": [], "origin_hijacking": []}

def build_quick_summary(traffic, routing, correlation):
    """Build a human-readable anomaly summary from raw agent outputs."""
    tr = traffic.get("result", traffic) if isinstance(traffic, dict) else {}
    if not isinstance(tr, dict):
        tr = {}

    rr = routing.get("result", routing) if isinstance(routing, dict) else {}
    if not isinstance(rr, dict):
        rr = {}

    traffic_anomaly_count = int(tr.get("anomaly_count", 0) or 0)
    traffic_data_available = bool(tr.get("data_available", tr.get("data_points", 0) > 0))
    # Motivation: traffic is the ground truth. Only anomaly_count counts.
    traffic_signal = traffic_anomaly_count > 0
    # BUG-R145 2026-09-29: when Cloudflare Radar has no timeseries for the

    # Routing aggregation. Try the annotation-package format first, then flat.
    hijack_section = rr.get("hijack") or {}
    leak_section = rr.get("leak") or {}
    outage_section = rr.get("outage") or {}

    hijack_count = (
        len(hijack_section.get("origin_hijacked") or [])
        + len(hijack_section.get("forge_hijacked") or [])
    )
    if hijack_count == 0:
        hijack_count = len(rr.get("hijacks") or rr.get("origin_hijacked") or rr.get("forge_hijacked") or [])

    # BUG (2026-10-05): `leak_count = len(route_leaks)` reads the capped list,
    leak_count = len(leak_section.get("route_leaks") or [])
    if leak_count == 0:
        leak_count = len(rr.get("leaks") or rr.get("route_leaks") or [])

    leak_total = leak_count
    leak_truncated = False
    for _src in (leak_section, rr, rr.get("leak_analysis") or {}):
        if not isinstance(_src, dict):
            continue
        if isinstance(_src.get("leak_count_total"), int):
            leak_total = max(leak_total, _src["leak_count_total"])
        if isinstance(_src.get("total_detected"), int):
            leak_total = max(leak_total, _src["total_detected"])
        if _src.get("leak_results_truncated") or _src.get("truncated"):
            leak_truncated = True
    leak_skipped = bool(
        rr.get("leak_analysis_skipped")
        or (isinstance(rr.get("leak_analysis"), dict) and rr["leak_analysis"].get("skipped"))
    )
    if leak_skipped:
        # A skipped detector must not register as a routing signal.
        leak_count = 0
        leak_total = 0

    outage_score = float(outage_section.get("score", 0.0) or 0.0) if isinstance(outage_section, dict) else 0.0
    if outage_score == 0.0 and isinstance(rr.get("outages"), dict):
        outage_score = float(rr["outages"].get("score", 0.0) or 0.0)
    # A skipped outage detector reports 0.0, which must not be read as a
    # measured zero when deciding whether routing evidence exists.
    outage_skipped = bool(
        rr.get("outage_analysis_skipped")
        or (isinstance(rr.get("outage_analysis"), dict) and rr["outage_analysis"].get("skipped"))
    )
    if outage_skipped:
        outage_score = 0.0

    routing_signal = (hijack_count + leak_count) > 0 or outage_score > 0.5

    # correlation_analyzer.analyze_temporal_correlation() returns a dict whose
    corr = correlation.get("result", correlation) if isinstance(correlation, dict) else {}
    if not isinstance(corr, dict):
        corr = {}
    corr_summary = corr.get("summary", {}) if isinstance(corr, dict) else {}
    corr_signals = corr.get("correlation", {}).get("signals", {}) if isinstance(corr.get("correlation"), dict) else {}
    # Prefer signals.temporal_proximity (the real value), then summary.correlation_level.
    raw_level = (
        corr_signals.get("temporal_proximity")
        or corr_summary.get("correlation_level")
        or corr.get("level")
        or "none"
    )
    correlation_level = str(raw_level).lower()
    correlation_strength = float(corr.get("strength", 0.0) or corr.get("score", 0.0) or 0.0)

    # Round-25 (mirror of agents/report_agent.render_tca_section):
    def bucket_from_strength(score):
        if score >= 0.65:
            return "high"
        if score >= 0.35:
            return "medium"
        if score >= 0.15:
            return "low"
        return "none"

    def bucket_from_temporal(label):
        if label in ("strong", "moderate", "high", "medium"):
            return "high"
        if label == "weak":
            return "low"
        return "none"

    if correlation_strength > 0:
        correlation_level = bucket_from_strength(correlation_strength)
    else:
        correlation_level = bucket_from_temporal(correlation_level)
        # Round-25: when temporal_proximity says "high" but the numeric
        if correlation_level == "high":
            correlation_level = "medium"

    # Map temporal_proximity to chief_agent's expected semantic levels
    # strong/moderate → high, weak → low, none → none.
    if correlation_level in ("strong", "moderate", "high", "medium"):
        correlation_level = "high"
    elif correlation_level == "weak":
        correlation_level = "low"
    elif correlation_level in ("signals_precomputed", "observational_only"):
        correlation_level = "none"

    # ── Quick verdict logic ─────────────────────────────────────────────────
    if not traffic_data_available:
        # Radar returned no data points. The anomaly_count is fabricated
        # and useless. Surface this gap so the reviewer knows the verdict
        # is not a real traffic signal, even when routing has alerts.
        verdict = "no_radar_data"
    elif traffic_signal and routing_signal and correlation_level in ("high", "medium", "low"):
        verdict = "real_incident"
    elif traffic_signal and routing_signal and correlation_level == "none":
        verdict = "correlation_uncertain"
    elif routing_signal and not traffic_signal:
        verdict = "silent_alert"
    elif traffic_signal and not routing_signal:
        verdict = "traffic_only"
    elif not traffic_signal and not routing_signal:
        verdict = "no_clear_anomaly"
    else:
        verdict = "unknown"

    return {
        "traffic_anomaly_count": traffic_anomaly_count,
        "traffic_signal_present": traffic_signal,
        "routing_hijack_count": hijack_count,
        "routing_leak_count": leak_count,
        "routing_leak_count_total": leak_total,
        "routing_leak_results_truncated": leak_truncated,
        "routing_leak_analysis_skipped": leak_skipped,
        "routing_outage_analysis_skipped": outage_skipped,
        "routing_outage_score": outage_score,
        "correlation_level": correlation_level,
        "correlation_strength": round(correlation_strength, 3),
        "quick_verdict": verdict,
    }


def analyze_traffic_outage(
    user_input = None,
    asn = None,
    start_time = None,
    end_time = None,
    analysis_mode = "traffic_first",
    enable_mitm: bool = MITM_DETECTION_ENABLED,
    enhanced = False,
    debate_rounds = 3,
    evaluation_retries = 2,
):
    """Sync entry point for traffic outage analysis."""
    result = asyncio.run(analyze_traffic_outage_async(
        user_input, asn, start_time, end_time, analysis_mode,
        enable_mitm,
        enhanced, debate_rounds, evaluation_retries,
    ))
    try:
        from utils.tracing import metrics, StageEvent
        out_dir = Path(__file__).resolve().parent / "results" / "json"
        slug = f"event_{asn or 'unknown'}"
        if isinstance(result, dict):
            ts = (
                result.get("chief_expert_analysis", {}).get("timestamp")
                or result.get("timestamp")
            )
            if ts:
                slug = f"{slug}_{str(ts).replace(':', '').replace('-', '').replace(' ', '_')[:15]}"
        if not metrics.all():
            import time as _t
            now = _t.time()
            metrics.record(StageEvent(
                name="chief.workflow",
                start_ts=now,
                end_ts=now,
                elapsed_s=0.0,
                attrs={
                    "asn": str(asn),
                    "mode": str(analysis_mode),
                    "enhanced": bool(enhanced),
                },
            ))
        out_dir.mkdir(parents=True, exist_ok=True)
        metrics.save(out_dir / f"{slug}_metrics.json")
        metrics.reset()
    except (AttributeError) as _exc:
        logger.debug(f"[tracing] metrics save skipped: {_exc!r}")
    return result


def run_quick_analysis_async(
    asn,
    start_time,
    end_time,
    user_input=None,
    enable_mitm: bool = MITM_DETECTION_ENABLED,
    cache_dir: Optional[Path] = None,
    event_id: Optional[str] = None,
    skip_leak: Optional[bool] = None,
    skip_outage: Optional[bool] = None,
) -> dict:
    """Phase 1 sync driver. 0 LLM. ~60 s. Returns the quick-phase result dict."""
    t0 = perf_counter()
    warnings: list = []
    asn_str = str(asn) if asn is not None else ""

    try:
        traffic_raw = run_traffic_agent(
            user_input=user_input,
            asn=asn,
            start_time=start_time,
            end_time=end_time,
            use_llm=False,
        )
        if not isinstance(traffic_raw, dict):
            traffic_raw = {"success": False, "error": f"traffic_agent returned non-dict: {type(traffic_raw).__name__}"}
        if not traffic_raw.get("success"):
            warnings.append(f"traffic_agent: {traffic_raw.get('error', 'unknown error')}")
    except (AttributeError) as _e:
        logger.warning(f"[quick] traffic_agent crashed: {_e!r}")
        warnings.append(f"traffic_agent crashed: {_e!r}")
        traffic_raw = {"success": False, "error": str(_e), "anomaly_count": 0}

    try:
        # BUG-FIX 2026-10-09: skip_outage was hardcoded True here, which
        routing_raw = asyncio.run(async_quick_routing(
            asn=asn, start_time=start_time, end_time=end_time,
            enable_mitm=enable_mitm,
            skip_leak=skip_leak,
            skip_outage=skip_outage,
        ))
        if not isinstance(routing_raw, dict):
            routing_raw = {"success": False, "error": f"routing returned non-dict: {type(routing_raw).__name__}"}
        if not routing_raw.get("success"):
            warnings.append(f"routing: {routing_raw.get('error', 'unknown error')}")
    except (AttributeError) as _e:
        logger.warning(f"[quick] _async_quick_routing crashed: {_e!r}")
        warnings.append(f"routing crashed: {_e!r}")
        routing_raw = {
            "success": False, "error": str(_e),
            "origin_hijacked": [], "origin_hijacking": [],
            "forge_hijacked": [], "forge_hijacking": [],
            "route_leaks": [], "leak_count": 0, "outage_score": 0.0,
        }

    try:
        from agents.correlation_analyzer import analyze_temporal_correlation
        traffic_anomaly_window = None
        try:
            tr_inner = traffic_raw.get("result", traffic_raw) if isinstance(traffic_raw, dict) else {}
            if isinstance(tr_inner, dict):
                traffic_anomaly_window = (
                    tr_inner.get("anomaly_window")
                    or tr_inner.get("traffic_anomaly_window")
                )
        except (ValueError):
            traffic_anomaly_window = None

        correlation = analyze_temporal_correlation(
            traffic_raw=traffic_raw,
            routing_result=routing_raw,
            target_as=asn_str,
            traffic_anomaly_window=traffic_anomaly_window,
        )
        if not isinstance(correlation, dict):
            correlation = {"summary": {}, "correlation": {}, "hypotheses": []}
    except (AttributeError) as _e:
        logger.warning(f"[quick] correlation analyzer crashed: {_e!r}")
        warnings.append(f"correlation crashed: {_e!r}")
        correlation = {"summary": {}, "correlation": {}, "hypotheses": []}

    summary = build_quick_summary(traffic_raw, routing_raw, correlation)
    traffic_signal_present = bool(summary.get("traffic_signal_present"))

    # Cache path. Filename encodes the canonical event id when provided
    # so multiple events sharing the same (asn, start, end) window
    # (e.g. AS16509 — three different hijacks) get distinct cache files.
    cache_root = cache_dir or (PROJECT_ROOT / "results" / "quick")
    cache_root.mkdir(parents=True, exist_ok=True)
    safe_start = str(start_time or "").replace(" ", "_").replace(":", "")
    safe_end = str(end_time or "").replace(" ", "_").replace(":", "")
    safe_event = re.sub(r"[^A-Za-z0-9._-]", "_", str(event_id or "")) if event_id else ""
    prefix = f"quick_{safe_event}__" if safe_event else f"quick_{asn_str}_"
    cache_path = cache_root / f"{prefix}{safe_start}_{safe_end}.json"

    elapsed = round(perf_counter() - t0, 2)

    # The hijack detector emits one record per announcement, so a busy window
    # produces hundreds of thousands of records for a single incident and the
    # cache reaches hundreds of megabytes -- large enough to be OOM-killed
    # while being written, and too slow to load during evaluation.  Collapse
    # the per-announcement records into one record per incident before the
    # cache is written; the original record counts are kept alongside, so no
    # downstream consumer loses the announcement-frequency information.
    routing_raw, correlation = compact_cache_payload(routing_raw, correlation)

    result = {
        "success": bool(traffic_raw.get("success", False)) or bool(routing_raw.get("success", False)),
        "event_id": event_id,  # v18 cache-based eval matches on this
        "asn": asn_str,
        "start_time": start_time,
        "end_time": end_time,
        "phase": "quick",
        "traffic": traffic_raw,
        "routing": routing_raw,
        "correlation": correlation,
        "anomaly_summary": summary,
        "quick_verdict": summary.get("quick_verdict", "unknown"),
        "traffic_signal_present": traffic_signal_present,
        "warnings": warnings,
        "elapsed_seconds": elapsed,
        "cached_at": datetime.utcnow().isoformat() + "Z",
        "cache_path": None,  # filled after atomic write
    }

    try:
        tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as _f:
            json.dump(make_json_safe(result), _f, ensure_ascii=False, default=str)
        os.replace(tmp_path, cache_path)
        result["cache_path"] = str(cache_path)
    except OSError as _e:
        logger.warning(f"[quick] failed to write cache {cache_path}: {_e!r}")
        warnings.append(f"cache write failed: {_e!r}")
        result["cache_path"] = None

    return result


def analyze_quick(
    asn,
    start_time,
    end_time,
    user_input=None,
    enable_mitm: bool = MITM_DETECTION_ENABLED,
    cache_dir: Optional[Path] = None,
    event_id: Optional[str] = None,
    skip_leak: Optional[bool] = None,
    skip_outage: Optional[bool] = None,
) -> dict:
    """**Phase 1** of the two-phase diagnosis. Sync. 0 LLM. ~60 s.
    
    Returns a JSON-serializable dict with raw traffic / routing / correlation
    results, plus a human-readable anomaly summary and a `quick_verdict`."""
    return run_quick_analysis_async(
        asn=asn, start_time=start_time, end_time=end_time,
        user_input=user_input,
        enable_mitm=enable_mitm,
        cache_dir=cache_dir,
        event_id=event_id,
        skip_leak=skip_leak,
        skip_outage=skip_outage,
    )

def analyze_deep_from_quick(
    quick_result: dict,
    user_input: Optional[str] = None,
    analysis_mode: str = "traffic_first",
    debate_rounds: int = 1,
) -> dict:
    """**Phase 2** of the two-phase diagnosis. Sync. ~3-5 min, runs the LLM.
    
    Returns:
    Same dict shape as `analyze_traffic_outage()`, plus `phase="deep"`."""
    if not quick_result or not quick_result.get("success"):
        return {"success": False, "error": "quick_result invalid", "phase": "deep"}

    asn = quick_result.get("asn")
    start_time = quick_result.get("start_time")
    end_time = quick_result.get("end_time")

    # Decide what to produce in deep phase. We avoid re-running traffic/routing
    # because their results are already in quick_result (cached). Only the LLM
    # stage (reasoning + report) is invoked.
    from config import MODEL as _MODEL, API_KEY as _KEY, BASE_URL as _URL
    chief_expert = ChiefExpertAgent(
        _MODEL, _KEY, _URL,
        analysis_mode=analysis_mode,
        enable_mitm=False,    # deep phase skips MITM (already included in quick routing if requested)
        debate_rounds=debate_rounds,
    )

    t0 = perf_counter()
    deep_result = asyncio.run(deep_only_pipeline(
        asn=asn,
        start_time=start_time,
        end_time=end_time,
        user_input=user_input,
        chief_expert=chief_expert,
        precomputed_routing=quick_result.get("routing"),
        precomputed_traffic=quick_result.get("traffic"),
    ))
    elapsed = round(perf_counter() - t0, 2)

    # Attach quick result
    deep_result.setdefault("chief_expert_analysis", {})
    deep_result["chief_expert_analysis"]["quick_summary"] = quick_result.get("anomaly_summary") or {}
    deep_result["chief_expert_analysis"]["quick_verdict"] = quick_result.get("quick_verdict", "unknown")
    deep_result["chief_expert_analysis"]["elapsed_phase2_seconds"] = elapsed
    deep_result["phase"] = "deep"
    deep_result["quick_result"] = {
        "anomaly_summary": quick_result.get("anomaly_summary", {}),
        "quick_verdict": quick_result.get("quick_verdict", "unknown"),
        "cache_path": quick_result.get("cache_path"),
        "elapsed_seconds": quick_result.get("elapsed_seconds"),
    }

    # Round-22 (observability): persist per-event metrics alongside the
    try:
        from utils.tracing import metrics
        out_dir = Path(__file__).resolve().parent / "results" / "json"
        slug = f"event_{asn or 'unknown'}_phase2"
        ts = (
            (deep_result.get("chief_expert_analysis") or {}).get("timestamp")
            or deep_result.get("timestamp")
        )
        if ts:
            slug += f"_{str(ts).replace(':', '').replace('-', '').replace(' ', '_')[:15]}"
        # Synthesise a wall-clock stage event if no other stage recorded
        # anything (which is the current case until agents wrap themselves).
        if not metrics.all():
            from utils.tracing import StageEvent
            metrics.record(StageEvent(
                name="deep.phase2",
                start_ts=t0,
                end_ts=perf_counter(),
                elapsed_s=elapsed,
                attrs={
                    "asn": str(asn),
                    "verdict": quick_result.get("quick_verdict", "unknown"),
                    "html": (
                        deep_result.get("analysis_report", {}) or {}
                    ).get("html_report_path", ""),
                },
            ))
        out_dir.mkdir(parents=True, exist_ok=True)
        metrics.save(out_dir / f"{slug}_metrics.json")
        metrics.reset()
    except (AttributeError) as _exc:  # noqa: BLE001 — observability never breaks deep
        logger.debug(f"[tracing] deep-phase metrics save skipped: {_exc!r}")

    return deep_result

async def deep_only_pipeline(
    asn, start_time, end_time, user_input,
    chief_expert: "ChiefExpertAgent",
    precomputed_routing: dict,
    precomputed_traffic: dict,
):
    """Run the LLM reasoning + report. Reuses precomputed traffic/routing."""
    return await chief_expert.coordinate_analysis(
        user_input=user_input,
        asn=asn,
        start_time=start_time,
        end_time=end_time,
        precomputed_routing=precomputed_routing,
        precomputed_traffic=precomputed_traffic,
    )

def load_quick_cache(cache_path_str):
    """Load a Phase-1 result from disk for a Phase-2 follow-up."""
    p = Path(cache_path_str)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError):
        return None

# CLI

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="BGP Anomaly Analysis - Multi-Agent System (Two-Phase)",
        usage=(
            "python chief_agent.py --asn <ASN> --start <TIME> --end <TIME> "
            "[--mode quick|deep|traffic_first|react] "
            "[--quick-cache <path>]"
        ),
    )
    parser.add_argument("--asn", help="AS number to analyze")
    parser.add_argument("--start", help="Start time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--end", help="End time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--user-input", help="Natural language input describing the event")
    parser.add_argument(
        "--mode", default="quick",
        choices=["quick", "deep", "auto", "traffic_first", "react"],
        help=(
            "quick (Phase 1, ~60s, 0 LLM), "
            "deep (Phase 2; needs --quick-cache), "
            "auto (Phase 1 sync + Phase 2 background, overwrites phase 1 path), "
            "traffic_first/react (single-phase legacy)"
        ),
    )
    parser.add_argument(
        "--quick-cache",
        help="Path to a quick-phase result JSON; run Phase 2 without re-detecting routing/traffic.",
    )
    parser.add_argument(
        "--json-summary", action="store_true", default=False,
        help="Print Phase 1 anomaly_summary as JSON (for batch consumption)",
    )
    parser.add_argument(
        "--json-output", action="store_true", default=False,
        help="Emit full structured result as JSON to stdout (overrides JSON_OUTPUT_ENABLED env var)",
    )

    args = parser.parse_args()

    # ── Two-phase dispatch ─────────────────────────────────────────────
    if args.mode == "quick":
        if not all([args.asn, args.start, args.end]):
            parser.error("--asn, --start, --end required for --mode quick")
        if not getattr(args, "json_output", False):
            print(f"Mode: quick (Phase 1, 0 LLM) | MITM: {'enabled' if MITM_DETECTION_ENABLED else 'disabled'} | Enhanced: off")
            print("=" * 60)
        result = analyze_quick(
            asn=args.asn, start_time=args.start, end_time=args.end,
            user_input=args.user_input,
            enable_mitm=MITM_DETECTION_ENABLED,
        )
        if getattr(args, "json_output", False):
            print(json.dumps(make_json_safe(result), indent=2, ensure_ascii=False, default=str))
            sys.exit(0 if result.get("success") else 1)
        if args.json_summary:
            print(json.dumps(make_json_safe({
                "asn": result["asn"],
                "start_time": result["start_time"],
                "end_time": result["end_time"],
                "quick_verdict": result["quick_verdict"],
                "anomaly_summary": result["anomaly_summary"],
                "traffic_signal_present": result["traffic_signal_present"],
                "elapsed_seconds": result["elapsed_seconds"],
                "cache_path": result.get("cache_path"),
                "warnings": result.get("warnings", []),
            }), indent=2, ensure_ascii=False, default=str))
        else:
            summary = result.get("anomaly_summary") or {}
            print(f"\n=== QUICK result (elapsed: {result.get('elapsed_seconds', 0):.1f}s) ===")
            print(f"AS: AS{result.get('asn')} | window: {result.get('start_time')} → {result.get('end_time')}")
            print(f"Traffic: {summary.get('traffic_anomaly_count')} anomalies, signal={'YES' if result.get('traffic_signal_present') else 'NO'}")
            print(f"Hijacks: {summary.get('routing_hijack_count')}")
            if summary.get("routing_leak_analysis_skipped"):
                print("Leaks: Skipped (light mode — not a measurement)")
            elif summary.get("routing_leak_results_truncated"):
                _lt = summary.get("routing_leak_count_total") or summary.get("routing_leak_count")
                print(f"Leaks: ≥{_lt} (TRUNCATED — only the first "
                      f"{summary.get('routing_leak_count')} itemised; detector cap, not a measurement)")
            else:
                print(f"Leaks: {summary.get('routing_leak_count')}")
            if summary.get("routing_outage_analysis_skipped"):
                print("Outage score: Skipped (light mode — not a measurement)")
            else:
                print(f"Outage score: {summary.get('routing_outage_score')}")
            print(f"Correlation: {summary.get('correlation_level')} (strength={summary.get('correlation_strength')})")
            # Round-25: if the upstream temporal-proximity string and the
            try:
                _str = float(summary.get('correlation_strength') or 0.0)
            except (TypeError, ValueError):
                _str = 0.0
            if _str == 0.0 and summary.get('correlation_level') == 'high':
                print("Note: temporal-proximity classifier reports 'high' but numeric strength is 0; verdict logic treats as 'medium'.")
            print(f"\n>>> QUICK VERDICT: {result.get('quick_verdict')}")
            verdict = result.get("quick_verdict")
            if verdict == "real_incident":
                print("⚠ Real incident — BGP anomaly drove the traffic change; action needed")
            elif verdict == "silent_alert":
                print("✅ Silent alert — BGP event present but traffic unaffected; ignorable")
            elif verdict == "traffic_only":
                print("🔍 Traffic anomaly with quiet routing — needs a non-BGP explanation")
            elif verdict == "correlation_uncertain":
                print("❓ Both traffic and routing anomalous but not overlapping in time — needs deeper analysis")
            else:
                print("ℹ️  No clear anomaly")
            if result.get("cache_path"):
                print(f"\nQuick cache written: {result.get('cache_path')}")
                print(f"→ run Phase 2 with: --mode deep --quick-cache {result.get('cache_path')}")
            if result.get("warnings"):
                print(f"\nWarnings: {result['warnings']}")
        sys.exit(0 if result.get("success") else 1)

    if args.mode == "auto":
        # Two-phase diagnosis: run Phase 1 (quick) sync so the user gets
        from chief_agent import run_auto_mode  # late import; defined below
        sys.exit(run_auto_mode(args))

    if args.mode == "deep":
        # Phase 2: load quick result from cache (or run quick first as a fallback)
        quick = None
        if args.quick_cache:
            quick = load_quick_cache(args.quick_cache)
            if not quick:
                print(f"Failed to load quick cache from {args.quick_cache}", file=sys.stderr)
                sys.exit(2)
        else:
            if not all([args.asn, args.start, args.end]):
                parser.error("--asn, --start, --end required for --mode deep without --quick-cache")
            if not (JSON_OUTPUT_ENABLED or getattr(args, "json_output", False)):
                print("No --quick-cache given; running quick phase first...")
            quick = analyze_quick(
                asn=args.asn, start_time=args.start, end_time=args.end,
                user_input=args.user_input,
                enable_mitm=MITM_DETECTION_ENABLED,
            )
        if not (JSON_OUTPUT_ENABLED or getattr(args, "json_output", False)):
            print("Mode: deep (Phase 2, LLM) | MITM: disabled | Enhanced: off (removed 2026-09-29)")
            print(f"Quick verdict: {quick.get('quick_verdict')} | traffic_signal={quick.get('traffic_signal_present')}")
            print("=" * 60)
        result = analyze_deep_from_quick(
            quick_result=quick,
            user_input=args.user_input,
            analysis_mode="traffic_first",
        )
    else:
        # Legacy one-phase modes (kept for backward compatibility)
        mode_arg = args.mode
        if mode_arg in ("traffic_first_enhanced", "react_enhanced"):
            mode_arg = mode_arg.replace("_enhanced", "")
        if not args.user_input and not all([args.asn, args.start, args.end]):
            parser.error("the following arguments are required: --asn, --start, --end (unless --user-input is provided)")
        if not (JSON_OUTPUT_ENABLED or getattr(args, "json_output", False)):
            print(f"Mode: {mode_arg} | MITM: {'enabled' if MITM_DETECTION_ENABLED else 'disabled'} | Enhanced: off (removed 2026-09-29)")
            print("=" * 60)
        try:
            result = analyze_traffic_outage(
                user_input=args.user_input,
                asn=args.asn,
                start_time=args.start,
                end_time=args.end,
                analysis_mode=mode_arg,
            )
        except (AttributeError) as e:
            logger.error(f"Analysis failed: {e}\n{traceback.format_exc()}")
            sys.exit(1)

    # ── JSON output mode (captured by the batch runner)────────────────────
    if JSON_OUTPUT_ENABLED or getattr(args, "json_output", False):
        import json as _json
        print(_json.dumps(result, indent=2, ensure_ascii=False, default=str))
        sys.exit(0)

    if result.get('batch_mode'):
        print(f"Batch Mode: {result.get('analysis_type', 'Unknown')} | AS Count: {result.get('as_count', 0)}")
        if result.get('html_report_path'):
            print(f"Report: {result['html_report_path']}")
    elif result.get('chief_expert_analysis'):
        analysis = result['chief_expert_analysis']
        execution_minutes = result.get('execution_time_minutes')
        if execution_minutes is None:
            elapsed_seconds = result.get('elapsed_seconds')
            if elapsed_seconds is not None:
                execution_minutes = float(elapsed_seconds) / 60.0
            else:
                start = result.get('event_start_time')
                end = result.get('event_end_time')
                if start and end:
                    try:
                        from datetime import datetime as _dt
                        execution_minutes = (_dt.fromisoformat(end) - _dt.fromisoformat(start)).total_seconds() / 60.0
                    except (ValueError):
                        execution_minutes = None
        execution_minutes = execution_minutes if execution_minutes is not None else 0
        token_count = result.get('token_count')
        if token_count is None or token_count == 0:
            # React path: token_count defaults to 0 because the per-call
            # tokens live in the global TokenBudget. If the chief dict
            # carries any usage info, surface it here.
            token_count = result.get('chief_expert_analysis', {}).get('token_count', token_count)
        print(f"Analysis completed | Tokens: {token_count if token_count not in (None, '') else 'N/A'}")
        print(f"Execution time: {execution_minutes:.2f} minutes")
        print(f"Data quality: {analysis.get('data_quality', 'N/A')}")
        print(f"Confidence score: {analysis.get('confidence_score', 'N/A')}")
        if analysis.get("quick_verdict"):
            print(f"Phase-1 verdict: {analysis['quick_verdict']} | traffic_signal={analysis.get('quick_summary', {}).get('traffic_signal_present')}")
        # Print Smart Cascade info if available
        if 'smart_cascade' in result:
            sc = result['smart_cascade']
            print(f"Smart Cascade Info:")
            print(f"  - Analysis mode: {sc.get('analysis_mode')}")
            screening_result = sc.get('screening_result') or {}
            print(f"  - Traffic screening score: {screening_result.get('quick_score', 'N/A')}")
            print(f"  - Needs traffic deep analysis: {sc.get('needs_traffic_deep_analysis')}")
            print(f"  - Routing analysis detail: {sc.get('routing_analysis_detail')}")
            if sc.get('validation_notes'):
                for note in sc['validation_notes']:
                    print(f"  - {note.get('message', 'Note')}")
        if result.get("analysis_report", {}).get("html_report_path"):
            print(f"Report: {result['analysis_report']['html_report_path']}")
    elif result.get('success') is False:
        print(f"Failed: {result.get('error', 'Unknown error')}")
    else:
        print(f"Unexpected result. Keys: {list(result.keys())[:5]}")

def run_auto_mode(args):
    """Two-phase diagnosis: Phase 1 sync, Phase 2 detached subprocess.
    
    Returns the standard POSIX exit code (0 = quick phase succeeded)."""
    import subprocess as _sp

    if not all([args.asn, args.start, args.end]):
        print("--asn, --start, --end are required for --mode auto", file=sys.stderr)
        return 2

    print("Mode: auto (Phase 1 sync + Phase 2 background) | Enhanced: off (removed 2026-09-29)")
    print(f"AS: AS{args.asn} | window: {args.start} → {args.end}")

    # Phase 1
    #
    # Every detector runs here.  Phase 1 is the triage stage, so a
    # detector that is skipped is an anomaly class that triage cannot
    # report at all.  The cost of running them is now a single pass over
    # the update stream (see detectors/shared_scan.py), which is what
    # made this affordable in the first place.
    quick = analyze_quick(
        asn=args.asn,
        start_time=args.start,
        end_time=args.end,
        user_input=args.user_input,
        enable_mitm=MITM_DETECTION_ENABLED,
        skip_leak=False,
        skip_outage=False,
    )
    cache_path = quick.get("cache_path")
    summary = quick.get("anomaly_summary") or {}
    print(f"Traffic: {summary.get('traffic_anomaly_count')} anomalies, signal={'YES' if quick.get('traffic_signal_present') else 'NO'}")
    print(f"Hijacks: {summary.get('routing_hijack_count')}")
    print(f"\n>>> QUICK VERDICT: {quick.get('quick_verdict')}")
    print("Background Phase 2 (deep + LLM) starting; the same HTML path will be overwritten when ready.")

    if not cache_path:
        print("Phase 1 didn't write a quick cache; skipping Phase 2.", file=sys.stderr)
        return 1

    # Phase 2 — detached
    cmd = [
        sys.executable, str(Path(__file__).resolve()),
        "--mode", "deep",
        "--quick-cache", cache_path,
        "--asn", str(args.asn),
        "--start", str(args.start),
        "--end", str(args.end),
    ]
    if args.user_input:
        cmd += ["--user-input", args.user_input]

    log_path = Path(__file__).resolve().parent / "results" / "json" / f"phase2_AS{args.asn}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fp = open(log_path, "w")
    proc = _sp.Popen(
        cmd,
        stdout=log_fp,
        stderr=_sp.STDOUT,
        stdin=_sp.DEVNULL,
        start_new_session=True,  # detach
    )
    print(f"Phase 2 subprocess started (pid={proc.pid}, log={log_path})")
    print(f"→ poll the same HTML path: results/html/multi_agent_report_{args.asn}_*.html")
    return 0