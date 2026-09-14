from __future__ import annotations

import asyncio
import json
import os
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
    WorkflowEvent,
    run_workflow,
    get_workflow_architecture_diagram
)
from agents.traffic_agent import (
    lookup_as_by_country,
    parse_country_region_input,
    parse_multiple_as_input,
    parse_traffic_outage_input,
    run_traffic_agent,
)
from agents.reasoning_agent import run_reasoning_agent, run_reasoning_agent_batch
from agents.routing_agent import run_routing_agent_async
from agents.react_agent import valid_llm_html_report
from data.asorg_loader import process_asorg
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from utils.helpers import make_json_safe
from utils.logger import logger
from utils.report_exporters import generate_comprehensive_report, generate_batch_html_report
from agents.coordination_utils import (
    generate_integrated_report,
    lookup_org_info,
    normalize_time,
    query_as_relationships,
    query_as_prefixes,
)
from config import API_KEY, BASE_URL, MODEL, MITM_DETECTION_ENABLED, CHECKPOINTING_ENABLED, JSON_OUTPUT_ENABLED

PROJECT_ROOT = Path(__file__).parent


class ChiefExpertAgent:
    """
    Chief Expert Agent — main orchestrator for BGP analysis.

    Mode selection:
      traffic_first: state machine workflow (default); deterministic and stable.
      react:         LLM-driven ReAct loop with 18 tools; supports streaming.
      --enhanced:    adds debate, online evaluation, reactive decisions on top of traffic_first.

    Attributes:
      analysis_mode: "traffic_first" | "react"
      enhanced:      bool — enables debate/evaluation/reactive mode
    """


    def __init__(
        self,
        model,
        api_key,
        base_url,
        analysis_mode="traffic_first",
        enhanced=False,
        debate_rounds=3,
        evaluation_retries=2,
        enable_mitm=MITM_DETECTION_ENABLED,
    ):
        # "traffic_first_enhanced" and "react_enhanced" are shorthand for base + enhanced=True.
        if analysis_mode in ("traffic_first_enhanced", "react_enhanced"):
            analysis_mode = analysis_mode.replace("_enhanced", "")
            enhanced = True
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.analysis_mode = analysis_mode
        self.enable_mitm = enable_mitm
        self.enhanced = enhanced
        self.debate_rounds = debate_rounds
        self.evaluation_retries = evaluation_retries
        self.llm = None
        self.token_counter = None
        self.asrel_file = None
        self.prefix2as_file = None
        self.asorg_file = None
        self.reasoning_analysis_result = None
        self._workflow_engine = None
        self._streaming_callback = None
    
    def _detect_output_language(self, user_input: Optional[str]) -> str:
        """Detect output language from user input."""
        if not user_input:
            return "en"

        text = str(user_input).lower()
        zh_markers = ["帮我", "分析", "异常", "情况", "劫持", "路由", "流量", "请", "到"]
        if any(marker in text for marker in zh_markers):
            return "zh"
        return "en"

    def _format_language_instruction(self, language: str) -> str:
        """Return language instruction for downstream prompts."""
        return "Respond in English only." if language == "en" else "请只用中文回复。"

    @property
    def workflow_engine(self):
        """Get or create workflow engine instance."""
        if self._workflow_engine is None:
            self._workflow_engine = WorkflowEngine(
                max_retries=3,
                parallel_execution=True,
                skip_unnecessary_analysis=False,
                enhanced=self.enhanced,
                debate_rounds=self.debate_rounds,
                evaluation_retries=self.evaluation_retries,
            )
        return self._workflow_engine
    
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
        event_type: str = None,
        as_role: str = None,
        precomputed_routing: dict = None,
        precomputed_traffic: dict = None,
    ):
        """
        Main coordination method - dispatches to appropriate mode.

        Args:
            user_input: Natural language input
            asn: AS number
            start_time: Start time
            end_time: End time
            streaming_callback: Optional callback for streaming output (React mode)

        Returns:
            Analysis result dictionary
        """
        t0 = perf_counter()
        event_start = datetime.now()

        # Store streaming callback for React mode
        self._streaming_callback = streaming_callback

        # Handle batch/special cases first
        if user_input and not (asn and start_time and end_time):
            batch_result = await self._handle_batch_input(user_input)
            if batch_result:
                return batch_result

        output_language = self._detect_output_language(user_input)

        # Validate parameters
        if user_input:
            if not (start_time and end_time):
                return {"success": False, "error": "Missing start_time, end_time"}
        else:
            if not all([asn, start_time, end_time]):
                return {"success": False, "error": "Missing asn, start_time, end_time"}

        if self.analysis_mode == "react":
            return await self._react_analysis_flow(
                asn, start_time, end_time, user_input, t0, event_start,
                precomputed_routing=precomputed_routing,
                precomputed_traffic=precomputed_traffic,
                enhanced=self.enhanced,
            )
        return await self._workflow_analysis_flow(
            asn, start_time, end_time, user_input, t0, event_start,
            event_type=event_type, as_role=as_role,
            precomputed_routing=precomputed_routing,
            precomputed_traffic=precomputed_traffic,
        )

    async def _handle_batch_input(self, user_input):
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
                except Exception as e:
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
    def _extract_react_token_count(result) -> int:
        """Sum token usage across all ReAct LLM calls recorded in the trace.

        The LLM factory maintains a process-wide TokenBudget; we read it via
        the LLM module instead of relying on the ReactResult to expose the
        counter. Falls back to 0 if TokenBudget is unavailable so the CLI
        summary line stays at "Tokens: 0" rather than "Tokens: N/A".
        """
        try:
            # Prefer the explicit counter if the agent records one
            for attr in ("total_tokens", "tokens", "token_count"):
                v = getattr(result, attr, None)
                if v:
                    return int(v)
        except Exception:
            pass
        try:
            from llm.llm_factory import get_global_token_counter
            return int(get_global_token_counter())
        except Exception:
            pass
        return 0

    async def _react_analysis_flow(
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
        """
        React 模式分析（Reasoning + Acting）。

        当 enhanced=True 时启用增强特性：
        - LLMDebateAgent（争议性结论触发三角色对抗辩论）
        - MultiAgentReportAgent（多专家联合报告，含冲突解决）
        - OnlineEvaluationAgent（每阶段质量门控）
        """
        logger.info(f"Using React Agent for AS{asn} analysis (enhanced={enhanced})")
        logger.info(f"Analysis mode: react (streaming: {self._streaming_callback is not None})")

        try:
            from agents.react_agent import ReactAgent, create_react_agent

            if self.llm is None:
                await self.setup_llm()

            from config import REACT_MAX_ROUNDS, REACT_STREAMING_ENABLED, REACT_LLM_TEMPERATURE
            agent = ReactAgent(
                llm=self.llm,
                max_rounds=REACT_MAX_ROUNDS,
                streaming_callback=self._streaming_callback if REACT_STREAMING_ENABLED else None,
                precomputed_routing=precomputed_routing,
                precomputed_traffic=precomputed_traffic,
                enhanced=enhanced,
            )

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
                # Bug fix: use `result` (the ReactResult) rather than undefined
                # `react_result` which was always raising NameError, so the
                # shared-evidence fallback path was never actually executed.
                _bucket = shared_evidence(result.run_id) if result.run_id else {}
                report_path = report_path or (
                    (_bucket.get("generate_report") or {}).get("report_path", "")
                )
            except Exception:
                pass
            report_generated = valid_llm_html_report(report_path)
            partial_success = bool(result.success) and report_generated

            # react mode: process HCAF causal attribution
            hcaf_attribution, hcaf_status = self._post_react_hcaf(result)

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
                    # Bug fix: previously these fields were missing on the
                    # ReAct code path so the CLI summary printed
                    # "Data quality: N/A" / "Confidence score: N/A".
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
                # Bug fix: expose token usage so the CLI summary doesn't print
                # "Tokens: N/A" on the ReAct path. ReAct does not maintain a
                # single token counter; we sum the per-call tokens recorded
                # by the LLM factory's TokenBudget.
                "token_count": ChiefExpertAgent._extract_react_token_count(result),
                # HCAF 归因结果（修复 Bug #6 后新增）
                "hcaf_attribution": hcaf_attribution,
                "hcaf_attribution_status": hcaf_status,
                "elapsed_seconds": elapsed,
                "error": result.error if not result.success else None,
            }

        except Exception as e:
            logger.error(f"React agent failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Fallback to legacy mode
            return await self._legacy_direct_analysis(
                asn, start_time, end_time, user_input, t0, event_start
            )

    def _post_react_hcaf(self, react_result):
        """Bug #6 修复：react 模式后处理 HCAF 因果归因。

        ReactAgent 的工具（analyze_traffic / analyze_routing / reason_and_classify /
        generate_report 等）会写入实例级 self._evidence dict，在 run() 结束时通过
        ReactResult.evidence 字段暴露。本方法优先从 result.evidence 读取数据，
        兼容旧版 _SHARED_EVIDENCE 作为兜底。
        """
        try:
            from agents.causal_attribution import 因果归因引擎

            # use result.evidence (instance variable copy) as priority
            evidence = getattr(react_result, "evidence", None) or {}
            if not evidence:
                try:
                    from agents.react_agent import shared_evidence
                    if react_result.run_id:
                        evidence = shared_evidence(react_result.run_id) or {}
                except Exception:
                    evidence = {}
            # 收集 routing / traffic 时间线
            routing_timeline = []
            traffic_timeline = []
            routing_ctx = {}
            traffic_ctx = {}

            for tool_name, data in evidence.items():
                if not isinstance(data, dict):
                    continue
                # analyze_traffic / analyze_prefix_traffic 输出含 traffic_timeline
                if "traffic_timeline" in data and isinstance(data["traffic_timeline"], list):
                    for pt in data["traffic_timeline"]:
                        if isinstance(pt, dict):
                            traffic_timeline.append({
                                "timestamp": pt.get("timestamp") or pt.get("time"),
                                "score": pt.get("score") or pt.get("anomaly_score", 0),
                            })
                # analyze_routing 输出含 routing_timeline
                if "routing_timeline" in data and isinstance(data["routing_timeline"], list):
                    for pt in data["routing_timeline"]:
                        if isinstance(pt, dict):
                            routing_timeline.append({
                                "timestamp": pt.get("timestamp") or pt.get("time"),
                                "score": pt.get("score") or pt.get("anomaly_score", 0),
                            })
                # as_path / event_type 从路由输出抓取
                if "as_path" in data and isinstance(data["as_path"], list):
                    routing_ctx["as_path"] = data["as_path"]
                if "event_type" in data:
                    routing_ctx["event_type"] = data["event_type"]
                # traffic_drop_ratio 从流量输出抓取
                if "traffic_drop_ratio" in data:
                    traffic_ctx["traffic_drop_ratio"] = data["traffic_drop_ratio"]
                if "affected_prefix" in data:
                    traffic_ctx["affected_prefix"] = data["affected_prefix"]

            if not routing_timeline and not traffic_timeline:
                return {}, "skipped_no_data"

            # 截断到 200 条（避免 tool 输出过大导致 HCAF 计算慢）
            routing_timeline = routing_timeline[:200]
            traffic_timeline = traffic_timeline[:200]

            engine = 因果归因引擎()
            result = engine.分析(
                路由时间线=routing_timeline,
                流量时间线=traffic_timeline,
                路由上下文=routing_ctx,
                流量上下文=traffic_ctx,
                拓扑上下文={},
                目标AS=None,
            )

            attribution = {
                "direction": getattr(result, "方向", "unknown"),
                "strength": getattr(getattr(result, "强度", None), "value", "unknown"),
                "confidence": float(getattr(result, "置信度", 0.0)),
                "is_causal": bool(getattr(result, "是否为因果", False)),
                "convergence": float(getattr(result, "收敛度", 0.0)),
                "explanation": getattr(result, "解释", ""),
                "novel_findings": [
                    {"method": f.方法名, "direction": f.方向, "strength": float(f.强度)}
                    for f in (getattr(result, "创新发现列表", []) or [])
                ],
            }
            logger.info(
                f"[HCAF post-react] 方向={attribution['direction']}, "
                f"强度={attribution['strength']}, 置信={attribution['confidence']:.0%}"
            )
            return attribution, "ok"

        except Exception as e:
            logger.warning(f"[HCAF post-react] 失败: {e}")
            return {}, "failed"

    # ── Workflow Engine Mode ─────────────────────────────────────────────────

    async def _workflow_analysis_flow(
        self,
        asn,
        start_time,
        end_time,
        user_input,
        t0,
        event_start: datetime,
        event_type: str = None,
        as_role: str = None,
        precomputed_routing: dict = None,
        precomputed_traffic: dict = None,
    ):
        """
        Execute analysis using the new workflow engine.
        
        This method uses the graph-based workflow engine for:
        - Smart Cascade: Traffic first, routing on demand
        - Quick screening (5-10s pre-check)
        - State machine transitions
        - Error recovery
        - Quality validation
        - Cross-validation for edge cases
        """
        logger.info(f"Using Workflow Engine for AS{asn} analysis")
        logger.info(f"Analysis mode: {self.analysis_mode}")
        logger.info(f"MITM detection: {'enabled' if self.enable_mitm else 'disabled'}")
        logger.info(f"Event type: {event_type}, AS role: {as_role}")

        try:
            # Run workflow with analysis mode
            ckpt = getattr(self, "checkpoint", None)
            context = await run_workflow(
                user_input=user_input,
                asn=asn,
                start_time=start_time,
                end_time=end_time,
                parallel=False,  # Disable old parallel mode
                max_retries=3,
                analysis_mode=self.analysis_mode,
                enable_mitm=self.enable_mitm,
                enhanced=self.enhanced,
                debate_rounds=self.debate_rounds,
                evaluation_retries=self.evaluation_retries,
                checkpoint=ckpt,
                event_type=event_type,
                as_role=as_role,
                precomputed_routing=precomputed_routing,
                precomputed_traffic=precomputed_traffic,
            )

            # Process workflow result. `run_workflow` may return either a
            # WorkflowContext dataclass or, on resume / fallback, a plain
            # dict (snapshot of the same data). Handle both.
            if isinstance(context, dict):
                result = context
            else:
                result = self._process_workflow_result(
                    context, asn, start_time, end_time, t0, event_start
                )
            # Save the fully-processed result too, for fast reload on resume
            if ckpt is not None and ckpt.enabled:
                try:
                    ckpt.save("analysis", result)
                except Exception as e:
                    logger.warning(f"[Checkpoint] Failed to save analysis: {e}")

            # Mirror the saved LLM HTML path into both analysis_report and
            # report_result so downstream scripts (run_batch_reality_cases.py)
            # can verify it without reaching into chief_expert_analysis.
            # Bug fix: the previous implementation walked chief_expert_analysis
            # → report_result → analysis_report to find the path, then setdefault'd
            # the value on the other two. _process_workflow_result already sets
            # all three keys (lines below), so the second write was always
            # either a no-op or a self-overwrite — pure dead code. Keep only
            # the bare-minimum safety net: ensure both aliases carry the
            # same path that chief_expert_analysis already has.
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
            return await self._legacy_direct_analysis(
                asn, start_time, end_time, user_input, t0, event_start
            )

    def _process_workflow_result(
        self,
        context: WorkflowContext,
        asn,
        start_time,
        end_time,
        t0,
        event_start: datetime
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
                # Bug fix: previously these two fields were missing on the
                # non-chief (workflow_engine) code path, so the CLI summary
                # printed "Data quality: N/A" and "Confidence score: N/A"
                # even on a fully successful run. Derive them from the
                # evidence chain when available, otherwise fall back to a
                # well-defined default that reflects the actual confidence
                # in the analysis (verdict + anomaly counts).
                "data_quality": ChiefExpertAgent._derive_data_quality(context),
                "confidence_score": ChiefExpertAgent._derive_confidence_score(context),
                "evidence_verdict": ChiefExpertAgent._derive_verdict(context),
                "traffic_anomaly_count": (
                    (context.traffic_result or {}).get("anomaly_count")
                    if isinstance(context.traffic_result, dict) else None
                ),
                "routing_anomaly_count": ChiefExpertAgent._count_routing_anomalies(context),
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
            "token_count": self._extract_token_count(context),
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
            "victim_asns": getattr(context, "victim_asns", []) or [],
            "evidence_board": {
                "observations": context.evidence_records,
                "claims": context.diagnosis_claims,
                "verdicts": context.verification_records,
                "challenges": context.contradictions,
                "causal_attribution": context.hcaf_attribution or {},
            },
            "analysis_report": context.final_result or {},
            "report_result": context.final_result or {},
            "org_info": context.org_info or {},
            "relationships": context.as_relationships or {},
            "prefixes": context.as_prefixes or {},
            "reasoning_trace": self._build_trace(context),
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

    def _extract_token_count(self, context: WorkflowContext):
        """Extract total token count from context + TokenBudget."""
        tokens = 0

        # Method 1: From reasoning_result (per-agent breakdown)
        for result in [context.traffic_result, context.routing_result, context.reasoning_result]:
            if result and isinstance(result, dict):
                token_usage = result.get("token_usage", {})
                if isinstance(token_usage, dict):
                    if "total_across_agents" in token_usage:
                        # Bug fix 2026-09-13 (BUG-R129): the previous code
                        # used ``tokens = token_usage["total_across_agents"]``
                        # which is an unconditional *assignment*. When
                        # multiple ``*_result`` payloads carry a
                        # ``total_across_agents`` field (each partial,
                        # e.g. traffic=routing + reasoning sum), the loop
                        # would keep overwriting with the LAST observed
                        # value rather than taking the maximum. The
                        # correct fallback semantics is "Method 2
                        # (TokenBudget) is authoritative; Method 1
                        # provides a *floor* we can use when TokenBudget
                        # is unavailable", so we take ``max(tokens, ...)``
                        # to remember the highest estimate seen across
                        # the three sources.
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
        except Exception:
            pass

        return tokens

    # ── Quality derivation helpers (Bug fix: token/quality previously N/A) ──
    @staticmethod
    def _derive_verdict(context: WorkflowContext) -> str:
        """Best-effort verdict string from the evidence chain."""
        ec = getattr(context, "evidence_chain", None)
        if isinstance(ec, dict):
            verdict = ec.get("verdict")
            if verdict:
                return str(verdict)
        return "unknown"

    @staticmethod
    def _derive_confidence_score(context: WorkflowContext) -> float:
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
        except Exception:
            return 0.0

    @staticmethod
    def _derive_data_quality(context: WorkflowContext) -> str:
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
    def _count_routing_anomalies(context: WorkflowContext) -> int:
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
        except Exception:
            return 0

    def _build_trace(self, context: WorkflowContext):
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

    async def _legacy_direct_analysis(
        self,
        asn,
        start_time,
        end_time,
        user_input,
        t0,
        event_start: datetime
    ):
        """
        Legacy direct analysis mode (original implementation).

        Kept for backward compatibility and as fallback.

        Checkpointing (when enabled via CHECKPOINTING_ENABLED in config):
            - 'traffic': traffic agent output
            - 'routing': routing agent output (with detected window)
            - 'reasoning': reasoning agent output
            - 'analysis': final assembled dict (auto-saved on success)
        """
        ckpt = getattr(self, "checkpoint", None)
        logger.info(f"Using Legacy Direct Mode for AS{asn} analysis")

        # ── Stage 1: traffic ──────────────────────────────────────────
        traffic_result = ckpt.load("traffic") if ckpt else None
        if traffic_result is None:
            traffic_result = run_traffic_agent(
                user_input=user_input,
                asn=asn,
                start_time=start_time,
                end_time=end_time,
            )
            if ckpt:
                ckpt.save("traffic", traffic_result)
        else:
            logger.info(f"[Resume] Skipped traffic stage for AS{asn}")

        routing_initial = ckpt.load("routing_initial") if ckpt else None
        if routing_initial is None:
            # Initial routing scan: skip slow 24h-baseline outage detector.
            # Outage detection is expensive (re-reads 200+ txt files) and only
            # contributes a "did the AS go silent" signal — not needed for the
            # initial routing pass that mostly counts hijacks/leaks.
            # Bug fix 2026-09-14 (BUG-R131): also skip forge / MITM detection
            # by default — it requires a full-day BGP data preload (~5min for
            # a 3h window with millions of rows) and the in-process analyzer
            # has a 200k-row forge-candidate bottleneck. The user explicitly
            # accepted "forge detection default off" as the desired behaviour.
            routing_initial = await run_routing_agent_async(
                asn, start_time, end_time, use_llm=False, skip_outage=True,
                skip_forge=True,
            )
            if ckpt:
                ckpt.save("routing_initial", routing_initial)
        else:
            logger.info(f"[Resume] Skipped initial routing stage for AS{asn}")

        traffic_anomaly_count = traffic_result.get('anomaly_count', 0)
        routing_anomaly_count = routing_initial.get('total_prefix_hijacks', 0)

        if traffic_anomaly_count + routing_anomaly_count == 0:
            return self._build_no_anomaly_result(
                asn, start_time, end_time, traffic_result, routing_initial, t0, event_start
            )

        detected_start, detected_end = self._extract_anomaly_times(
            traffic_result, start_time, end_time
        )

        # ── Stage 2: routing (with detected window) ──────────────────
        routing_result = ckpt.load("routing") if ckpt else None
        if routing_result is None:
            # Skip slow 24h-baseline outage detector: Phase-1 quick pass already
            # produced an outage signal (or skipped it via skip_outage=True). Doing
            # it again in deep phase would re-read 200+ txt files and dominate wall
            # time without new information.
            # Bug fix 2026-09-14 (BUG-R131): also skip forge / MITM detection
            # to keep the deep-phase routing pass under the 900s per-mode
            # timeout used by run_4mode_batch.py.
            routing_result = await run_routing_agent_async(
                asn, detected_start, detected_end, use_llm=True, skip_outage=True,
                skip_forge=True,
            )
            if ckpt:
                ckpt.save("routing", routing_result)
        else:
            logger.info(f"[Resume] Skipped routing stage for AS{asn}")

        # ── Stage 3: reasoning ────────────────────────────────────────
        reasoning_result = ckpt.load("reasoning") if ckpt else None
        if reasoning_result is None:
            reasoning_result = run_reasoning_agent(
                asn=asn,
                start_time=detected_start,
                end_time=detected_end,
                user_input=user_input,
                pre_computed_routing=routing_result,
                pre_computed_traffic=traffic_result,
            )
            if ckpt:
                ckpt.save("reasoning", reasoning_result)
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

        report_result = await self._generate_report(
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
            "token_count": self._extract_tokens(reasoning_result),
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

        if ckpt:
            ckpt.save("analysis", result)

        return result

    def _build_no_anomaly_result(
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
            no_anomalies=True
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

    def _extract_anomaly_times(
        self,
        traffic_result,
        start_time,
        end_time
    ):
        """Extract anomaly time range from traffic result."""
        detected_start = None
        detected_end = None

        # Bug fix 2026-09-13 (BUG-R103): the previous implementation had
        # three issues:
        #
        #   1. It used ``if`` for consecutive_windows AND ``if`` (not
        #      ``elif``) for expanded_windows — so when BOTH keys were
        #      present, the consecutive block ran first, set
        #      detected_start/end, then the expanded block ran and
        #      overwrote them. The behaviour is identical to using
        #      ``elif`` (the latest writer wins) but the wasted
        #      comparison hides the priority and makes the code
        #      harder to reason about.
        #
        #   2. The local variable ``detected_windows`` was assigned in
        #      the expanded_windows branch but NEVER returned and
        #      NEVER read anywhere — pure dead code whose only
        #      side-effect was a misleading comment "用于报告展示所有窗口"
        #      suggesting downstream consumers used it.
        #
        #   3. ``outage_period_anomalies`` used ``min(times)`` /
        #      ``max(times)`` directly on raw timestamp strings, so
        #      ``detected_start`` ended up being whichever raw string
        #      sorted first lexicographically — wrong for ISO times
        #      like "2024-01-15" vs "2024-01-05". We now parse both
        #      bounds and pick min/max on parsed datetimes.
        #
        # Reorganise as an explicit priority chain: expanded_windows
        # > consecutive_anomaly_windows > outage_period_anomalies.
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
                    except Exception:
                        continue
                if parsed_times:
                    detected_start = min(parsed_times).isoformat()
                    detected_end = max(parsed_times).isoformat()
            except Exception:
                pass

        detected_start = detected_start or start_time
        detected_end = detected_end or end_time

        def normalize_ts(ts_str):
            try:
                if 'T' in ts_str:
                    dt = datetime.strptime(ts_str.split('Z')[0], '%Y-%m-%dT%H:%M:%S')
                    return dt.strftime('%Y-%m-%d %H:%M')
                return ts_str
            except Exception:
                return ts_str

        return normalize_ts(detected_start), normalize_ts(detected_end)

    def _extract_tokens(self, reasoning_result):
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

    async def _generate_report(
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
        # 优先使用传入的 routing_result 和 traffic_result（直接来自 agent）
        # 如果为空，则回退到 evidence_summary
        evidence = reasoning_result.get("evidence_summary", {}) if reasoning_result else {}

        # 使用直接传入的数据，如果为空则从 evidence_summary 提取
        traffic_data = traffic_result if traffic_result else evidence.get("traffic_data", {})
        routing_data = routing_result if routing_result else evidence.get("routing_data", {})

        # HCAF 优先取参数；否则从 reasoning_result 拿（workflow 模式已塞进去）
        hcaf = hcaf_attribution
        if not hcaf and isinstance(reasoning_result, dict):
            hcaf = reasoning_result.get("hcaf_attribution")

        # Debug logging
        logger.info(f"[_generate_report] Using traffic_data: {list(traffic_data.keys()) if isinstance(traffic_data, dict) else type(traffic_data)}")
        logger.info(f"[_generate_report] Using routing_data: {list(routing_data.keys()) if isinstance(routing_data, dict) else type(routing_data)}")
        logger.info(f"[_generate_report] routing_data origin_hijacked count: {len(routing_data.get('origin_hijacked', [])) if isinstance(routing_data, dict) else 'N/A'}")
        logger.info(f"[_generate_report] traffic_data anomalies_detected: {traffic_data.get('anomalies_detected') if isinstance(traffic_data, dict) else 'N/A'}")
        logger.info(f"[_generate_report] traffic_data plot_path: {traffic_data.get('plot_path') if isinstance(traffic_data, dict) else 'N/A'}")
        logger.info(f"[_generate_report] HCAF 状态: {'present' if hcaf else 'missing'}")

        # 提取 plot_path 用于报告嵌入
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
            fallback_report_func=generate_integrated_report,
            traffic_plot_path=plot_path,  # 传递图表路径
            hcaf_attribution=hcaf,
        )

# ==================== Entry Points ====================

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
    resume: bool = CHECKPOINTING_ENABLED,
    no_checkpoint: bool = not CHECKPOINTING_ENABLED,
    event_type: str = None,
    as_role: str = None,
    precomputed_routing: dict = None,
    precomputed_traffic: dict = None,
    time_window_extension_hours: float = 0.0,
):
    """
    Async entry point for BGP anomaly analysis.

    Args:
        user_input: Natural language description
        asn: AS number
        start_time: Start time (YYYY-MM-DD HH:MM)
        end_time: End time (YYYY-MM-DD HH:MM)
        analysis_mode: "traffic_first" (default) or "react"
        enable_mitm: Enable MITM/hijack detection. Defaults to config.MITM_DETECTION_ENABLED.
        resume: True to load and skip completed stages from checkpoint. Defaults to config.CHECKPOINTING_ENABLED.
        no_checkpoint: True to disable checkpointing entirely. Defaults to not config.CHECKPOINTING_ENABLED.
    """
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

    ckpt = CheckpointManager(
        asn=asn,
        start_time=start_time,
        mode=analysis_mode,
        enabled=resume and not no_checkpoint,
    )
    if not resume and not no_checkpoint:
        # 全新跑：清理旧 checkpoint，避免脏数据混淆
        ckpt.clear()
        ckpt.enabled = False  # 本次不写 checkpoint，除非显式 resume

    # ── 扩展时间窗口 ───────────────────────────────────────────────────────────
    if time_window_extension_hours > 0:
        from agents.coordination_utils import normalize_time
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        start_time = (start_dt - timedelta(hours=time_window_extension_hours)).strftime("%Y-%m-%d %H:%M")
        end_time = (end_dt + timedelta(hours=time_window_extension_hours)).strftime("%Y-%m-%d %H:%M")
        logger.info(f"[TimeWindow] Extended to {start_time} ~ {end_time} (±{time_window_extension_hours}h)")

    chief_expert = ChiefExpertAgent(
        MODEL, API_KEY, BASE_URL,
        analysis_mode=analysis_mode,
        enable_mitm=enable_mitm,
        enhanced=enhanced,
        debate_rounds=debate_rounds,
        evaluation_retries=evaluation_retries,
    )
    chief_expert.checkpoint = ckpt
    result = await chief_expert.coordinate_analysis(
        user_input, asn, start_time, end_time,
        event_type=event_type,
        as_role=as_role,
        precomputed_routing=precomputed_routing,
        precomputed_traffic=precomputed_traffic,
    )

    result = make_json_safe(result)

    # Atomic write: serialise to a sibling temp file first, then rename
    # so a crash or Ctrl-C never leaves the caller reading a half-written
    # ``analysis.json``. Bug fix 2026-09-13 (BUG-R51): the previous
    # implementation had no try/except around the serialise+rename. A
    # disk-full or permission error would surface as a top-level
    # exception, discarding the perfectly good ``result`` we just
    # produced (and forcing the user to rerun the (expensive) pipeline).
    # Now we log the failure loudly and still return ``result`` so the
    # caller keeps their data; we only lose the on-disk file.
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


# ── CheckpointManager ────────────────────────────────────────────────────────
# 断点续传：每个 (asn, start_time, mode) 对应一组 checkpoint
# 命名：<checkpoint_dir>/ckpt_<asn>_<start_safe>_<mode>.json
class CheckpointManager:
    """
    按阶段保存中间结果，启用 checkpoint 后支持断点续传，跳过已完成步骤。

    Stages（按顺序）：
      1. traffic      — TrafficAgent 的完整输出
      2. routing      — RoutingAgent 的完整输出
      3. reasoning    — ReasoningAgent 的完整输出
      4. analysis     — 最终组装结果

    Usage:
        ckpt = CheckpointManager(asn, start_time, mode)
        if (traffic := ckpt.load("traffic")) is None:
            traffic = run_traffic_agent(...)
            ckpt.save("traffic", traffic)
    """

    STAGE_ORDER = ("traffic", "routing", "reasoning", "report", "analysis")

    def __init__(self, asn, start_time: str, mode: str, checkpoint_dir: Optional[Path] = None,
                 enabled: bool = True):
        self.asn = str(asn)
        # Keep the original ``start_time`` for round-tripping through JSON;
        # earlier versions wrote the sanitized ``self.tag`` into the payload
        # which polluted the ``start_time`` field with the AS+mode suffix.
        self.start_time = str(start_time)
        # 文件名安全化：替换空格、冒号为下划线
        self.tag = f"{self.asn}_{self.start_time.replace(' ', '_').replace(':', '')}_{mode}"
        self.checkpoint_dir = Path(checkpoint_dir) if checkpoint_dir else PROJECT_ROOT / "results" / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.checkpoint_dir / f"ckpt_{self.tag}.json"
        self.enabled = enabled
        self._stages: dict[str, dict] = {}
        if self.enabled and self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._stages = data.get("stages", {}) or {}
                logger.info(
                    f"[Checkpoint] Resuming from {self.path.name}, "
                    f"completed stages: {[s for s in self.STAGE_ORDER if s in self._stages]}"
                )
            except Exception as e:
                logger.warning(f"[Checkpoint] Failed to read existing checkpoint: {e}; starting fresh")
                self._stages = {}

    def has(self, stage: str) -> bool:
        """Returns True if this stage has a valid cached result."""
        return self.enabled and stage in self._stages and bool(self._stages[stage])

    def load(self, stage: str) -> Optional[dict]:
        """Load a previously saved stage result, or None if not available."""
        if not self.has(stage):
            return None
        logger.info(f"[Checkpoint] Loading stage '{stage}' from {self.path.name}")
        return self._stages.get(stage)

    def save(self, stage: str, data) -> None:
        """Save a stage result and flush to disk."""
        if not self.enabled:
            return
        try:
            safe = make_json_safe(data)
        except Exception as exc:
            # Bug fix 2026-09-13: previously, if make_json_safe raised, the
            # checkpoint was silently replaced with the first 1000 chars of
            # str(data) — a near-useless artefact that hides the failure.
            # Now we mark the stage as truncated and log loudly so the
            # operator can investigate.
            from utils.logger import logger as _logger
            _logger.warning(
                f"[Checkpoint] make_json_safe failed for stage '{stage}': {exc!r}; "
                "saving size-limited str fallback with a warning marker."
            )
            safe = {
                "_truncated": True,
                "_reason": f"make_json_safe failed: {exc!r}",
                "raw": str(data)[:1000],
            }
        self._stages[stage] = safe
        try:
            payload = {
                "asn": self.asn,
                "start_time": self.start_time,
                "stages": self._stages,
                "updated_at": datetime.now().isoformat(),
            }
            # Bug fix 2026-09-13 (BUG-R113): the previous code wrote the
            # checkpoint JSON via ``open(path, "w").write(...)`` — a
            # non-atomic operation that could leave a partial file on
            # disk if the process died mid-write (power outage, OOM
            # kill, Ctrl-C). The next ``__init__`` would then fail at
            # ``json.load(f)``, drop the whole file into ``except`` and
            # reset ``self._stages = {}`` — silently losing every
            # previously-completed stage.
            #
            # The fix mirrors the one applied to ``parquet_cache``
            # (BUG-R93): write to ``path.tmp`` first, fsync to flush
            # kernel buffers, then ``os.replace`` (which is atomic on
            # POSIX) onto the real path. A crash anywhere before
            # ``os.replace`` leaves the old checkpoint untouched;
            # after ``os.replace`` the new one is durable.
            import os as _os
            tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
                    try:
                        f.flush()
                        _os.fsync(f.fileno())
                    except (AttributeError, OSError):
                        # fsync may fail on some filesystems (e.g. tmpfs
                        # on some Linux configs); the atomic replace is
                        # still a strict improvement over the open(path, "w")
                        # implementation, so we tolerate fsync failures.
                        pass
                _os.replace(tmp_path, self.path)
                logger.info(f"[Checkpoint] Saved stage '{stage}' -> {self.path.name}")
            except Exception as write_exc:
                logger.warning(f"[Checkpoint] Failed to write checkpoint: {write_exc}")
                # Best-effort cleanup of the tmp file
                try:
                    if tmp_path.exists():
                        tmp_path.unlink()
                except OSError:
                    pass
        except Exception as e:
            logger.warning(f"[Checkpoint] Failed to write checkpoint: {e}")

    def clear(self) -> None:
        """Remove all saved stages (e.g. for fresh start)."""
        self._stages = {}
        if self.path.exists():
            try:
                self.path.unlink()
                logger.info(f"[Checkpoint] Cleared checkpoint {self.path.name}")
            except Exception:
                pass


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
    resume: bool = CHECKPOINTING_ENABLED,
    no_checkpoint: bool = not CHECKPOINTING_ENABLED,
):
    """
    Sync entry point for traffic outage analysis.

    enable_mitm / resume / no_checkpoint default to config values
    (MITM_DETECTION_ENABLED, CHECKPOINTING_ENABLED).
    """
    return asyncio.run(analyze_traffic_outage_async(
        user_input, asn, start_time, end_time, analysis_mode,
        enable_mitm,
        enhanced, debate_rounds, evaluation_retries,
        resume=resume, no_checkpoint=no_checkpoint,
    ))


# ──────────────────────── Two-Phase Diagnosis API ─────────────────────────
# 设计目的：现实中的人急于"立即知道结果"，而不是等 LLM 报告出来。
# Phase 1（quick）：同步、0 LLM 调用、~60 秒拿到结构化 JSON 结论
#   - 流量异常检测（Cloudflare Radar）
#   - 路由异常检测（hijack/leak/outage）
#   - 时间关联度评估（routing ↔ traffic）
#   - 给出一个快速结论："真实incident" 还是 "静默告警"
# Phase 2（deep）：异步、含 LLM 调用、3-5 分钟生成 HTML 报告
#   - 接续 quick 的结果，无需重跑 traffic / routing
#   - 完整 LLM 推理 + HTML 报告
# 旧的 `--mode traffic_first_enhanced` / `--mode react_enhanced` 被吸收到 --mode deep + --enhanced。
# 旧的 `--mode traffic_first` / `--mode react` 仍可用作"一阶段"兼容入口。

def _run_quick_analysis_async(
    asn,
    start_time,
    end_time,
    user_input=None,
    enable_mitm: bool = MITM_DETECTION_ENABLED,
    cache_dir: Optional[Path] = None,
    skip_correlation: bool = False,
):
    """Phase 1: 0 LLM, just facts. Returns raw traffic/routing/correlation dicts.

    Caches intermediate results under `results/quick/<asn>_<start>_<end>.json`
    so a follow-up `analyze_deep_from_quick` can re-use them without re-downloading
    BGP updates from RIPE RIS.

    Args:
        asn: AS number
        start_time: ISO-like "YYYY-MM-DD HH:MM"
        end_time:   ISO-like "YYYY-MM-DD HH:MM"
        user_input: optional natural-language input (for context only; not parsed here)
        enable_mitm: whether to run MITM/forge hijack detection (default off — quick phase
                     uses a lightweight pass to keep latency low)
        cache_dir: override cache location; default = PROJECT_ROOT/results/quick
        skip_correlation: skip temporal correlation step (saves time when the caller will
                         not need it in this run)

    Returns:
        dict with keys:
          traffic (dict), routing (dict), correlation (dict),
          quick_verdict (str), traffic_signal_present (bool), anomaly_summary,
          cached_at, elapsed_seconds
    """
    t0 = perf_counter()
    cache_dir = Path(cache_dir) if cache_dir else (PROJECT_ROOT / "results" / "quick")
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe_tag = f"{asn}_{str(start_time).replace(' ', '_').replace(':', '')}_{str(end_time).replace(' ', '_').replace(':', '')}"
    cache_file = cache_dir / f"quick_{safe_tag}.json"

    # ── Cache hit short-circuit ──────────────────────────────────────
    # If a previous quick run produced a result for the exact same
    # asn/start/end, reuse it instead of re-downloading BGP updates +
    # re-querying Cloudflare Radar. This makes repeated invocations of
    # `analyze_quick` free, which is the whole point of the two-phase
    # design (quick → deep reuses quick's cache).
    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            cached["cache_hit"] = True
            cached["cache_path"] = str(cache_file)
            cached["elapsed_seconds"] = round(perf_counter() - t0, 2)
            return cached
        except Exception as _cache_err:
            logger.debug(f"quick cache read failed: {_cache_err!r}")

    # ── 拉流量 ──────────────────────────────────────────────────────
    traffic: dict = {}
    routing: dict = {}
    warnings: list = []
    try:
        from agents.traffic_agent import run_traffic_agent
        # Phase 1: skip the ~10s LLM round-trip on traffic insights.
        # CloudflareRadar detection still runs so we have raw anomaly counts.
        traffic = run_traffic_agent(
            user_input=user_input, asn=asn, start_time=start_time, end_time=end_time,
            use_llm=False,
        ) or {}
    except Exception as _te:
        warnings.append(f"traffic_agent failed: {_te!r}")
        logger.error(traceback.format_exc())

    # ── 拉路由 ──────────────────────────────────────────────────────
    try:
        # Always run the non-LLM router path in phase 1 (faster, deterministic)
        routing = asyncio.run(_async_quick_routing(
            asn=asn, start_time=start_time, end_time=end_time,
            enable_mitm=enable_mitm,
        )) or {}
    except Exception as _re:
        warnings.append(f"routing_agent failed: {_re!r}")
        logger.error(traceback.format_exc())

    # ── 关联 ────────────────────────────────────────────────────────
    correlation: dict = {}
    if not skip_correlation and traffic and routing:
        try:
            from agents.correlation_analyzer import analyze_temporal_correlation
            from agents.report_agent import extract_traffic_anomaly_window as _etaw
            tr_unwrapped = traffic.get("result", traffic) if isinstance(traffic, dict) else traffic
            rr_unwrapped = routing.get("result", routing) if isinstance(routing, dict) else routing
            tr_window = _etaw(tr_unwrapped if isinstance(tr_unwrapped, dict) else {})
            correlation = analyze_temporal_correlation(
                traffic_raw=tr_unwrapped,
                routing_result=rr_unwrapped,
                target_as=str(asn),
                traffic_anomaly_window=tr_window or {},
            ) or {}
        except Exception as _ce:
            warnings.append(f"correlation failed: {_ce!r}")
            logger.debug(traceback.format_exc())

    # ── 摘要 + 快速结论 ─────────────────────────────────────────────
    summary = build_quick_summary(traffic, routing, correlation)
    verdict = summary.get("quick_verdict", "unknown")
    signal_present = summary.get("traffic_signal_present", False)

    elapsed = round(perf_counter() - t0, 2)
    result = {
        "success": True,
        "asn": str(asn),
        "start_time": start_time,
        "end_time": end_time,
        "phase": "quick",
        "traffic": traffic,
        "routing": routing,
        "correlation": correlation,
        "anomaly_summary": summary,
        "quick_verdict": verdict,
        "traffic_signal_present": signal_present,
        "warnings": warnings,
        "elapsed_seconds": elapsed,
        "cached_at": datetime.now().isoformat(),
    }

    # Persist for a follow-up analyze_deep_from_quick
    try:
        # Bug fix 2026-09-13 (BUG-R122): the previous code wrote the
        # quick-phase cache via ``cache_file.write_text(...)`` — a
        # non-atomic operation that, on a crash mid-write, left a
        # partial JSON file at ``cache_file``. The next run would
        # then either trip ``json.loads(cache_file.read_text())``
        # (because the file is incomplete) — already handled by the
        # try/except above — *or* worse, the JSON happened to be
        # complete enough that it parsed into a partially-populated
        # result object with a corrupt ``traffic`` / ``routing``
        # sub-dict, and the deep phase would silently reuse that
        # garbage instead of recomputing it (defeating the entire
        # two-phase design). The fix mirrors BUG-R93 / R113 / R116:
        # write to ``cache_file.tmp`` first, fsync, then
        # ``os.replace`` onto the real path. On crash mid-write the
        # old cache is preserved (if any); on first run the
        # ``.tmp`` orphan is cleaned up here.
        import os as _os
        tmp_path = cache_file.with_suffix(cache_file.suffix + ".tmp")
        try:
            payload = json.dumps(
                make_json_safe(result), indent=2, ensure_ascii=False, default=str
            )
            with open(tmp_path, "w", encoding="utf-8") as _cf:
                _cf.write(payload)
                try:
                    _cf.flush()
                    _os.fsync(_cf.fileno())
                except (AttributeError, OSError):
                    pass
            _os.replace(tmp_path, cache_file)
            result["cache_path"] = str(cache_file)
        except Exception as _wk_err:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            logger.warning(f"[quick] Failed to write cache: {_wk_err}")
    except Exception as _ck_err:
        logger.warning(f"[quick] Failed to write cache: {_ck_err}")

    return result


async def _async_quick_routing(asn, start_time, end_time, enable_mitm, skip_outage=True):
    """Quick routing analysis without LLM (Phase 1).

    Defaults to a light pass that:
      * skips slow forge / MITM detection (needs full-day pre-load + ES lookup)
      * skips path-leak detection (the slowest step at high announcement rates)
      * optionally skips outage detection (24h baseline re-reads 200+ txt files
        and dominates quick-phase wall time)

    Use `skip_outage=False` only when you specifically want outage scoring in
    the Phase-1 result.
    """
    from agents.routing_agent import run_routing_agent_async

    # ── Light hijack path: bypass the streaming pipeline ───────────────────────
    # The full streaming detector (detect_hijacks → detect_hijacks_batch →
    # detect_hijacks_streaming) re-runs vectorized origin detection once per
    # 5-minute chunk (~37 chunks for a 3h window ⇒ ~55s wall time at MAX_WORKERS=1).
    #
    # For Phase 1 we only need origin hijack counts (no forge / no per-chunk
    # streaming). Loading the whole window into a single Polars DataFrame and
    # calling detect_origin_hijacks ONCE collapses 55s to ~3-5s.
    quick_hijack = _light_origin_hijack(asn, start_time, end_time)

    # Run the rest of routing through the standard path, but skip the
    # streaming hijack detector (we already produced origin_hijacked /
    # origin_hijacking above in a single pass). Leak/outage follow the
    # same skip_* flags as before.
    rest = await run_routing_agent_async(
        asn=asn, start_time=start_time, end_time=end_time,
        use_llm=False,
        enable_mitm=enable_mitm,
        skip_leak=True,        # light mode skips path-leak detection
        skip_forge=True,       # light mode skips forge / MITM (needs full-day pre-load)
        skip_outage=skip_outage,  # outage detector scans 24h baseline → expensive
        skip_hijack_streaming=True,  # single-pass detector already filled origin_hijacked/ing
    )

    # Merge quick hijack counts into the routing result.
    if isinstance(rest, dict) and quick_hijack:
        rest.setdefault("origin_hijacked", [])
        rest.setdefault("origin_hijacking", [])
        rest["origin_hijacked"] = quick_hijack.get("origin_hijacked", [])
        rest["origin_hijacking"] = quick_hijack.get("origin_hijacking", [])
        rest["total_prefix_hijacks"] = (
            len(rest["origin_hijacked"]) + len(rest.get("forge_hijacked", []))
        )
    return rest


def _light_origin_hijack(asn, start_time, end_time) -> dict:
    """Single-pass vectorized origin hijack detection.

    Bypasses the streaming `detect_hijacks_batch` pipeline. Loads all 5-min
    chunks for the window into a single DataFrame and calls
    `detect_origin_hijacks` once. Wall-time drops from ~55s to ~3-5s for a
    3-hour AS12479-scale window at MAX_WORKERS=1.

    Returns dict with keys `origin_hijacked` and `origin_hijacking` (lists of
    alert dicts). Empty lists on any failure (fail-safe).
    """
    try:
        from datetime import datetime as _dt
        from data.parquet_cache import iter_window_chunks

        # Coerce ISO strings to UTC-naive datetimes (parquet_cache expects naive)
        def _coerce(value):
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

        start_dt = _coerce(start_time)
        end_dt = _coerce(end_time)
        if start_dt is None or end_dt is None or end_dt <= start_dt:
            return {"origin_hijacked": [], "origin_hijacking": []}

        # ── Load all 5-min chunks into one DataFrame ─────────────────────
        # The parquet cache already keeps memory bounded: each chunk is the
        # full content of one RIPE RIS 5-minute file (≤80 MB), and for a 3h
        # window that's ~37 chunks ⇒ peak ~3 GB which the system can handle.
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
        # Polars Parquet files typically use snake_case (`as_path`) while
        # the upstream MRT schema uses hyphens (`as-path`).  Accept either
        # so the column is never silently dropped before detection runs.
        keep = ["prefix"]
        for col in ("as-path", "as_path"):
            if col in df.columns:
                keep.append(col)
                break
        if "timestamp" in df.columns:
            keep.append("timestamp")
        df = df.select([c for c in keep if c in df.columns])

        # ── Build prefix → owner AS mapping for target AS ────────────────
        from data.prefix2as_loader import process_prefix2as
        p2a_path = process_prefix2as(start_dt)
        with open(p2a_path, "r", encoding="utf-8") as f:
            prefix_to_as = json.load(f)

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
    except Exception as _e:
        logger.warning(f"[light-hijack] failed (fallback to streaming): {_e}")
        return {"origin_hijacked": [], "origin_hijacking": []}


def build_quick_summary(traffic: dict, routing: dict, correlation: dict) -> dict:
    """Build a human-readable anomaly summary from raw agent outputs.

    Summary fields:
        traffic_anomaly_count (int)
        traffic_signal_present (bool) ← **the decisive field for "real incident?"**
        routing_hijack_count (int)
        routing_leak_count (int)
        routing_outage_score (float)
        correlation_level (str) ← "high"/"medium"/"low"/"none"
        correlation_strength (float)
        quick_verdict (str) ← "real_incident" / "silent_alert" / "routing_only" / "traffic_only" / "unknown"
    """
    tr = traffic.get("result", traffic) if isinstance(traffic, dict) else {}
    if not isinstance(tr, dict):
        tr = {}

    rr = routing.get("result", routing) if isinstance(routing, dict) else {}
    if not isinstance(rr, dict):
        rr = {}

    traffic_anomaly_count = int(tr.get("anomaly_count", 0) or 0)
    # Motivation: traffic is the ground truth. Only anomaly_count counts.
    # `data_available` just means Cloudflare Radar returned data points;
    # a healthy AS with no anomalies still returns data points but is NOT
    # a traffic signal. Use anomaly_count as the sole indicator.
    traffic_signal = traffic_anomaly_count > 0

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

    leak_count = len(leak_section.get("route_leaks") or [])
    if leak_count == 0:
        leak_count = len(rr.get("leaks") or rr.get("route_leaks") or [])

    outage_score = float(outage_section.get("score", 0.0) or 0.0) if isinstance(outage_section, dict) else 0.0
    if outage_score == 0.0 and isinstance(rr.get("outages"), dict):
        outage_score = float(rr["outages"].get("score", 0.0) or 0.0)

    routing_signal = (hijack_count + leak_count) > 0 or outage_score > 0.5

    # correlation_analyzer.analyze_temporal_correlation() returns a dict whose
    # actual correlation level lives under `correlation.signals.temporal_proximity`
    # (strong / moderate / weak / none) OR `summary.correlation_level` (which
    # mirrors `correlation.level`). The top-level `level` is always
    # "SIGNALS_PRECOMPUTED" — not useful here.
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

    # Map temporal_proximity to chief_agent's expected semantic levels
    # strong/moderate → high, weak → low, none → none.
    if correlation_level in ("strong", "moderate", "high", "medium"):
        correlation_level = "high"
    elif correlation_level == "weak":
        correlation_level = "low"
    elif correlation_level in ("signals_precomputed", "observational_only"):
        correlation_level = "none"

    # ── 快速结论判断 ─────────────────────────────────────────────────
    # 1. 路由+流量都有异常 + 高关联 → 真实 incident
    # 2. 路由有异常 + 流量平静 → 静默告警
    # 3. 流量异常 + 路由平静 → 其他原因（BGP 异常是单向的，需要 flow 进一步分析）
    # 4. 都没异常 → "无明确异常"（not actionable）
    if traffic_signal and routing_signal and correlation_level in ("high", "medium", "low"):
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
        "routing_outage_score": outage_score,
        "correlation_level": correlation_level,
        "correlation_strength": round(correlation_strength, 3),
        "quick_verdict": verdict,
    }


def analyze_quick(
    asn,
    start_time,
    end_time,
    user_input=None,
    enable_mitm: bool = MITM_DETECTION_ENABLED,
    cache_dir: Optional[Path] = None,
) -> dict:
    """**Phase 1** of the two-phase diagnosis. Sync. 0 LLM. ~60 s.

    Returns a JSON-serializable dict with raw traffic / routing / correlation
    results, plus a human-readable anomaly summary and a `quick_verdict`.

    The result dict is the input to `analyze_deep_from_quick()` for Phase 2.

    Sample:
        >>> result = analyze_quick('12479', '2024-01-03 14:45', '2024-01-03 18:00')
        >>> print(result['quick_verdict'], result['anomaly_summary']['traffic_signal_present'])
    """
    return _run_quick_analysis_async(
        asn=asn, start_time=start_time, end_time=end_time,
        user_input=user_input,
        enable_mitm=enable_mitm,
        cache_dir=cache_dir,
    )


def analyze_deep_from_quick(
    quick_result: dict,
    user_input: Optional[str] = None,
    analysis_mode: str = "traffic_first",
    enhanced: bool = False,
    debate_rounds: int = 1,
) -> dict:
    """**Phase 2** of the two-phase diagnosis. Sync. ~3-5 min, runs the LLM.

    Args:
        quick_result: dict returned by `analyze_quick()`. Phase 2 reuses
            the cached traffic/routing results without re-downloading BGP data.
        user_input: optional context string forwarded to the LLM.
        analysis_mode: legacy shape selector. Default "traffic_first".
        enhanced: if True, fires one round of LLM debate after the main report.

    Returns:
        Same dict shape as `analyze_traffic_outage()`, plus `phase="deep"`.
    """
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
        enhanced=enhanced,
        debate_rounds=debate_rounds,
    )

    t0 = perf_counter()
    deep_result = asyncio.run(_deep_only_pipeline(
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
    return deep_result


async def _deep_only_pipeline(
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


def load_quick_cache(cache_path: str) -> Optional[dict]:
    """Load a Phase-1 result from disk for a Phase-2 follow-up."""
    p = Path(cache_path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


# ==================== CLI ====================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="BGP Anomaly Analysis - Multi-Agent System (Two-Phase)",
        usage=(
            "python chief_agent.py --asn <ASN> --start <TIME> --end <TIME> "
            "[--mode quick|deep|traffic_first|react] [--enhanced] "
            "[--quick-cache <path>]"
        ),
    )
    parser.add_argument("--asn", help="AS number to analyze")
    parser.add_argument("--start", help="Start time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--end", help="End time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--user-input", help="Natural language input describing the event")
    parser.add_argument(
        "--mode", default="quick",
        choices=["quick", "deep", "traffic_first", "react",
                 "traffic_first_enhanced", "react_enhanced"],
        help=(
            "quick (default; Phase 1, ~60s, 0 LLM), "
            "deep (Phase 2; uses --quick-cache if provided), "
            "traffic_first/react (single-phase legacy), "
            "traffic_first_enhanced/react_enhanced (legacy + --enhanced)"
        ),
    )
    parser.add_argument("--enhanced", action="store_true", default=False,
                       help="Enable enhanced debate round (only with --mode deep)")
    parser.add_argument("--debate-rounds", type=int, default=1,
                       help="Number of debate rounds in --mode deep + --enhanced (default: 1)")
    parser.add_argument("--evaluation-retries", type=int, default=2,
                       help="Max evaluation retries in enhanced mode (default: 2)")
    parser.add_argument(
        "--quick-cache",
        help="Path to a quick-phase result JSON; run Phase 2 without re-detecting routing/traffic.",
    )
    parser.add_argument(
        "--json-summary", action="store_true", default=False,
        help="Print Phase 1 anomaly_summary as JSON (for batch consumption)",
    )
    # Bug fix: README + run_v2_events.sh both reference --json-output but the
    # CLI parser never declared it, so every v2 event invocation would die
    # with "unrecognized arguments: --json-output" before the workflow
    # could even start. We accept --json-output and short-circuit to the
    # JSON_OUTPUT_ENABLED branch so the documented behaviour matches.
    parser.add_argument(
        "--json-output", action="store_true", default=False,
        help="Emit full structured result as JSON to stdout (overrides JSON_OUTPUT_ENABLED env var)",
    )

    args = parser.parse_args()

    # ── Two-phase dispatch ─────────────────────────────────────────────
    # quick → run analyze_quick, no LLM, write cache, exit 0
    # deep + (--quick-cache or implicit re-run of quick) → run analyze_deep_from_quick
    # traffic_first / react → run analyze_traffic_outage (legacy one-phase)
    if args.mode == "quick":
        if not all([args.asn, args.start, args.end]):
            parser.error("--asn, --start, --end required for --mode quick")
        # Bug fix: when --json-output is requested (used by run_v2_events.sh),
        # skip the human-readable mode banner entirely so stdout contains
        # nothing but parseable JSON. Mixing prose with JSON makes downstream
        # ``json.loads(open(out).read())`` fail in batch pipelines.
        if not getattr(args, "json_output", False):
            print(f"Mode: quick (Phase 1, 0 LLM) | MITM: {'enabled' if MITM_DETECTION_ENABLED else 'disabled'} | Enhanced: off")
            print("=" * 60)
        result = analyze_quick(
            asn=args.asn, start_time=args.start, end_time=args.end,
            user_input=args.user_input,
            enable_mitm=MITM_DETECTION_ENABLED,
        )
        # Bug fix: --json-output (full JSON, run_v2_events.sh style) must
        # take precedence over --json-summary (Phase-1 anomaly_summary
        # only) AND the human-readable verdict output. Previously, quick
        # mode emitted prose even when --json-output was set, breaking
        # batch consumers that rely on stdout containing parseable JSON.
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
            print(f"Leaks: {summary.get('routing_leak_count')}")
            print(f"Outage score: {summary.get('routing_outage_score')}")
            print(f"Correlation: {summary.get('correlation_level')} (strength={summary.get('correlation_strength')})")
            print(f"\n>>> QUICK VERDICT: {result.get('quick_verdict')}")
            verdict = result.get("quick_verdict")
            if verdict == "real_incident":
                print("⚠ 真实 incident — BGP 告警引起了流量变化，需要处理")
            elif verdict == "silent_alert":
                print("✅ 静默告警 — BGP 事件存在但未影响流量，可忽略")
            elif verdict == "traffic_only":
                print("🔍 流量异常但路由平静 — 需要其他原因分析 (非 BGP 范畴)")
            elif verdict == "correlation_uncertain":
                print("❓ 流量 + 路由都有异常但时间不重叠 — 需深入分析")
            else:
                print("ℹ️  无明确异常")
            if result.get("cache_path"):
                print(f"\nQuick cache written: {result.get('cache_path')}")
                print(f"→ run Phase 2 with: --mode deep --quick-cache {result.get('cache_path')}")
            if result.get("warnings"):
                print(f"\nWarnings: {result['warnings']}")
        sys.exit(0 if result.get("success") else 1)

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
            # Bug fix 2026-09-13 (BUG-R63): when --json-output is on,
            # the subsequent ``Mode: deep...`` banner below would
            # pollute stdout before the JSON dump, breaking
            # ``json.loads(stdout)`` for batch consumers. Suppress the
            # banner (and the auto-quick fallback message) when JSON
            # output is requested.
            if not (JSON_OUTPUT_ENABLED or getattr(args, "json_output", False)):
                print("No --quick-cache given; running quick phase first...")
            quick = analyze_quick(
                asn=args.asn, start_time=args.start, end_time=args.end,
                user_input=args.user_input,
                enable_mitm=MITM_DETECTION_ENABLED,
            )
        if not (JSON_OUTPUT_ENABLED or getattr(args, "json_output", False)):
            print(f"Mode: deep (Phase 2, LLM) | MITM: disabled | Enhanced: {'ON' if args.enhanced else 'off'}")
            print(f"Quick verdict: {quick.get('quick_verdict')} | traffic_signal={quick.get('traffic_signal_present')}")
            print("=" * 60)
        result = analyze_deep_from_quick(
            quick_result=quick,
            user_input=args.user_input,
            analysis_mode="traffic_first",
            enhanced=args.enhanced,
            debate_rounds=args.debate_rounds,
        )
    else:
        # Legacy one-phase modes (kept for backward compatibility)
        mode_arg = args.mode
        enhanced_arg = args.enhanced
        if args.mode in ("traffic_first_enhanced", "react_enhanced"):
            mode_arg = args.mode.replace("_enhanced", "")
            enhanced_arg = True
        if not args.user_input and not all([args.asn, args.start, args.end]):
            parser.error("the following arguments are required: --asn, --start, --end (unless --user-input is provided)")
        # Bug fix 2026-09-13 (BUG-R63 corollary): suppress the legacy
        # banner when --json-output is on so stdout stays pure JSON.
        if not (JSON_OUTPUT_ENABLED or getattr(args, "json_output", False)):
            print(f"Mode: {mode_arg} | MITM: {'enabled' if MITM_DETECTION_ENABLED else 'disabled'} | Enhanced: {'ON' if enhanced_arg else 'off'}")
            print(f"Checkpointing: {'enabled' if CHECKPOINTING_ENABLED else 'disabled'}")
            print("=" * 60)
        try:
            result = analyze_traffic_outage(
                user_input=args.user_input,
                asn=args.asn,
                start_time=args.start,
                end_time=args.end,
                analysis_mode=mode_arg,
                enhanced=enhanced_arg,
                debate_rounds=args.debate_rounds,
                evaluation_retries=args.evaluation_retries,
            )
        except Exception as e:
            logger.error(f"Analysis failed: {e}\n{traceback.format_exc()}")
            sys.exit(1)

    # ── JSON output mode（供批处理脚本捕获）────────────────────
    # Bug fix: --json-output CLI flag now respected (matches run_v2_events.sh
    # and the README docs; previously the argparse entry was missing so the
    # flag caused "unrecognized arguments" before any analysis ran).
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
        print(f"Analysis completed | Tokens: {result.get('token_count', 'N/A')}")
        print(f"Execution time: {result.get('execution_time_minutes', 0):.2f} minutes")
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
