"""
Chief Expert Agent - Advanced Multi-Agent Orchestrator
======================================================

This module provides the main entry point for BGP anomaly analysis,
integrating the workflow engine with specialized agents.

Architecture:
------------
    ┌─────────────────────────────────────────────────────────┐
    │                    ChiefExpertAgent                      │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │            WorkflowEngine                         │   │
    │  │  State Machine + Parallel Execution + Recovery   │   │
    │  └─────────────────────────────────────────────────┘   │
    │                          │                             │
    │         ┌────────────────┼────────────────┐            │
    │         ▼                ▼                ▼            │
    │   ┌──────────┐    ┌──────────┐    ┌──────────────┐   │
    │   │ Traffic  │    │ Routing  │    │  Reasoning   │   │
    │   │  Agent   │    │  Agent   │    │    Agent     │   │
    │   └──────────┘    └──────────┘    └──────────────┘   │
    └─────────────────────────────────────────────────────────┘

Version: 2.0
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Optional

from workflow_engine import (
    WorkflowEngine,
    WorkflowContext,
    WorkflowState,
    WorkflowEvent,
    AnalysisMode,
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
from data.asorg_loader import process_asorg
from llm.llm_factory import setup_llm_settings
from utils.helpers import make_json_safe
from utils.logger import logger
from utils.report_exporters import generate_comprehensive_report
from utils.report_generator import generate_batch_html_report, generate_comprehensive_report as generate_llm_report
from agents.coordination_utils import (
    generate_integrated_report,
    lookup_org_info,
    normalize_time,
    query_as_relationships,
    query_as_prefixes,
)
from config import API_KEY, BASE_URL, COORDINATION_TIMEOUT, MODEL, USE_DIRECT_MODE

PROJECT_ROOT = Path(__file__).parent


class ChiefExpertAgent:
    """
    Chief Expert Agent - Main orchestrator for BGP analysis.
    
    This agent coordinates multiple specialized agents to perform comprehensive
    BGP anomaly detection and analysis.
    
    Features:
    ---------
    - Smart Cascade Mode (v3.0): Traffic first, routing on demand
    - Multiple analysis modes: fast, traffic_first, full, routing_focus
    - Dual-mode execution: Legacy Direct Mode or new Workflow Engine
    - Parallel data collection (legacy mode)
    - Automatic error recovery
    - Comprehensive result tracking
    - Optional MITM (中间人劫持) detection with ES support
    
    Attributes:
    -----------
    model : str
        LLM model to use for analysis
    api_key : str
        API key for LLM access
    base_url : str
        Base URL for LLM API
    use_workflow_engine : bool
        Whether to use the new workflow engine (default: True)
    analysis_mode : str
        Analysis mode: "fast", "traffic_first", "full", "routing_focus"
    enable_mitm : bool
        Whether to enable MITM (中间人劫持) detection (default: True, requires ES)
    """
    
    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str,
        use_workflow_engine: bool = True,
        analysis_mode: str = "traffic_first",
        enable_mitm: bool = True
    ):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.use_workflow_engine = use_workflow_engine and USE_DIRECT_MODE
        self.analysis_mode = analysis_mode
        self.enable_mitm = enable_mitm  # 控制是否启用MITM检测
        self.llm = None
        self.token_counter = None
        self.asrel_file = None
        self.prefix2as_file = None
        self.asorg_file = None
        self.reasoning_analysis_result = None
        self.tool_call_counts = {'invoke_reasoning_expert': 0}
        self.current_asn = None
        self.current_start_time = None
        self.current_end_time = None
        
        # Workflow engine instance
        self._workflow_engine: Optional[WorkflowEngine] = None
    
    @property
    def workflow_engine(self) -> WorkflowEngine:
        """Get or create workflow engine instance."""
        if self._workflow_engine is None:
            self._workflow_engine = WorkflowEngine(
                max_retries=3,
                parallel_execution=True,
                skip_unnecessary_analysis=True
            )
        return self._workflow_engine
    
    async def setup_llm(self):
        """Initialize the LLM client."""
        self.llm, self.token_counter = setup_llm_settings(
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=0.1,
            timeout=300.0,
            max_retries=2
        )
    
    # ==================== Tool Wrappers ====================
    
    def wrapped_reasoning_agent(self, asn, start_time, end_time, user_input, **kwargs):
        """Wrapper for reasoning agent with call tracking."""
        if self.tool_call_counts['invoke_reasoning_expert'] > 0:
            return {
                "success": False,
                "error": "Reasoning analysis already completed. Do not call this tool again.",
                "asn": asn,
                "analysis_period": f"{start_time} to {end_time}"
            }

        self.tool_call_counts['invoke_reasoning_expert'] += 1

        if self.current_asn:
            return run_reasoning_agent(
                self.current_asn,
                self.current_start_time,
                self.current_end_time
            )

        if user_input and not (asn and start_time and end_time):
            return run_reasoning_agent(user_input=user_input)

        return run_reasoning_agent(asn, start_time, end_time)

    def wrapped_analysis_agent(self, traffic_analysis, routing_analysis, user_input=None, **kwargs):
        """Wrapper for analysis agent."""
        from agents.analysis_agent import run_analysis_agent
        return run_analysis_agent(traffic_analysis, routing_analysis, user_input)

    def query_as_organization(self, asn):
        """Query AS organization information."""
        if not self.asorg_file:
            return {"success": False, "error": "AS organization data file not available", "asn": asn}
        return lookup_org_info(str(asn), self.asorg_file)

    def query_as_relationships(self, asn):
        """Query AS relationships."""
        return query_as_relationships(str(asn), self.asrel_file)

    def query_as_prefixes(self, asn):
        """Query AS prefixes."""
        return query_as_prefixes(str(asn), self.prefix2as_file)

    # ==================== Main Coordination ====================

    async def coordinate_analysis(
        self,
        user_input: Optional[str] = None,
        asn: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> dict:
        """
        Main coordination method - dispatches to appropriate mode.
        
        Args:
            user_input: Natural language input
            asn: AS number
            start_time: Start time
            end_time: End time
            
        Returns:
            Analysis result dictionary
        """
        t0 = perf_counter()
        event_start = datetime.now()

        # Handle batch/special cases first
        if user_input and not (asn and start_time and end_time):
            batch_result = await self._handle_batch_input(user_input)
            if batch_result:
                return batch_result

        # Validate parameters
        if user_input:
            if not (start_time and end_time):
                return {"success": False, "error": "Missing start_time, end_time"}
        else:
            if not all([asn, start_time, end_time]):
                return {"success": False, "error": "Missing asn, start_time, end_time"}

        self.current_asn = asn
        self.current_start_time = start_time
        self.current_end_time = end_time

        # Choose execution mode
        if self.use_workflow_engine:
            return await self._workflow_analysis_flow(
                asn, start_time, end_time, user_input, t0, event_start
            )
        else:
            return await self._legacy_direct_analysis(
                asn, start_time, end_time, user_input, t0, event_start
            )

    async def _handle_batch_input(self, user_input: str) -> Optional[dict]:
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

        # Try country-based analysis
        country_region, c_start, c_end, c_asn = parse_country_region_input(user_input)
        if c_asn:
            return {
                "success": True,
                "parsed_asn": c_asn,
                "start_time": normalize_time(c_start) if c_start else c_start,
                "end_time": normalize_time(c_end) if c_end else c_end,
                "user_input": user_input
            }
        
        return None

    # ==================== Workflow Engine Mode ====================

    async def _workflow_analysis_flow(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        user_input: Optional[str],
        t0: float,
        event_start: datetime
    ) -> dict:
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
        logger.info(f"Using Workflow Engine (Smart Cascade) for AS{asn} analysis")
        logger.info(f"Analysis mode: {self.analysis_mode}")
        logger.info(f"MITM detection: {'enabled' if self.enable_mitm else 'disabled'}")

        try:
            # Run workflow with analysis mode
            context = await run_workflow(
                user_input=user_input,
                asn=asn,
                start_time=start_time,
                end_time=end_time,
                parallel=False,  # Disable old parallel mode
                max_retries=3,
                analysis_mode=self.analysis_mode,
                enable_mitm=self.enable_mitm
            )

            # Process workflow result
            return self._process_workflow_result(
                context, asn, start_time, end_time, t0, event_start
            )

        except Exception as e:
            logger.error(f"Workflow engine failed: {e}")
            # Fallback to legacy mode
            return await self._legacy_direct_analysis(
                asn, start_time, end_time, user_input, t0, event_start
            )

    def _process_workflow_result(
        self,
        context: WorkflowContext,
        asn: str,
        start_time: str,
        end_time: str,
        t0: float,
        event_start: datetime
    ) -> dict:
        """Process workflow result into standard format."""
        elapsed = (datetime.now() - event_start).total_seconds()
        
        # Build result from context
        result = {
            "success": context.current_state == WorkflowState.COMPLETE,
            "chief_expert_analysis": {
                "coordination_summary": "Workflow Engine (Smart Cascade) execution completed",
                "analysis_method": "Graph-based Workflow v3.0 - Smart Cascade",
                "analysis_mode": context.analysis_mode.value if hasattr(context.analysis_mode, 'value') else str(context.analysis_mode),
                "target_as": asn,
                "time_range": f"{start_time} to {end_time}",
                "data_quality": context.data_quality,
                "confidence_score": context.confidence_score,
                "anomalies_detected": context.anomalies_detected,
                "execution_time_seconds": elapsed,
                "coordination_time_seconds": perf_counter() - t0,
                "analysis_timestamp": datetime.now().isoformat(),
                "llm_model": self.model,
                "coordination_strategy": "Smart Cascade: Traffic first, routing on demand",
                "workflow_states": [t.from_state.name for t in context.transitions],
            },
            # Smart Cascade specific fields
            "smart_cascade": {
                "analysis_mode": context.analysis_mode.value if hasattr(context.analysis_mode, 'value') else str(context.analysis_mode),
                "traffic_screening_result": context.traffic_screening_result,
                "need_full_traffic_analysis": context.need_full_traffic_analysis,
                "need_routing_analysis": context.need_routing_analysis,
                "routing_analysis_mode": context.routing_analysis_mode,
                "traffic_ok_routing_anomaly": context.traffic_ok_routing_anomaly,
                "cross_validation_notes": context.cross_validation_notes,
            },
            "token_count": self._extract_token_count(context),
            "reasoning_result": context.reasoning_result or {},
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

    def _extract_token_count(self, context: WorkflowContext) -> int:
        """Extract total token count from context."""
        tokens = 0
        
        for result in [context.traffic_result, context.routing_result, context.reasoning_result]:
            if result and isinstance(result, dict):
                token_usage = result.get("token_usage", {})
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

    def _build_trace(self, context: WorkflowContext) -> list:
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

    # ==================== Legacy Direct Mode ====================

    async def _legacy_direct_analysis(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        user_input: Optional[str],
        t0: float,
        event_start: datetime
    ) -> dict:
        """
        Legacy direct analysis mode (original implementation).
        
        Kept for backward compatibility and as fallback.
        """
        logger.info(f"Using Legacy Direct Mode for AS{asn} analysis")

        traffic_result = run_traffic_agent(
            user_input=user_input,
            asn=asn,
            start_time=start_time,
            end_time=end_time,
        )

        routing_result = await run_routing_agent_async(asn, start_time, end_time, use_llm=False)

        traffic_anomaly_count = traffic_result.get('anomaly_count', 0)
        routing_anomaly_count = routing_result.get('total_prefix_hijacks', 0)

        if traffic_anomaly_count + routing_anomaly_count == 0:
            return self._build_no_anomaly_result(
                asn, start_time, end_time, traffic_result, routing_result, t0, event_start
            )

        # Detect anomaly time range
        detected_start, detected_end = self._extract_anomaly_times(
            traffic_result, start_time, end_time
        )

        # Full routing analysis with LLM
        routing_result = await run_routing_agent_async(
            asn, detected_start, detected_end, use_llm=True
        )

        # Reasoning analysis
        reasoning_result = run_reasoning_agent(
            asn=asn,
            start_time=detected_start,
            end_time=detected_end,
            user_input=user_input,
            pre_computed_routing=routing_result,
            pre_computed_traffic=traffic_result,
        )

        if not reasoning_result.get("success", False):
            error_msg = reasoning_result.get("error", "Unknown error")
            raise RuntimeError(f"Reasoning agent failed: {error_msg}")

        self.reasoning_analysis_result = reasoning_result
        self.asrel_file = reasoning_result.get("as_rel_file")
        self.prefix2as_file = reasoning_result.get("prefix2as_file")
        self.asorg_file = reasoning_result.get("asorg_file")

        # Enrich data
        org_info = {}
        if self.asorg_file:
            org_info = lookup_org_info(str(asn), self.asorg_file)

        relationships = query_as_relationships(str(asn), self.asrel_file) if self.asrel_file else {}
        prefixes = query_as_prefixes(str(asn), self.prefix2as_file) if self.prefix2as_file else {}

        await self.setup_llm()

        # Generate report
        report_result = await self._generate_report(
            routing_result, traffic_result, reasoning_result, 
            asn, start_time, detected_end, org_info
        )

        elapsed = (datetime.now() - event_start).total_seconds()

        return {
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

    def _build_no_anomaly_result(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        traffic_result: dict,
        routing_result: dict,
        t0: float,
        event_start: datetime
    ) -> dict:
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
            llm=None,
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
        traffic_result: dict,
        start_time: str,
        end_time: str
    ) -> tuple:
        """Extract anomaly time range from traffic result."""
        detected_start = None
        detected_end = None

        consecutive_windows = traffic_result.get('consecutive_anomaly_windows', [])
        if consecutive_windows:
            first_window = consecutive_windows[0]
            detected_start = first_window.get('start')
            detected_end = first_window.get('end')
        elif traffic_result.get('expanded_boundaries'):
            eb = traffic_result['expanded_boundaries']
            detected_start = eb.get('expanded_start')
            detected_end = eb.get('expanded_end')
        elif traffic_result.get('outage_period_anomalies'):
            try:
                times = [a['timestamp'] for a in traffic_result['outage_period_anomalies'] if a.get('timestamp')]
                if times:
                    detected_start = min(times)
                    detected_end = max(times)
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

    def _extract_tokens(self, reasoning_result: dict) -> int:
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
        routing_result: dict,
        traffic_result: dict,
        reasoning_result: dict,
        asn: str,
        start_time: str,
        end_time: str,
        org_info: dict
    ) -> dict:
        """Generate final analysis report."""
        evidence = reasoning_result.get("evidence_summary", {})
        traffic_data = evidence.get("traffic_data", {})
        routing_data = reasoning_result.get("routing_analysis_override", {})

        return await generate_llm_report(
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
        )

    # ==================== Legacy Compatibility ====================

    async def react_agent_flow(self, asn, start_time, end_time, user_input=None):
        """Legacy ReAct flow - now falls back to workflow engine."""
        logger.warning("ReAct mode is deprecated, using workflow engine instead")
        return await self._workflow_analysis_flow(
            asn, start_time, end_time, user_input, 
            perf_counter(), datetime.now()
        )

    def create_agent_tools(self):
        """Create tools for legacy ReAct mode."""
        from llama_index.core.tools import FunctionTool
        return [
            FunctionTool.from_defaults(
                fn=self.wrapped_reasoning_agent,
                name="invoke_reasoning_expert",
                description="Invoke multi-round reasoning expert for BGP analysis. CALL ONCE ONLY."
            ),
            FunctionTool.from_defaults(
                fn=self.wrapped_analysis_agent,
                name="invoke_analysis_expert",
                description="Invoke comprehensive analysis expert for final report."
            ),
            FunctionTool.from_defaults(
                fn=self.query_as_organization,
                name="query_as_organization",
                description="Query organization info for ASN using asorg data."
            ),
            FunctionTool.from_defaults(
                fn=self.query_as_relationships,
                name="query_as_relationships",
                description="Query provider/peer/customer relationships using asrel data."
            ),
            FunctionTool.from_defaults(
                fn=self.query_as_prefixes,
                name="query_as_prefixes",
                description="Query legal prefixes owned by ASN using prefix2as data."
            ),
        ]


# ==================== Entry Points ====================

async def analyze_traffic_outage_async(
    user_input: Optional[str] = None,
    asn: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    use_workflow: bool = True,
    analysis_mode: str = "traffic_first",
    enable_mitm: bool = True
) -> dict:
    """
    Async entry point for traffic outage analysis.
    
    Args:
        user_input: Natural language description
        asn: AS number
        start_time: Start time (YYYY-MM-DD HH:MM)
        end_time: End time (YYYY-MM-DD HH:MM)
        use_workflow: Use workflow engine (default True)
        analysis_mode: Analysis mode
            - "fast": Only quick traffic screening, no routing analysis
            - "traffic_first": Traffic first, routing on demand (RECOMMENDED, default)
            - "full": Full parallel analysis (legacy mode)
            - "routing_focus": Routing first, traffic supplementary
        enable_mitm: Whether to enable MITM (中间人劫持) detection (default: True)
                     When False, skips forge hijack detection and ES usage
        
    Returns:
        Analysis result dictionary
    """
    output_dir = PROJECT_ROOT / "results"
    output_dir.mkdir(exist_ok=True, parents=True)

    # Determine output file name
    if asn and start_time:
        analysis_file = output_dir / "json" / f"traffic_outage_analysis_{asn}_{start_time.replace(' ', '_')}.json"
    else:
        analysis_file = output_dir / "json" / f"traffic_outage_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    analysis_file.parent.mkdir(exist_ok=True, parents=True)

    chief_expert = ChiefExpertAgent(
        MODEL, API_KEY, BASE_URL,
        use_workflow_engine=use_workflow,
        analysis_mode=analysis_mode,
        enable_mitm=enable_mitm
    )
    result = await chief_expert.coordinate_analysis(user_input, asn, start_time, end_time)

    result = make_json_safe(result)

    with open(analysis_file, "w", encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return result


def analyze_traffic_outage(
    user_input: Optional[str] = None,
    asn: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    use_workflow: bool = True,
    analysis_mode: str = "traffic_first",
    enable_mitm: bool = True
) -> dict:
    """
    Sync entry point for traffic outage analysis.
    
    Wraps analyze_traffic_outage_async with asyncio.run().
    """
    return asyncio.run(analyze_traffic_outage_async(
        user_input, asn, start_time, end_time, use_workflow, analysis_mode, enable_mitm
    ))


def print_architecture_diagram():
    """Print the workflow architecture diagram."""
    print(get_workflow_architecture_diagram())


# ==================== CLI ====================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Traffic Outage Analysis - Chief Expert Agent v3.0 (Smart Cascade)")
    parser.add_argument("--user-input", help="Natural language input describing the traffic outage")
    parser.add_argument("--asn", help="AS number")
    parser.add_argument("--start", help="Start time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--end", help="End time (YYYY-MM-DD HH:MM)")
    parser.add_argument("--legacy", action="store_true", help="Use legacy direct mode instead of workflow engine")
    parser.add_argument("--mode", "--analysis-mode", dest="analysis_mode", 
                       default="traffic_first",
                       choices=["fast", "traffic_first", "full", "routing_focus"],
                       help="Analysis mode: fast (quick screening only), traffic_first (recommended), full (parallel), routing_focus")
    parser.add_argument("--mitm", action="store_true", default=True,
                       help="Enable MITM (中间人劫持) detection (default: enabled, requires ES)")
    parser.add_argument("--no-mitm", dest="mitm", action="store_false",
                       help="Disable MITM (中间人劫持) detection (skips forge hijack detection and ES usage)")
    parser.add_argument("--print-architecture", action="store_true", help="Print architecture diagram")
    parser.add_argument("--show-metrics", action="store_true", help="Show workflow metrics")

    args = parser.parse_args()

    if args.print_architecture:
        print_architecture_diagram()
        exit(0)

    if args.show_metrics:
        engine = WorkflowEngine()
        metrics = engine.get_metrics()
        print("Workflow Engine Metrics:")
        print(json.dumps(metrics, indent=2))
        exit(0)

    print(f"Traffic Outage Analysis | LLM: {MODEL}")
    print(f"Execution Mode: {'Legacy Direct' if args.legacy else 'Workflow Engine'}")
    print(f"Analysis Mode: {args.analysis_mode}")
    print(f"MITM Detection: {'enabled' if args.mitm else 'disabled'}")
    print("=" * 60)

    result = analyze_traffic_outage(
        args.user_input,
        args.asn,
        args.start,
        args.end,
        use_workflow=not args.legacy,
        analysis_mode=args.analysis_mode,
        enable_mitm=args.mitm
    )

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
        # Print Smart Cascade info if available
        if 'smart_cascade' in result:
            sc = result['smart_cascade']
            print(f"Smart Cascade Info:")
            print(f"  - Analysis mode: {sc.get('analysis_mode')}")
            screening_result = sc.get('traffic_screening_result') or {}
            print(f"  - Traffic screening score: {screening_result.get('quick_score', 'N/A')}")
            print(f"  - Need full traffic analysis: {sc.get('need_full_traffic_analysis')}")
            print(f"  - Routing analysis mode: {sc.get('routing_analysis_mode')}")
            if sc.get('cross_validation_notes'):
                for note in sc['cross_validation_notes']:
                    print(f"  - {note.get('message', 'Note')}")
        if result.get("analysis_report", {}).get("html_report_path"):
            print(f"Report: {result['analysis_report']['html_report_path']}")
    elif result.get('success') is False:
        print(f"Failed: {result.get('error', 'Unknown error')}")
    else:
        print(f"Unexpected result. Keys: {list(result.keys())[:5]}")
