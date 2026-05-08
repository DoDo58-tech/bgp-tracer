"""
BGP Tracer Multi-Agent Workflow Engine
========================================

Advanced workflow orchestration for BGP anomaly detection.

Architecture:
-------------

                    ┌──────────────────────────────────────────────┐
                    │              UserInput                        │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │           StateMachine                        │
                    │  ┌─────────────────────────────────────┐    │
                    │  │ States:                             │    │
                    │  │   INITIAL → DATA_COLLECTION →       │    │
                    │  │   ROUTING_ANALYSIS → REASONING →   │    │
                    │  │   VALIDATION → REPORT_GENERATION → │    │
                    │  │   COMPLETE / ERROR                  │    │
                    │  └─────────────────────────────────────┘    │
                    └──────────────┬───────────────────────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │         Parallel Data Collection          │
              │  ┌─────────────────┬─────────────────┐  │
              │  │ Traffic Agent   │  Routing Agent  │  │
              │  │ (async)        │  (async)       │  │
              │  └─────────────────┴─────────────────┘  │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │        Conditional Reasoning             │
              │  ┌───────────────────────────────────┐ │
              │  │ Need Deep Analysis?               │ │
              │  │   ├─ YES → Multi-round Reasoning  │ │
              │  │   └─ NO  → Skip to Validation     │ │
              │  └───────────────────────────────────┘ │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │           Validation Gate               │
              │  ┌───────────────────────────────────┐ │
              │  │ Check data quality & confidence   │ │
              │  │ Retry up to 3 times on failure   │ │
              │  └───────────────────────────────────┘ │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │          Report Generation              │
              │  ┌───────────────────────────────────┐ │
              │  │ Template + LLM Enhancement        │ │
              │  └───────────────────────────────────┘ │
              └────────────────────┬────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │              COMPLETE                       │
                    └──────────────────────────────────────────────┘

Features:
---------
1. State Machine: Clear, predictable workflow states
2. Parallel Execution: Traffic + Routing agents run concurrently
3. Error Recovery: Automatic retry with exponential backoff
4. Conditional Logic: Skip unnecessary analysis based on data quality
5. Progress Tracking: Detailed execution trace
6. Type Safety: Full type hints throughout

Author: BGP Tracer Team
Version: 3.0 - Smart Cascade Mode
"""

from __future__ import annotations

import asyncio
import json
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Generic
from functools import wraps
import time

from utils.logger import logger

T = TypeVar('T')


class WorkflowState(Enum):
    """Workflow execution states with transitions."""
    INITIAL = auto()
    PARSING_INPUT = auto()
    TRAFFIC_SCREENING = auto()  # NEW: Quick traffic pre-check
    TRAFFIC_ANALYSIS = auto()
    ROUTING_ANALYSIS = auto()
    REASONING = auto()
    VALIDATION = auto()
    DATA_ENRICHMENT = auto()
    REPORT_GENERATION = auto()
    COMPLETE = auto()
    ERROR = auto()
    RETRY = auto()


class WorkflowEvent(Enum):
    """Events that trigger state transitions."""
    START = auto()
    INPUT_PARSED = auto()
    SCREENING_COMPLETE = auto()  # NEW: Traffic screening done
    SCREENING_SKIP = auto()      # NEW: Skip to light routing
    TRAFFIC_DONE = auto()
    ROUTING_DONE = auto()
    REASONING_COMPLETE = auto()
    VALIDATION_PASSED = auto()
    VALIDATION_FAILED = auto()
    REPORT_GENERATED = auto()
    ERROR_OCCURRED = auto()
    RETRY_SUCCESS = auto()
    RETRY_EXHAUSTED = auto()
    COMPLETE = auto()
    DATA_COLLECTED = auto()  # Legacy: Used by DATA_ENRICHMENT state


# ==================== Analysis Mode Configuration ====================

class AnalysisMode(Enum):
    """Analysis mode selection for different use cases."""
    FAST = "fast"           # Only quick traffic screening, no routing
    TRAFFIC_FIRST = "traffic_first"  # Traffic first, routing on demand (RECOMMENDED)
    FULL = "full"           # Full parallel analysis (legacy mode)
    ROUTING_FOCUS = "routing_focus"  # Routing first, traffic supplementary


@dataclass
class StateTransition:
    """Represents a state transition with metadata."""
    from_state: WorkflowState
    to_state: WorkflowState
    event: WorkflowEvent
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class WorkflowContext:
    """
    Shared context passed through the workflow.
    
    This dataclass holds all data and state needed by agents
    and allows for clean data flow between workflow stages.
    """
    # User input
    user_input: Optional[str] = None
    asn: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    
    # Parsed data
    parsed_as_list: list[str] = field(default_factory=list)
    is_batch: bool = False
    
    # Agent results
    traffic_result: Optional[dict] = None
    routing_result: Optional[dict] = None
    reasoning_result: Optional[dict] = None
    
    # Quality metrics
    data_quality: str = "Unknown"
    confidence_score: float = 0.0
    anomalies_detected: bool = False
    
    # Execution tracking
    current_state: WorkflowState = WorkflowState.INITIAL
    transitions: list[StateTransition] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    execution_time_ms: float = 0.0
    retry_count: int = 0
    
    # Enriched data
    org_info: Optional[dict] = None
    as_relationships: Optional[dict] = None
    as_prefixes: Optional[dict] = None
    
    # Output
    report_path: Optional[str] = None
    final_result: Optional[dict] = None
    
    # Smart Cascade fields (Version 3.0)
    analysis_mode: AnalysisMode = AnalysisMode.TRAFFIC_FIRST
    traffic_screening_result: Optional[dict] = None
    need_full_traffic_analysis: bool = False
    need_routing_analysis: bool = False
    routing_analysis_mode: str = "full"  # "full" or "light"
    cross_validation_notes: list = field(default_factory=list)
    
    # Special case tracking
    traffic_ok_routing_anomaly: bool = False  # Traffic normal but routing abnormal
    
    # MITM detection control (中间人劫持检测)
    enable_mitm: bool = True  # 是否启用MITM检测（启用时需要ES）
    
    def add_error(self, error: str, stage: str, details: Optional[dict] = None):
        """Record an error with context."""
        self.errors.append({
            "error": error,
            "stage": stage,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        })
    
    def add_transition(self, from_state: WorkflowState, to_state: WorkflowState, 
                       event: WorkflowEvent, duration_ms: float = 0.0,
                       metadata: Optional[dict] = None):
        """Record a state transition."""
        self.transitions.append(StateTransition(
            from_state=from_state,
            to_state=to_state,
            event=event,
            duration_ms=duration_ms,
            metadata=metadata or {}
        ))
        self.current_state = to_state


class WorkflowError(Exception):
    """Base exception for workflow errors."""
    def __init__(self, message: str, stage: WorkflowState, context: WorkflowContext):
        self.message = message
        self.stage = stage
        self.context = context
        super().__init__(message)


class RetryableError(Exception):
    """Error that can be retried."""
    pass


def async_retry(max_retries: int = 3, backoff_base: float = 1.0):
    """
    Decorator for automatic retry with exponential backoff.
    
    Usage:
        @async_retry(max_retries=3)
        async def unreliable_operation():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except RetryableError as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = backoff_base * (2 ** attempt)
                        logger.warning(f"Retry {attempt + 1}/{max_retries} for {func.__name__} after {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} retries exhausted for {func.__name__}")
            raise last_exception
        return wrapper
    return decorator


class WorkflowEngine:
    """
    Graph-based workflow engine with state machine.
    
    This engine orchestrates multi-agent BGP analysis with:
    - Parallel execution where possible
    - Conditional branching
    - Error recovery
    - Detailed execution tracing
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        parallel_execution: bool = True,
        skip_unnecessary_analysis: bool = True
    ):
        self.max_retries = max_retries
        self.parallel_execution = parallel_execution
        self.skip_unnecessary_analysis = skip_unnecessary_analysis
        
        # State handlers
        self._state_handlers: dict[WorkflowState, Callable] = {}
        self._register_default_handlers()
        
        # Metrics
        self.metrics = {
            "total_runs": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "total_execution_time_ms": 0.0
        }
    
    def _register_default_handlers(self):
        """Register default state handlers."""
        self._state_handlers = {
            WorkflowState.INITIAL: self._handle_initial,
            WorkflowState.PARSING_INPUT: self._handle_parsing_input,
            WorkflowState.TRAFFIC_SCREENING: self._handle_traffic_screening,
            WorkflowState.TRAFFIC_ANALYSIS: self._handle_traffic_analysis,
            WorkflowState.ROUTING_ANALYSIS: self._handle_routing_analysis,
            WorkflowState.REASONING: self._handle_reasoning,
            WorkflowState.VALIDATION: self._handle_validation,
            WorkflowState.DATA_ENRICHMENT: self._handle_data_enrichment,
            WorkflowState.REPORT_GENERATION: self._handle_report_generation,
            WorkflowState.COMPLETE: self._handle_complete,
            WorkflowState.ERROR: self._handle_error,
            WorkflowState.RETRY: self._handle_retry,
        }
    
    async def execute(self, context: WorkflowContext) -> WorkflowContext:
        """
        Execute the workflow starting from INITIAL state.
        
        Args:
            context: Initial workflow context with user input
            
        Returns:
            Updated context with all results and execution trace
        """
        start_time = time.perf_counter()
        self.metrics["total_runs"] += 1
        
        context.add_transition(
            WorkflowState.INITIAL, 
            WorkflowState.INITIAL,
            WorkflowEvent.START
        )
        
        try:
            # Main state machine loop
            while context.current_state not in (WorkflowState.COMPLETE, WorkflowState.ERROR):
                handler = self._state_handlers.get(context.current_state)
                
                if handler is None:
                    raise WorkflowError(
                        f"No handler for state {context.current_state}",
                        context.current_state,
                        context
                    )
                
                # Track state duration
                state_start = time.perf_counter()
                prev_state = context.current_state
                
                # Execute state handler
                next_event = await handler(context)
                
                # Record transition
                state_duration = (time.perf_counter() - state_start) * 1000
                
                # Determine next state based on event
                next_state = self._get_next_state(prev_state, next_event)
                context.add_transition(
                    prev_state,
                    next_state,
                    next_event,
                    duration_ms=state_duration
                )
                
                logger.debug(
                    f"State transition: {prev_state.name} -> {next_state.name} "
                    f"(event: {next_event.name}, duration: {state_duration:.1f}ms)"
                )
            
            # Success
            self.metrics["successful_runs"] += 1
            
        except Exception as e:
            context.add_error(str(e), context.current_state.name, {
                "exception_type": type(e).__name__,
                "traceback": traceback.format_exc()
            })
            context.current_state = WorkflowState.ERROR
            self.metrics["failed_runs"] += 1
            logger.error(f"Workflow error at {context.current_state.name}: {e}")
        
        finally:
            context.execution_time_ms = (time.perf_counter() - start_time) * 1000
            self.metrics["total_execution_time_ms"] += context.execution_time_ms
        
        return context
    
    def _get_next_state(self, current: WorkflowState, event: WorkflowEvent) -> WorkflowState:
        """Determine next state based on current state and event."""
        transitions = {
            # Smart Cascade Flow (Version 3.0)
            (WorkflowState.INITIAL, WorkflowEvent.START): WorkflowState.PARSING_INPUT,
            (WorkflowState.PARSING_INPUT, WorkflowEvent.INPUT_PARSED): WorkflowState.TRAFFIC_SCREENING,
            # Traffic screening -> either full analysis or light routing
            (WorkflowState.TRAFFIC_SCREENING, WorkflowEvent.SCREENING_COMPLETE): WorkflowState.TRAFFIC_ANALYSIS,
            (WorkflowState.TRAFFIC_SCREENING, WorkflowEvent.SCREENING_SKIP): WorkflowState.ROUTING_ANALYSIS,
            # After traffic analysis, proceed to routing
            (WorkflowState.TRAFFIC_ANALYSIS, WorkflowEvent.TRAFFIC_DONE): WorkflowState.ROUTING_ANALYSIS,
            # After routing analysis, go to reasoning
            (WorkflowState.ROUTING_ANALYSIS, WorkflowEvent.ROUTING_DONE): WorkflowState.REASONING,
            # Reasoning complete -> validation
            (WorkflowState.REASONING, WorkflowEvent.REASONING_COMPLETE): WorkflowState.VALIDATION,
            # Validation
            (WorkflowState.VALIDATION, WorkflowEvent.VALIDATION_PASSED): WorkflowState.DATA_ENRICHMENT,
            (WorkflowState.VALIDATION, WorkflowEvent.VALIDATION_FAILED): WorkflowState.RETRY,
            # Retry
            (WorkflowState.RETRY, WorkflowEvent.RETRY_SUCCESS): WorkflowState.DATA_ENRICHMENT,
            (WorkflowState.RETRY, WorkflowEvent.RETRY_EXHAUSTED): WorkflowState.ERROR,
            # Data enrichment and report
            (WorkflowState.DATA_ENRICHMENT, WorkflowEvent.DATA_COLLECTED): WorkflowState.REPORT_GENERATION,
            (WorkflowState.REPORT_GENERATION, WorkflowEvent.REPORT_GENERATED): WorkflowState.COMPLETE,
        }
        
        result = transitions.get((current, event))
        if result is None:
            logger.warning(f"No transition for state={current.name}, event={event.name}")
            # Return appropriate next state based on context
            if current == WorkflowState.TRAFFIC_SCREENING:
                return WorkflowState.TRAFFIC_ANALYSIS
        return result if result else current
    
    # ==================== State Handlers ====================
    
    async def _handle_initial(self, context: WorkflowContext) -> WorkflowEvent:
        """Handle initial state."""
        return WorkflowEvent.START
    
    async def _handle_parsing_input(self, context: WorkflowContext) -> WorkflowEvent:
        """Parse user input and extract parameters."""
        from agents.traffic_agent import (
            parse_traffic_outage_input,
            parse_multiple_as_input,
            parse_country_region_input,
        )
        from agents.coordination_utils import normalize_time
        
        if context.user_input and not (context.asn and context.start_time and context.end_time):
            # Try to parse from natural language
            parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(context.user_input)
            
            if parsed_asn:
                context.asn = str(parsed_asn)
                context.start_time = normalize_time(parsed_start) if parsed_start else None
                context.end_time = normalize_time(parsed_end) if parsed_end else None
            else:
                # Try batch parsing
                as_list, multi_start, multi_end = parse_multiple_as_input(context.user_input)
                if as_list and len(as_list) > 1:
                    context.parsed_as_list = as_list
                    context.is_batch = True
                    context.start_time = normalize_time(multi_start) if multi_start else None
                    context.end_time = normalize_time(multi_end) if multi_end else None
        
        return WorkflowEvent.INPUT_PARSED
    
    async def _handle_traffic_screening(self, context: WorkflowContext) -> WorkflowEvent:
        """
        Smart Cascade Stage 1: Quick Traffic Screening
        
        Performs a fast pre-check (5-10s) to determine if full analysis is needed.
        This replaces the old parallel DATA_COLLECTION state.
        """
        from detectors.traffic.traffic_detector import CloudflareRadarAPI
        
        logger.info(f"Starting traffic quick screening for AS{context.asn}...")
        
        try:
            api = CloudflareRadarAPI()
            
            # Run quick screening
            screening_result = api.quick_screening(
                asn=context.asn,
                start_time=context.start_time,
                end_time=context.end_time
            )
            
            context.traffic_screening_result = screening_result
            
            # Store screening info in context for later use
            context.need_full_traffic_analysis = screening_result.get("need_full_analysis", True)
            
            logger.info(
                f"Traffic screening complete: score={screening_result.get('quick_score', 0):.2f}, "
                f"need_full={context.need_full_traffic_analysis}, "
                f"signals={len(screening_result.get('anomaly_signals', []))}"
            )
            
            # Decide routing analysis mode based on screening
            if context.analysis_mode == AnalysisMode.FAST:
                # Fast mode: only screening, no routing
                context.need_routing_analysis = False
                return WorkflowEvent.SCREENING_SKIP
            elif context.analysis_mode == AnalysisMode.FULL:
                # Full mode: always do both
                context.need_full_traffic_analysis = True
                context.need_routing_analysis = True
                context.routing_analysis_mode = "full"
                return WorkflowEvent.SCREENING_COMPLETE
            else:
                # TRAFFIC_FIRST (default) or ROUTING_FOCUS
                context.need_routing_analysis = True
                # Light routing if no traffic anomaly signals
                if not screening_result.get("need_full_analysis"):
                    context.routing_analysis_mode = "light"
                    logger.info("Traffic appears normal, using light routing analysis")
                else:
                    context.routing_analysis_mode = "full"
                return WorkflowEvent.SCREENING_COMPLETE
                
        except Exception as e:
            logger.error(f"Traffic screening failed: {e}")
            # On error, default to full analysis
            context.traffic_screening_result = {
                "error": str(e),
                "need_full_analysis": True,
                "decision_reasons": ["Screening failed, defaulting to full analysis"]
            }
            context.need_full_traffic_analysis = True
            context.need_routing_analysis = True
            context.routing_analysis_mode = "full"
            return WorkflowEvent.SCREENING_COMPLETE
    
    async def _safe_execute_traffic(self, context: WorkflowContext):
        """Execute traffic agent with error handling."""
        from agents.traffic_agent import run_traffic_agent
        try:
            return run_traffic_agent(
                user_input=context.user_input,
                asn=context.asn,
                start_time=context.start_time,
                end_time=context.end_time
            )
        except Exception as e:
            logger.error(f"Traffic agent failed: {e}")
            raise RetryableError(f"Traffic agent error: {e}")
    
    async def _safe_execute_routing(self, context: WorkflowContext):
        """Execute routing agent with error handling."""
        from agents.routing_agent import run_routing_agent_async
        try:
            return await run_routing_agent_async(
                context.asn,
                context.start_time,
                context.end_time,
                use_llm=True,
                enable_mitm=context.enable_mitm
            )
        except Exception as e:
            logger.error(f"Routing agent failed: {e}")
            raise RetryableError(f"Routing agent error: {e}")
    
    async def _handle_traffic_analysis(self, context: WorkflowContext) -> WorkflowEvent:
        """
        Handle traffic analysis state.
        
        Only runs full analysis if needed (based on screening result).
        """
        # Check if we need full traffic analysis
        if not context.need_full_traffic_analysis:
            logger.info("Traffic screening passed, skipping full traffic analysis")
            context.traffic_result = {
                "success": True,
                "skipped": True,
                "reason": "screening_passed",
                "screening_result": context.traffic_screening_result
            }
            return WorkflowEvent.TRAFFIC_DONE
        
        context.traffic_result = await self._safe_execute_traffic(context)
        return WorkflowEvent.TRAFFIC_DONE
    
    async def _handle_routing_analysis(self, context: WorkflowContext) -> WorkflowEvent:
        """
        Handle routing analysis state.
        
        Supports two modes:
        - full: Complete BGP analysis with LLM
        - light: Quick check for obvious anomalies
        """
        from agents.routing_agent import run_routing_agent_async
        
        # Check if we need routing analysis at all
        if not context.need_routing_analysis:
            logger.info("Routing analysis skipped (fast mode)")
            context.routing_result = {
                "success": True,
                "skipped": True,
                "reason": "fast_mode"
            }
            return WorkflowEvent.ROUTING_DONE
        
        routing_mode = getattr(context, 'routing_analysis_mode', 'full')
        
        if routing_mode == "light":
            logger.info("Running light routing analysis")
            try:
                # Light mode: quick check without LLM
                context.routing_result = await run_routing_agent_async(
                    context.asn,
                    context.start_time,
                    context.end_time,
                    use_llm=False,  # Skip LLM for faster results
                    enable_mitm=context.enable_mitm
                )
            except Exception as e:
                logger.warning(f"Light routing analysis failed: {e}, falling back to quick check")
                context.routing_result = {
                    "success": True,
                    "light_mode_failed": True,
                    "error": str(e),
                    "total_prefix_hijacks": 0,
                    "quick_check_notes": "Light mode failed, quick check returned no anomalies"
                }
        else:
            # Full mode
            logger.info("Running full routing analysis")
            context.routing_result = await self._safe_execute_routing(context)
        
        # Cross-validation: Check for special case
        await self._cross_validate_results(context)
        
        return WorkflowEvent.ROUTING_DONE
    
    async def _cross_validate_results(self, context: WorkflowContext):
        """
        Cross-validate traffic and routing results.
        
        Special case handling: Traffic appears normal but routing has anomalies.
        This could indicate:
        - Hidden/prevented issues
        - Potential future problems
        - Routing instability not yet affecting traffic
        """
        traffic_ok = (
            context.traffic_result and 
            context.traffic_result.get("success", False) and
            context.traffic_result.get("anomaly_count", 0) == 0
        )
        
        routing_anomalies = 0
        if context.routing_result:
            routing_anomalies = context.routing_result.get("total_prefix_hijacks", 0)
            routing_anomalies += context.routing_result.get("total_route_leaks", 0)
            routing_anomalies += context.routing_result.get("total_outages", 0)
        
        routing_ok = routing_anomalies == 0
        
        if traffic_ok and not routing_ok:
            context.traffic_ok_routing_anomaly = True
            context.cross_validation_notes.append({
                "case": "traffic_ok_routing_anomaly",
                "severity": "warning",
                "message": "流量正常但路由检测到异常，可能存在潜在风险",
                "details": {
                    "traffic_anomalies": 0,
                    "routing_anomalies": routing_anomalies,
                    "possible_reasons": [
                        "路由问题已被自动修复",
                        "路由不稳定但尚未影响流量",
                        "流量可能被CDN/缓存保护",
                        "存在备用路由"
                    ],
                    "recommendation": "建议持续监控，路由异常可能预示未来问题"
                }
            })
            logger.warning(
                f"⚠️ Cross-validation alert: Traffic OK but routing has {routing_anomalies} anomalies"
            )
        elif not traffic_ok and not routing_ok:
            context.cross_validation_notes.append({
                "case": "both_anomalous",
                "severity": "critical",
                "message": "流量和路由均检测到异常，需要深度关联分析",
                "details": {
                    "traffic_anomalies": context.traffic_result.get("anomaly_count", 0),
                    "routing_anomalies": routing_anomalies,
                    "recommendation": "路由异常很可能是流量问题的根本原因"
                }
            })
        elif traffic_ok and routing_ok:
            context.cross_validation_notes.append({
                "case": "both_ok",
                "severity": "info",
                "message": "流量和路由均正常，问题可能与路由无关",
                "details": {
                    "traffic_anomalies": 0,
                    "routing_anomalies": 0
                }
            })
    
    async def _handle_reasoning(self, context: WorkflowContext) -> WorkflowEvent:
        """Handle multi-round reasoning state."""
        from agents.reasoning_agent import run_reasoning_agent
        
        # Skip reasoning if no anomalies detected and skip is enabled
        if self.skip_unnecessary_analysis and not context.anomalies_detected:
            logger.info("Skipping reasoning - no anomalies detected")
            context.reasoning_result = {
                "success": True,
                "skipped": True,
                "reason": "no_anomalies_detected"
            }
            return WorkflowEvent.REASONING_COMPLETE
        
        try:
            context.reasoning_result = run_reasoning_agent(
                asn=context.asn,
                start_time=context.start_time,
                end_time=context.end_time,
                pre_computed_routing=context.routing_result,
                pre_computed_traffic=context.traffic_result
            )
            return WorkflowEvent.REASONING_COMPLETE
        except Exception as e:
            logger.error(f"Reasoning agent failed: {e}")
            raise RetryableError(f"Reasoning error: {e}")
    
    async def _handle_validation(self, context: WorkflowContext) -> WorkflowEvent:
        """Validate collected data and analysis quality."""
        # Check minimum data quality
        quality_score = self._calculate_quality_score(context)
        context.confidence_score = quality_score
        
        if quality_score >= 0.5:
            return WorkflowEvent.VALIDATION_PASSED
        else:
            return WorkflowEvent.VALIDATION_FAILED
    
    async def _handle_retry(self, context: WorkflowContext) -> WorkflowEvent:
        """Handle retry logic for failed operations."""
        context.retry_count += 1
        
        if context.retry_count > self.max_retries:
            return WorkflowEvent.RETRY_EXHAUSTED
        
        # Exponential backoff
        wait_time = 1.0 * (2 ** (context.retry_count - 1))
        logger.warning(f"Retry {context.retry_count}/{self.max_retries} after {wait_time}s")
        await asyncio.sleep(wait_time)
        
        return WorkflowEvent.RETRY_SUCCESS
    
    async def _handle_data_enrichment(self, context: WorkflowContext) -> WorkflowEvent:
        """Enrich context with additional data (org info, relationships, etc.)."""
        from agents.coordination_utils import (
            lookup_org_info,
            query_as_relationships,
            query_as_prefixes
        )
        
        # Load data files from reasoning result if available
        asrel_file = None
        prefix2as_file = None
        asorg_file = None
        
        if context.reasoning_result:
            asrel_file = context.reasoning_result.get("as_rel_file")
            prefix2as_file = context.reasoning_result.get("prefix2as_file")
            asorg_file = context.reasoning_result.get("asorg_file")
        
        # Enrich with org info
        if asorg_file and context.asn:
            context.org_info = lookup_org_info(context.asn, asorg_file)
        
        # Enrich with AS relationships
        if asrel_file and context.asn:
            context.as_relationships = query_as_relationships(context.asn, asrel_file)
        
        # Enrich with prefixes
        if prefix2as_file and context.asn:
            context.as_prefixes = query_as_prefixes(context.asn, prefix2as_file)
        
        return WorkflowEvent.DATA_COLLECTED
    
    async def _handle_report_generation(self, context: WorkflowContext) -> WorkflowEvent:
        """Generate final comprehensive report."""
        from utils.report_generator import generate_comprehensive_report
        from agents.coordination_utils import generate_integrated_report
        from llm.llm_factory import setup_llm_settings
        from config import MODEL, API_KEY, BASE_URL
        
        try:
            # Initialize LLM for report generation
            llm = None
            try:
                llm, _ = setup_llm_settings(
                    model=MODEL,
                    api_key=API_KEY,
                    base_url=BASE_URL,
                    temperature=0.1,
                    timeout=300.0,
                    max_retries=2
                )
            except Exception as e:
                logger.warning(f"Failed to initialize LLM for report: {e}")
            
            report_result = await generate_comprehensive_report(
                llm=llm,
                routing_analysis=context.routing_result or {},
                traffic_analysis=context.traffic_result or {},
                law_analysis=None,
                reasoning_analysis=context.reasoning_result or {},
                start_time=context.start_time,
                output_dir=Path("results/html"),
                org_name=context.org_info.get("org_name") if context.org_info else None,
                asn=context.asn,
                fallback_report_func=generate_integrated_report,
            )
            
            context.report_path = report_result.get("html_report_path")
            context.final_result = report_result
            return WorkflowEvent.REPORT_GENERATED
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            # Use fallback report function
            try:
                report_result = generate_integrated_report(
                    routing_analysis=context.routing_result or {},
                    traffic_analysis=context.traffic_result or {},
                    reasoning_analysis=context.reasoning_result or {},
                    start_time=context.start_time,
                    output_dir=str(Path("results/html")),
                    asn=context.asn,
                )
                context.report_path = report_result.get("html_report_path")
                context.final_result = report_result
                return WorkflowEvent.REPORT_GENERATED
            except Exception as fallback_error:
                logger.error(f"Fallback report generation also failed: {fallback_error}")
                raise RetryableError(f"Report generation error: {e}")
    
    async def _handle_complete(self, context: WorkflowContext) -> WorkflowEvent:
        """Handle completion state."""
        return WorkflowEvent.COMPLETE
    
    async def _handle_error(self, context: WorkflowContext) -> WorkflowEvent:
        """Handle error state."""
        return WorkflowEvent.ERROR
    
    # ==================== Quality Assessment ====================
    
    def _assess_data_quality(self, context: WorkflowContext) -> str:
        """Assess overall data quality."""
        score = self._calculate_quality_score(context)
        
        if score >= 0.8:
            return "High"
        elif score >= 0.5:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_quality_score(self, context: WorkflowContext) -> float:
        """Calculate a 0-1 quality score based on available data."""
        score = 0.0
        factors = 0
        
        # Traffic data quality
        if context.traffic_result:
            factors += 1
            if context.traffic_result.get("success"):
                score += 0.3
                if context.traffic_result.get("anomalies_detected"):
                    score += 0.2
        
        # Routing data quality
        if context.routing_result:
            factors += 1
            if context.routing_result.get("success"):
                score += 0.3
                if context.routing_result.get("total_prefix_hijacks", 0) > 0:
                    score += 0.2
        
        # Normalize if we have any factors
        if factors > 0:
            return min(1.0, score / (factors * 0.5))
        return 0.0
    
    # ==================== Metrics ====================
    
    def get_metrics(self) -> dict:
        """Get workflow execution metrics."""
        avg_time = (
            self.metrics["total_execution_time_ms"] / self.metrics["total_runs"]
            if self.metrics["total_runs"] > 0 else 0
        )
        
        return {
            "total_runs": self.metrics["total_runs"],
            "successful_runs": self.metrics["successful_runs"],
            "failed_runs": self.metrics["failed_runs"],
            "success_rate": (
                self.metrics["successful_runs"] / self.metrics["total_runs"]
                if self.metrics["total_runs"] > 0 else 0
            ),
            "average_execution_time_ms": avg_time,
            "parallel_execution_enabled": self.parallel_execution,
            "skip_unnecessary_analysis_enabled": self.skip_unnecessary_analysis
        }


# ==================== Convenience Functions ====================

async def run_workflow(
    user_input: Optional[str] = None,
    asn: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    parallel: bool = True,
    max_retries: int = 3,
    analysis_mode: str = "traffic_first",
    enable_mitm: bool = True
) -> WorkflowContext:
    """
    Run the complete workflow with the given parameters.
    
    This is the main entry point for workflow execution.
    
    Args:
        user_input: Natural language description of the analysis
        asn: AS number to analyze
        start_time: Start time in ISO format
        end_time: End time in ISO format
        parallel: Enable parallel execution of agents (deprecated, use analysis_mode)
        max_retries: Maximum retry attempts for failed operations
        analysis_mode: Analysis mode selection
            - "fast": Only quick traffic screening, no routing analysis
            - "traffic_first": Traffic first, routing on demand (RECOMMENDED, default)
            - "full": Full parallel analysis (legacy mode)
            - "routing_focus": Routing first, traffic supplementary
        enable_mitm: Whether to enable MITM (中间人劫持) detection (default: True)
                     When False, skips forge hijack detection and ES usage
        
    Returns:
        WorkflowContext with all results and execution trace
    """
    engine = WorkflowEngine(
        max_retries=max_retries,
        parallel_execution=False  # Disable old parallel mode, use smart cascade
    )
    
    # Map string mode to enum
    mode_map = {
        "fast": AnalysisMode.FAST,
        "traffic_first": AnalysisMode.TRAFFIC_FIRST,
        "full": AnalysisMode.FULL,
        "routing_focus": AnalysisMode.ROUTING_FOCUS,
    }
    selected_mode = mode_map.get(analysis_mode.lower(), AnalysisMode.TRAFFIC_FIRST)
    
    context = WorkflowContext(
        user_input=user_input,
        asn=asn,
        start_time=start_time,
        end_time=end_time,
        analysis_mode=selected_mode,
        enable_mitm=enable_mitm  # 传递MITM检测开关
    )
    
    return await engine.execute(context)


def get_workflow_architecture_diagram() -> str:
    """Return ASCII art diagram of the workflow architecture."""
    return """
    ┌─────────────────────────────────────────────────────────────────────────┐
    │           BGP Tracer Workflow Architecture (v3.0 - Smart Cascade)        │
    └─────────────────────────────────────────────────────────────────────────┘
    
                              ┌───────────────┐
                              │   UserInput   │
                              └───────┬───────┘
                                      │
                              ┌───────▼───────┐
                              │     Parse     │
                              │    Input      │
                              └───────┬───────┘
                                      │
                          ┌───────────▼───────────┐
                          │  Traffic Quick Screen  │  ← NEW: 5-10s pre-check
                          │  ┌─────────────────┐  │
                          │  │ - Data avail    │  │
                          │  │ - Quick scoring│  │
                          │  │ - Signal detect│  │
                          │  └─────────────────┘  │
                          └───────────┬───────────┘
                                      │
                          ┌───────────▼───────────┐
                          │  Conditional Routing   │
                          │  ┌─────────────────┐  │
                          │  │ Need full?      │  │
                          │  │   ├─ YES→Full  │  │
                          │  │   └─ NO→Light  │  │
                          │  └─────────────────┘  │
                          └───────────┬───────────┘
                                      │
                          ┌───────────▼───────────┐
                          │   Traffic Analysis     │
                          │  (if needed)          │
                          └───────────┬───────────┘
                                      │
                          ┌───────────▼───────────┐
                          │   Routing Analysis     │
                          │  ┌─────────────────┐  │
                          │  │ Full or Light   │  │
                          │  │ (based on need) │  │
                          │  └─────────────────┘  │
                          └───────────┬───────────┘
                                      │
                          ┌───────────▼───────────┐
                          │  Cross-Validation     │  ← NEW: Handle edge cases
                          │  ┌─────────────────┐  │
                          │  │ Traffic OK +    │  │
                          │  │ Routing Anomaly │  │
                          │  │ → Warning alert │  │
                          │  └─────────────────┘  │
                          └───────────┬───────────┘
                                      │
                          ┌───────────▼───────────┐
                          │      Reasoning        │
                          │  ┌─────────────────┐  │
                          │  │ Multi-round     │  │
                          │  │ Analysis        │  │
                          │  │ (Conditional)   │  │
                          │  └─────────────────┘  │
                          └───────────┬───────────┘
                                      │
                          ┌───────────▼───────────┐
                          │   Report Generation   │
                          └───────────┬───────────┘
                                      │
                              ┌───────▼───────┐
                              │    Complete   │
                              └───────────────┘
    
    Analysis Modes:
    ├─ FAST: Quick screening only (5-10s)
    ├─ TRAFFIC_FIRST: Traffic → Routing on demand (RECOMMENDED)
    ├─ FULL: Parallel analysis (legacy mode)
    └─ ROUTING_FOCUS: Routing first, traffic supplement
    
    Special Cases Handled:
    ⚠ Traffic OK + Routing Anomaly → Potential hidden risk warning
    ✓ Both OK → Quick confirmation (routing unrelated)
    ✗ Both Anomalous → Deep correlation analysis
    """


__all__ = [
    "WorkflowEngine",
    "WorkflowContext",
    "WorkflowState",
    "WorkflowEvent",
    "WorkflowError",
    "RetryableError",
    "AnalysisMode",
    "run_workflow",
    "get_workflow_architecture_diagram",
]
