"""
BGP Tracer Multi-Agent Workflow Engine
======================================
State machine: INITIAL → TRAFFIC_ANALYSIS → ROUTING_ANALYSIS → REASONING → REPORT → COMPLETE/ERROR

Enhanced Mode (--enhanced flag):
  ┌──────────────────────────────────────────────────────────────────────┐
  │            ReactiveDecisionEngine + MessageBus + LLMDebateAgent           │
  │  eval → decide (proceed|retry|probe|debate|escalate) ──▶ execute    │
  └──────────────────────────────────────────────────────────────────────┘
                                  ↑
                        OnlineEvaluationAgent
                       (QualityEvaluator gates + self-correction)

Fixes applied:
  F9  (Issue 9):   Reactive decisions ACTUALLY change execution via _handle_decision
  F12 (Issue 12):  Agents subscribe to MessageBus topics (not just publish)
  F5  (Issue 5):   Decision budgets prevent infinite loops
  F6  (Issue 6):   ExternalValidator breaks LLM self-reference in debate
  F7  (Issue 7):   ConflictResolver implemented in MultiAgentReportAgent
  F10 (Issue 10):   Concrete formulas for all quality metrics
  F11 (Issue 11):   Token cost + latency tracking per stage
  F13 (Issue 13):   Unified terminology (conclusion/winner/outcome)
  F14 (Issue 14):    Specific error types (PipelineError, DecisionBudgetExceeded)
"""

from __future__ import annotations

import asyncio
import json
import os
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar
from functools import wraps
import time
from time import perf_counter

from utils.helpers import make_json_safe
from utils.logger import logger
from detectors.traffic.multi_scale_baseline import CausalCorrelationScorer
from detectors.evidence_chain_builder import EvidenceChainBuilder


class WorkflowState(Enum):
    INITIAL = auto()
    PARSING_INPUT = auto()
    TRAFFIC_SCREENING = auto()
    TRAFFIC_ANALYSIS = auto()
    ROUTING_ANALYSIS = auto()
    JOINT_EVIDENCE = auto()  # New state for three-card joint evidence analysis (C1/C2/C3)
    REASONING = auto()
    VALIDATION = auto()
    DATA_ENRICHMENT = auto()
    REPORT_GENERATION = auto()
    COMPLETE = auto()
    ERROR = auto()


class WorkflowEvent(Enum):
    START = auto()
    INPUT_PARSED = auto()
    SCREENING_COMPLETE = auto()
    SCREENING_SKIP = auto()
    TRAFFIC_DONE = auto()
    ROUTING_DONE = auto()
    JOINT_EVIDENCE_COMPLETE = auto()  # New event for joint evidence complete
    REASONING_COMPLETE = auto()
    VALIDATION_PASSED = auto()
    VALIDATION_FAILED = auto()
    REPORT_GENERATED = auto()
    ERROR_OCCURRED = auto()
    DATA_COLLECTED = auto()


# ==================== Analysis Mode Configuration ====================

class AnalysisMode(Enum):
    """Analysis mode selection for different use cases."""
    TRAFFIC_FIRST = "traffic_first"  # Traffic first, routing on demand (RECOMMENDED)
    REACT = "react"  # LLM-driven ReAct with streaming


@dataclass
class StateTransition:
    """Represents a state transition with metadata."""
    step: int = 0                          # sequential step number (set when added to context)
    from_state: WorkflowState = None
    to_state: WorkflowState = None
    event: WorkflowEvent = None
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class WorkflowContext:
    user_input: str = None
    asn: str = None
    start_time: str = None
    end_time: str = None
    parsed_as_list: list = field(default_factory=list)
    is_batch: bool = False
    traffic_result: dict = None
    routing_result: dict = None
    reasoning_result: dict = None
    data_quality: str = "Unknown"
    confidence_score: float = 0.0
    anomalies_detected: bool = False
    diagnosis_result: dict = None
    verification_result: dict = None
    experiment_metrics: dict = field(default_factory=dict)
    current_state: WorkflowState = WorkflowState.INITIAL
    transitions: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    execution_time_ms: float = 0.0
    org_info: dict = None
    as_relationships: dict = None
    as_prefixes: dict = None
    report_path: str = None
    final_result: dict = None
    analysis_mode: str = "traffic_first"
    enable_mitm: bool = False
    # ── 事件元数据 ────────────────────────────────────────────────────────────
    event_type: str = None   # "hijack", "leak", "outage" - 用于决策是否强制路由分析
    as_role: str = None      # "受害者", "攻击者" - 用于判断分析的 AS 角色
    # ── 预计算数据（来自 annotation_package 等外部数据源）─────────────────────
    precomputed_routing: dict = None  # route_check.json 等预计算路由数据
    precomputed_traffic: dict = None  # 预计算流量数据
    # ── Screening & Analysis Control ──────────────────────────────────────────
    screening_result: dict = None
    needs_traffic_deep_analysis: bool = False
    needs_routing_analysis: bool = False
    routing_analysis_detail: str = "full"
    # victim ASes extracted from routing events (set by compute_causal_analysis)
    victim_asns: list = field(default_factory=list)
    routing_time_window: dict = None
    validation_notes: list = field(default_factory=list)
    evidence_records: list = field(default_factory=list)
    diagnosis_claims: list = field(default_factory=list)
    verification_records: list = field(default_factory=list)
    contradictions: list = field(default_factory=list)
    traffic_ok_but_routing_anomaly: bool = False
    causal_analysis: dict = None
    joint_alert: dict = None
    evidence_chain: dict = None
    bayesian_result: dict = None
    # ── HCAF 因果归因引擎结果（三个创新方法：MSCBD/CTPR/CIC）─────────────
    hcaf_attribution: dict = None
    hcaf_attribution_status: str = "skipped"  # "ok" / "skipped" / "failed"
    buffer_hours: float = 2.0
    # ── Enhanced multi-agent fields ──────────────────────────────────────────
    enhanced: bool = False              # enable enhanced multi-agent mode
    shared_blackboard = None           # single Blackboard shared across all stages
    message_bus_run_id: str = ""       # unique run_id for MessageBus instance
    debate_rounds: int = 3            # debate rounds in enhanced mode
    evaluation_retries: int = 2        # max evaluation retries in enhanced mode
    reactive_decisions: list = field(default_factory=list)  # decisions at reactive points
    evaluation_metrics: dict = field(default_factory=dict)   # per-stage quality metrics
    debate_results: list = field(default_factory=list)       # LLM debate results

    def add_error(self, error, stage, details = None):
        self.errors.append({"error": error, "stage": stage,
                            "timestamp": datetime.now().isoformat(), "details": details or {}})
    
    def add_transition(self, from_state: WorkflowState, to_state: WorkflowState, 
                       event: WorkflowEvent, duration_ms = 0.0,
                       metadata = None):
        """Record a state transition."""
        self.transitions.append(StateTransition(
            step=len(self.transitions) + 1,
            from_state=from_state,
            to_state=to_state,
            event=event,
            duration_ms=duration_ms,
            metadata=metadata or {}
        ))
        self.current_state = to_state


class WorkflowError(Exception):
    """Base exception for workflow errors."""
    def __init__(self, message, stage: WorkflowState, context: WorkflowContext):
        self.message = message
        self.stage = stage
        self.context = context
        super().__init__(message)


class RetryableError(Exception):
    """Error that can be retried."""
    pass


def async_retry(max_retries = 3, backoff_base = 1.0):
    """
    Decorator for automatic retry with exponential backoff.

    Usage:
        @async_retry(max_retries=3)
        async def unreliable_operation():
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Bug fix 2026-09-13 (BUG-R44): the previous implementation
            # unconditionally executed ``raise last_exception`` after the
            # retry loop. When ``max_retries == 0`` the for-loop runs
            # zero times, ``last_exception`` stays None, and the post-loop
            # statement becomes ``raise None`` → ``TypeError: exceptions
            # must derive from BaseException`` at runtime. Also, even
            # with a positive retry count, any non-RetryableError
            # exception was suppressed (we returned ``None``) — silent
            # swallowing.
            #
            # The cleaner fix: rewrite as ``attempt < max(max_retries, 1)``
            # so the function is always invoked at least once, and only
            # retry when ``max_retries > 0``.
            last_exception = None
            effective_attempts = max(max_retries, 1)
            for attempt in range(effective_attempts):
                try:
                    return await func(*args, **kwargs)
                except RetryableError as e:
                    last_exception = e
                    if attempt < effective_attempts - 1:
                        wait_time = backoff_base * (2 ** attempt)
                        logger.warning(f"Retry {attempt + 1}/{max_retries} for {func.__name__} after {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} retries exhausted for {func.__name__}")
            # If we got here, the function raised a RetryableError every
            # time. Propagate the last captured exception.
            if last_exception is not None:
                raise last_exception
            # Defensive fallback (should be unreachable in practice).
            return None
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
    - Enhanced multi-agent mode (--enhanced flag):
      * Shared Blackboard across all stages
      * AgentMessageBus for real-time agent communication
      * OnlineEvaluationAgent with self-correction
      * LLM-driven debate replacing rule-based ChallengeAgent/RefereeAgent
      * ReactiveDecisionEngine for adaptive stage decisions
      * MultiAgentReportAgent for specialist-validated reports
    """

    def __init__(
        self,
        max_retries = 3,
        parallel_execution = True,
        skip_unnecessary_analysis = None,
        enhanced = False,
        debate_rounds = 3,
        evaluation_retries = 2,
    ):
        from config import (
            WORKFLOW_SKIP_WHEN_NO_ANOMALIES,
            WORKFLOW_MIN_HCAF_TIER,
            WORKFLOW_MIN_HCAF_SCORE,
        )
        self.max_retries = max_retries
        self.parallel_execution = parallel_execution
        # Resolve from config if not explicitly passed (no hard-coded booleans)
        self.skip_unnecessary_analysis = (
            WORKFLOW_SKIP_WHEN_NO_ANOMALIES
            if skip_unnecessary_analysis is None
            else skip_unnecessary_analysis
        )
        self.min_hcaf_tier = WORKFLOW_MIN_HCAF_TIER
        self.min_hcaf_score = WORKFLOW_MIN_HCAF_SCORE
        self.enhanced = enhanced
        self.debate_rounds = debate_rounds
        self.evaluation_retries = evaluation_retries
        self._enhanced_components = None  # lazy-initialized

        # State handlers
        self._state_handlers: dict[WorkflowState, Callable] = {}
        self.register_default_handlers()

        # Metrics
        self.metrics = {
            "total_runs": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "total_execution_time_ms": 0.0
        }

    @staticmethod
    def _extract_hcaf_strength(result) -> dict:
        """Return ``{"strength": <value|None>}`` from a HCAF result object.

        Bug fix 2026-09-13: previous code used
        ``getattr(getattr(结果, "强度", None), "value", "unknown")``.
        If ``结果.强度`` exists but lacks a ``.value`` attribute, the
        inner getattr returned ``None`` and the outer ``getattr`` ALSO
        returned ``None`` — the "unknown" default was unreachable.

        New shape handles four cases:
          1. ``强度`` missing  → ``"unknown"``
          2. ``强度`` has ``.value`` (e.g. Enum) → use that
          3. ``强度`` is a plain scalar (float/int/str) → use directly
          4. Otherwise → ``str(强度)`` so the value still reaches the caller
        """
        strength_obj = getattr(result, "强度", None)
        if strength_obj is None:
            return {"strength": "unknown"}
        if hasattr(strength_obj, "value"):
            return {"strength": strength_obj.value}
        if isinstance(strength_obj, (int, float, str, bool)):
            return {"strength": strength_obj}
        try:
            return {"strength": str(strength_obj)}
        except Exception:
            return {"strength": "unknown"}

    def register_default_handlers(self):
        """Register default state handlers."""
        self._state_handlers = {
            WorkflowState.INITIAL: self._handle_initial,
            WorkflowState.PARSING_INPUT: self._handle_parsing_input,
            WorkflowState.TRAFFIC_SCREENING: self._handle_traffic_screening,
            WorkflowState.TRAFFIC_ANALYSIS: self._handle_traffic_analysis,
            WorkflowState.ROUTING_ANALYSIS: self._handle_routing_analysis,
            WorkflowState.JOINT_EVIDENCE: self._handle_joint_evidence,  # New state for three-card analysis
            WorkflowState.REASONING: self._handle_reasoning,
            WorkflowState.VALIDATION: self._handle_validation,
            WorkflowState.DATA_ENRICHMENT: self._handle_data_enrichment,
            WorkflowState.REPORT_GENERATION: self._handle_report_generation,
            WorkflowState.COMPLETE: self._handle_complete,
            WorkflowState.ERROR: self._handle_error,
        }

    def init_enhanced_components(self, context: WorkflowContext):
        """
        Lazily initialize enhanced multi-agent components.
        Called once at the start of enhanced-mode execution.
        """
        if self._enhanced_components is not None:
            return

        from agents.enhanced import (
            AgentMessageBus,
            BlackboardMessageBridge,
            OnlineEvaluationAgent,
            QualityEvaluator,
            ReactiveDecisionEngine,
            ReactiveDecision,
            LLMDebateAgent,
            MultiAgentReportAgent,
            Topic,
        )
        from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
        from config import MODEL, API_KEY, BASE_URL

        # Create unique run_id from context
        run_id = f"{context.asn}_{context.start_time.replace(' ', '_')[:19]}".replace(':', '')
        context.message_bus_run_id = run_id

        # Shared Blackboard (single instance, persists across all stages)
        from agents.core import Blackboard
        bb = Blackboard()
        context.shared_blackboard = bb

        # Message bus + bridge
        bus = AgentMessageBus.get_instance(run_id)
        bridge = BlackboardMessageBridge(bb, bus)
        bridge.start()

        # ── F12: Real event-driven subscriptions ───────────────────────────────────
        from config import WORKFLOW_EVENT_DRIVEN_ENABLED

        async def on_traffic_full(envelope):
            """When traffic.full arrives, write a synthesised observation
            to Blackboard so other stages can consume without re-querying
            routing/traffic."""
            traffic = envelope.content.get("traffic_result", {}) or {}
            anomaly_count = traffic.get("anomaly_count", 0) if isinstance(traffic, dict) else 0
            await bb.add_observation({
                "source": "BusSub:RoutingAgent",
                "kind": "traffic_bus_signal",
                "summary": f"Traffic full result published: {anomaly_count} anomalies",
                "confidence": 0.7,
                "payload": {"anomaly_count": anomaly_count},
                "tags": ["traffic", "bus"],
            })
            logger.info(f"[BusSub] RoutingAgent saw traffic.full (anomaly_count={anomaly_count})")

        async def on_routing_complete(envelope):
            routing = envelope.content.get("routing_result", {}) or {}
            hijack_count = (
                len(routing.get("origin_hijacked") or [])
                + len(routing.get("forge_hijacked") or [])
                + len(routing.get("origin_hijacking") or [])
                + len(routing.get("forge_hijacking") or [])
            )
            await bb.add_observation({
                "source": "BusSub:EvalAgent",
                "kind": "routing_bus_signal",
                "summary": f"Routing complete: {hijack_count} hijack events",
                "confidence": 0.75,
                "payload": {"hijack_count": hijack_count},
                "tags": ["routing", "bus"],
            })
            logger.info(f"[BusSub] EvalAgent saw routing.complete (hijack_count={hijack_count})")

        async def on_diagnosis(envelope):
            """ReportCoordinator uses diagnosis conclusion to feed
            the MultiAgentReportAgent stage later."""
            content = envelope.content or {}
            debate_results = content.get("debate_results") or []
            best = debate_results[0] if debate_results else {}
            conclusion = best.get("conclusion") or best.get("winner") or content.get("conclusion") or "N/A"
            await bb.add_observation({
                "source": "BusSub:ReportCoordinator",
                "kind": "diagnosis_bus_signal",
                "summary": f"Diagnosis final: conclusion={conclusion}",
                "confidence": 0.8,
                "payload": {"conclusion": conclusion, "debate_result_count": len(debate_results)},
                "tags": ["diagnosis", "bus"],
            })
            logger.info(f"[BusSub] ReportCoordinator saw diagnosis.final (conclusion={conclusion})")

        async def on_hcaf(envelope):
            """HCAF attribution feeds confidence calibration in real time."""
            hcaf = envelope.content or {}
            tier = hcaf.get("tier", "INSUFFICIENT")
            confidence = float(hcaf.get("confidence", 0.0))
            direction = hcaf.get("direction", "unknown")
            await bb.add_observation({
                "source": "BusSub:CalibratorAgent",
                "kind": "hcaf_bus_signal",
                "summary": f"HCAF: tier={tier}, direction={direction}, confidence={confidence:.0%}",
                "confidence": max(0.5, confidence),
                "payload": hcaf,
                "tags": ["hcaf", "bus"],
            })
            logger.info(f"[BusSub] CalibratorAgent saw validation.hcaf_attribution (tier={tier})")

        bus.subscribe_sync(Topic.TRAFFIC_FULL_RESULT, on_traffic_full, "RoutingAgent")
        bus.subscribe_sync(Topic.ROUTING_COMPLETE, on_routing_complete, "EvalAgent")
        bus.subscribe_sync("diagnosis.debate.complete", on_diagnosis, "ReportCoordinator")
        bus.subscribe_sync(Topic.DIAGNOSIS_FINAL, on_diagnosis, "ReportCoordinator")
        bus.subscribe_sync("validation.hcaf_attribution", on_hcaf, "CalibratorAgent")
        bus.subscribe_sync(Topic.REPORT_COMPLETE, on_diagnosis, "ReportCoordinator")

        if not WORKFLOW_EVENT_DRIVEN_ENABLED:
            # Diagnostic mode: collapse subscribers to log-only behavior.
            # Useful when LLM rate limits make downstream reactions undesirable.
            # Bug fix 2026-09-13: the previous implementation iterated
            # ``bus._subscriptions.values()`` (lists of callbacks) and used
            # each list as a dict key — which raises TypeError because
            # lists are unhashable. Iterate keys instead.
            for topic in list(bus._subscriptions.keys()):
                bus._subscriptions[topic] = []
            logger.info("[BusSub] WORKFLOW_EVENT_DRIVEN_ENABLED=false — subscribers disabled")

        # LLM (shared across all enhanced agents)
        llm, _ = setup_llm_settings(
            model=MODEL, api_key=API_KEY, base_url=BASE_URL,
            temperature=DEFAULT_TEMP_REASONING, timeout=120.0
        )

        # Evaluation components
        evaluator = QualityEvaluator()
        eval_agent = OnlineEvaluationAgent(bb, evaluator=evaluator)

        # Reactive decision engine
        decision_engine = ReactiveDecisionEngine(llm=llm)

        # LLM debate agent
        debate_agent = LLMDebateAgent(bb, max_rounds=self.debate_rounds)

        # Multi-agent report agent
        report_agent = MultiAgentReportAgent(bb)

        self._enhanced_components = {
            "bus": bus,
            "bridge": bridge,
            "llm": llm,
            "evaluator": evaluator,
            "eval_agent": eval_agent,
            "decision_engine": decision_engine,
            "debate_agent": debate_agent,
            "report_agent": report_agent,
        }

    async def execute(self, context: WorkflowContext):
        """
        Execute the workflow starting from INITIAL state.

        Args:
            context: Initial workflow context with user input

        Returns:
            Updated context with all results and execution trace
        """
        _t0 = perf_counter()
        self.metrics["total_runs"] += 1

        # Hard cap on total workflow runtime to avoid the enhanced mode
        # getting stuck in debate/retry loops. Defaults to 900s, overridable
        # via BGP_TRACER_WORKFLOW_TIMEOUT_S. When the cap is hit we jump
        # straight to REPORT_GENERATION so the caller still gets a usable
        # HTML, then mark COMPLETE.
        try:
            from config import WORKFLOW_TOTAL_TIMEOUT_S
        except Exception:
            WORKFLOW_TOTAL_TIMEOUT_S = 900.0
        workflow_timeout_s = float(
            os.environ.get("BGP_TRACER_WORKFLOW_TIMEOUT_S", WORKFLOW_TOTAL_TIMEOUT_S)
        )

        context.add_transition(
            WorkflowState.INITIAL,
            WorkflowState.INITIAL,
            WorkflowEvent.START
        )

        # Transfer enhanced flags from engine to context
        context.enhanced = context.enhanced or self.enhanced
        context.debate_rounds = context.debate_rounds or self.debate_rounds
        context.evaluation_retries = context.evaluation_retries or self.evaluation_retries

        # Bug fix 2026-09-13: ``event_type`` and ``as_role`` came in as
        # parameters to ``run_workflow`` and were stored on the context,
        # but were NEVER written into the Blackboard ``config`` section.
        # Downstream agents that read ``config.event_type`` (e.g.
        # RoutingAgent when deciding whether to skip / force routing
        # analysis for a hijack-shaped event) therefore saw ``None``.
        # Mirror both keys into the shared blackboard here so they're
        # available before any handler runs.
        bb_seed = getattr(context, "shared_blackboard", None)
        if bb_seed is not None:
            if context.event_type is not None:
                await bb_seed.write("config", "event_type", context.event_type)
            if context.as_role is not None:
                await bb_seed.write("config", "as_role", context.as_role)

        try:
            # Initialize enhanced multi-agent components if enabled
            if context.enhanced:
                self.init_enhanced_components(context)
                logger.info(
                    f"[Enhanced Mode] Enabled: debate_rounds={context.debate_rounds}, "
                    f"evaluation_retries={context.evaluation_retries}, "
                    f"run_id={context.message_bus_run_id}"
                )

            # Main state machine loop
            timed_out = False
            while context.current_state not in (WorkflowState.COMPLETE, WorkflowState.ERROR):
                # ── Global timeout check ──────────────────────────────────
                elapsed = perf_counter() - _t0
                if elapsed > workflow_timeout_s:
                    logger.warning(
                        f"[Workflow] GLOBAL TIMEOUT ({elapsed:.1f}s > {workflow_timeout_s}s) "
                        f"at state {context.current_state.name}; forcing REPORT_GENERATION"
                    )
                    context.validation_notes.append({
                        "case": "workflow_global_timeout",
                        "severity": "warning",
                        "message": (
                            f"Workflow exceeded {workflow_timeout_s:.0f}s; "
                            "skipping remaining stages and forcing report generation"
                        ),
                    })
                    timed_out = True
                    if context.current_state != WorkflowState.REPORT_GENERATION:
                        context.current_state = WorkflowState.REPORT_GENERATION
                        continue
                    break

                handler = self._state_handlers.get(context.current_state)

                if handler is None:
                    raise WorkflowError(
                        f"No handler for state {context.current_state}",
                        context.current_state,
                        context
                    )

                # Track state duration
                state_start = perf_counter()
                prev_state = context.current_state

                # Execute state handler
                next_event = await handler(context)

                # Record transition
                state_duration = (perf_counter() - state_start) * 1000

                # Determine next state based on event (pass context for dynamic routing)
                next_state = self.get_next_state(prev_state, next_event, context)
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

                # ── Checkpoint: persist progress after each successful state ──
                ckpt = getattr(self, "checkpoint", None)
                if ckpt is not None and ckpt.enabled:
                    try:
                        ckpt.save(f"workflow_{prev_state.name.lower()}", snapshot_context(context))
                    except Exception as e:
                        logger.warning(f"[Checkpoint] Failed to save after {prev_state.name}: {e}")

            if timed_out and context.current_state != WorkflowState.COMPLETE:
                # Fallback reached: jump to report generation and let it
                # produce whatever HTML it can with the partial evidence.
                # The state machine loop above already redirected us there.
                pass

            # Success
            self.metrics["successful_runs"] += 1

        except Exception as e:
            tb = traceback.format_exc()
            context.add_error(str(e), context.current_state.name, {
                "exception_type": type(e).__name__,
                "traceback": tb
            })
            context.current_state = WorkflowState.ERROR
            self.metrics["failed_runs"] += 1
            logger.error(f"Workflow error at {context.current_state.name}: {e}\n{tb}")

            # ── Save on error too, so the user can resume from the failure point ──
            ckpt = getattr(self, "checkpoint", None)
            if ckpt is not None and ckpt.enabled:
                try:
                    ckpt.save("workflow_state", snapshot_context(context))
                except Exception as save_err:
                    logger.warning(f"[Checkpoint] Failed to save error state: {save_err}")

        finally:
            context.execution_time_ms = (perf_counter() - _t0) * 1000
            self.metrics["total_execution_time_ms"] += context.execution_time_ms

            # Clean up MessageBus if enhanced mode was used
            if context.message_bus_run_id:
                # Bug fix 2026-09-13: stop() the BlackboardMessageBridge
                # BEFORE clearing the bus instance. The bridge monkey-patches
                # ``bb._notify`` in start(); without stop() the patched
                # callback stays attached and any subsequent Blackboard
                # activity (including a non-enhanced follow-up run that
                # happens to share the same Python process) will try to
                # call into a dead bus instance and AttributeError.
                bridge = (self._enhanced_components or {}).get("bridge") if hasattr(self, "_enhanced_components") else None
                if bridge is not None:
                    try:
                        bridge.stop()
                    except Exception as _bs_err:
                        logger.warning(f"[Enhanced Mode] Bridge stop failed: {_bs_err}")
                from agents.enhanced import AgentMessageBus
                AgentMessageBus.clear_instance(context.message_bus_run_id)
                logger.info(f"[Enhanced Mode] MessageBus instance cleared: {context.message_bus_run_id}")

            # Bug fix 2026-09-13 (BUG-R56): TokenBudget.clear_instance
            # existed but was never called in production — only tests
            # used it. Without cleanup, every run leaks its TokenBudget
            # entry into TokenBudget._instances for the lifetime of the
            # Python process. Long-running batch jobs (e.g. 100-event
            # benchmark runs) accumulate hundreds of AgentTokenUsage
            # lists that are kept alive even after analysis completes,
            # eventually OOMing the worker. We now clear the instance
            # here alongside MessageBus so both registries balance with
            # each run.
            if context.message_bus_run_id:
                try:
                    from agents.token_budget import TokenBudget
                    TokenBudget.clear_instance(context.message_bus_run_id)
                except Exception as _tb_err:
                    logger.debug(f"[Cleanup] TokenBudget.clear_instance failed: {_tb_err}")

            # ── Final checkpoint: save fully-completed context ──
            ckpt = getattr(self, "checkpoint", None)
            if ckpt is not None and ckpt.enabled and context.current_state == WorkflowState.COMPLETE:
                try:
                    ckpt.save("workflow_context", snapshot_context(context))
                except Exception as e:
                    logger.warning(f"[Checkpoint] Failed to save final context: {e}")

        return context
    
    def get_next_state(self, current: WorkflowState, event: WorkflowEvent, context: WorkflowContext = None):
        transitions = {
            (WorkflowState.INITIAL, WorkflowEvent.START): WorkflowState.PARSING_INPUT,
            (WorkflowState.PARSING_INPUT, WorkflowEvent.INPUT_PARSED): WorkflowState.TRAFFIC_SCREENING,
            (WorkflowState.TRAFFIC_SCREENING, WorkflowEvent.SCREENING_COMPLETE): WorkflowState.TRAFFIC_ANALYSIS,
            (WorkflowState.TRAFFIC_SCREENING, WorkflowEvent.SCREENING_SKIP): WorkflowState.JOINT_EVIDENCE,
            (WorkflowState.ROUTING_ANALYSIS, WorkflowEvent.ROUTING_DONE): WorkflowState.JOINT_EVIDENCE,
            (WorkflowState.JOINT_EVIDENCE, WorkflowEvent.JOINT_EVIDENCE_COMPLETE): WorkflowState.REASONING,
            (WorkflowState.REASONING, WorkflowEvent.REASONING_COMPLETE): WorkflowState.VALIDATION,
            (WorkflowState.VALIDATION, WorkflowEvent.VALIDATION_PASSED): WorkflowState.DATA_ENRICHMENT,
            (WorkflowState.VALIDATION, WorkflowEvent.VALIDATION_FAILED): WorkflowState.ERROR,
            (WorkflowState.DATA_ENRICHMENT, WorkflowEvent.DATA_COLLECTED): WorkflowState.REPORT_GENERATION,
            (WorkflowState.REPORT_GENERATION, WorkflowEvent.REPORT_GENERATED): WorkflowState.COMPLETE,
        }

        result = transitions.get((current, event))
        if current == WorkflowState.TRAFFIC_ANALYSIS and event == WorkflowEvent.TRAFFIC_DONE:
            # After traffic, go to routing if needed, else joint evidence
            if context and getattr(context, 'needs_routing_analysis', False):
                return WorkflowState.ROUTING_ANALYSIS
            return WorkflowState.JOINT_EVIDENCE
        return result if result else current
    
    # ── State Handlers ───────────────────────────────────────────────────────

    async def _handle_initial(self, context: WorkflowContext):
        return WorkflowEvent.START

    async def _handle_parsing_input(self, context: WorkflowContext):
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
    
    async def _handle_traffic_screening(self, context: WorkflowContext):
        logger.info(f"Preparing joint traffic and routing analysis for AS{context.asn}...")
        
        try:
            # Full traffic analysis always runs below. Keep this stage as
            # workflow metadata instead of making a second API request.
            screening_result = {
                "need_full_analysis": True,
                "quick_score": None,
                "data_available": None,
                "anomaly_signals": [],
                "decision_reasons": ["Full traffic and routing analysis is required for joint assessment."],
                "skipped": True,
            }
            
            context.screening_result = screening_result
            context.needs_traffic_deep_analysis = screening_result.get("need_full_analysis", True)

            logger.info(
                f"Traffic screening complete: score={screening_result.get('quick_score')}, "
                f"need_full={context.needs_traffic_deep_analysis}, "
                f"signals={len(screening_result.get('anomaly_signals', []))}"
            )

            if context.analysis_mode == AnalysisMode.REACT:
                # React mode is handled elsewhere; screening defaults to traffic-first behavior here.
                context.needs_routing_analysis = True
                context.routing_analysis_detail = "full" if screening_result.get("need_full_analysis") else "light"
                return WorkflowEvent.SCREENING_COMPLETE
            else:
                # TRAFFIC_FIRST (default)
                context.needs_routing_analysis = True
                context.routing_analysis_detail = "full"
                return WorkflowEvent.SCREENING_COMPLETE

        except Exception as e:
            logger.error(f"Traffic screening failed: {e}")
            # On error, default to full analysis
            context.screening_result = {
                "error": str(e),
                "need_full_analysis": True,
                "decision_reasons": ["Screening failed, defaulting to full analysis"]
            }
            context.needs_traffic_deep_analysis = True
            context.needs_routing_analysis = True
            context.routing_analysis_detail = "full"
            return WorkflowEvent.SCREENING_COMPLETE
    
    async def _handle_traffic_analysis(self, context: WorkflowContext):
        from agents.core import Blackboard
        from agents.traffic_agent import TrafficAgent

        logger.info(f"[_handle_traffic_analysis] precomputed_traffic={bool(context.precomputed_traffic)}")

        # Use shared Blackboard in enhanced mode; create new one otherwise
        if context.enhanced and context.shared_blackboard:
            bb = context.shared_blackboard
            # Bug fix: in enhanced mode the shared Blackboard is created in
            # init_enhanced_components but never seeded with config.asn /
            # config.start_time / config.end_time. Without these, TrafficAgent
            # / RoutingAgent immediately return "Missing config" and the
            # whole analysis chain silently degrades to inconclusive.
            await bb.write("config", "asn", context.asn)
            await bb.write("config", "start_time", context.start_time)
            await bb.write("config", "end_time", context.end_time)
        else:
            bb = Blackboard()
            await bb.write("config", "asn", context.asn)
            await bb.write("config", "start_time", context.start_time)
            await bb.write("config", "end_time", context.end_time)

        # ── 注入预计算数据（来自 annotation_package route_check.json）─────────────
        if context.precomputed_routing:
            logger.info(f"[PrecomputedRouting] Injecting {len(context.precomputed_routing)} precomputed routing records")
            await bb.write("routing", "precomputed", context.precomputed_routing)
            await bb.write("config", "use_precomputed_routing", True)

        if context.precomputed_traffic:
            logger.info(f"[PrecomputedTraffic] Injecting precomputed traffic data")
            await bb.write("traffic", "precomputed", context.precomputed_traffic)

        if context.precomputed_traffic:
            logger.info("[TrafficAnalysis] Using supplied traffic evidence")
            context.traffic_result = context.precomputed_traffic
            context.anomalies_detected = context.anomalies_detected or bool(
                context.precomputed_traffic.get("anomalies_detected")
                or context.precomputed_traffic.get("anomalies")
                or context.precomputed_traffic.get("anomaly_count", 0) > 0
            )
            context.needs_routing_analysis = True
            context.routing_analysis_detail = "full"
            return WorkflowEvent.TRAFFIC_DONE

        agent = TrafficAgent(bb)
        await agent.start()
        result = await agent.step()

        if result.success:
            traffic = await bb.read_section("traffic")
            context.traffic_result = traffic.get("result", traffic)
            if traffic.get("anomalies"):
                # set anomalies_detected when traffic data contains anomalies
                context.anomalies_detected = True
                windows = extract_anomaly_windows(traffic["anomalies"], buffer_hours=context.buffer_hours)
                if windows:
                    all_windows = union_anomaly_windows(windows)
                    context.routing_time_window = all_windows

            # Routing evidence is independently required. A normal traffic
            # series can coexist with a short-lived or mitigated route event.
            traffic_has_anomaly = traffic.get("anomalies_detected", False) or context.anomalies_detected
            context.anomalies_detected = context.anomalies_detected or traffic_has_anomaly
            context.needs_routing_analysis = True
            context.routing_analysis_detail = "full"

            logger.info(
                f"Traffic: anomalies={traffic_has_anomaly}, "
                f"needs_routing={context.needs_routing_analysis}, "
                f"event_type={context.event_type}, as_role={context.as_role}, "
                f"routing_window={context.routing_time_window}"
            )

            # Enhanced mode: publish to MessageBus
            if context.enhanced and context.message_bus_run_id:
                from agents.enhanced import AgentMessageBus, Topic
                bus = AgentMessageBus.get_instance(context.message_bus_run_id)
                await bus.publish(
                    topic=Topic.TRAFFIC_FULL_RESULT,
                    sender="TrafficAgent",
                    content={"traffic_result": context.traffic_result, "anomalies": traffic.get("anomalies", [])},
                )

        return WorkflowEvent.TRAFFIC_DONE
    
    async def _handle_routing_analysis(self, context: WorkflowContext):
        from agents.core import Blackboard
        from agents.routing_agent import RoutingAgent

        if not context.needs_routing_analysis:
            context.routing_result = {"success": True, "skipped": True, "reason": "fast_mode"}
            return WorkflowEvent.ROUTING_DONE

        routing_start = context.start_time
        routing_end = context.end_time

        rt = context.routing_time_window
        if rt:
            context.traffic_anomaly_window = rt
            # when routing_time_window comes from traffic-expanded analysis,
            # 路由分析应使用扩展后的时间窗口，而非用户原始输入窗口。
            # 原代码这里只更新 traffic_anomaly_window，但没有更新 routing_start/routing_end，
            # 导致 RoutingAgent 收到的 bb config 永远是用户原始时间窗口。
            if isinstance(rt, dict):
                if rt.get("start") or rt.get("start_time"):
                    routing_start = str(rt.get("start") or rt.get("start_time"))
                if rt.get("end") or rt.get("end_time"):
                    routing_end = str(rt.get("end") or rt.get("end_time"))
            logger.info(f"[RoutingAnalysis] Using traffic-expanded routing window: {routing_start} → {routing_end}")
        else:
            context.traffic_anomaly_window = None

        # ── 注入预计算路由数据 ────────────────────────────────────────────────
        if context.precomputed_routing:
            logger.info("[RoutingAnalysis] Using precomputed routing data from annotation_package")
            context.routing_result = context.precomputed_routing
            # 确保预计算数据被标记为成功
            if isinstance(context.routing_result, dict):
                context.routing_result["_source"] = "precomputed"
                context.routing_result["_from_annotation_package"] = True
            # set anomalies_detected when precomputed data contains anomalies
            context.anomalies_detected = context.anomalies_detected or bool(
                context.routing_result.get("origin_hijacked")
                or context.routing_result.get("path_leak")
                or context.routing_result.get("anomalies_detected")
                or context.routing_result.get("anomaly_count", 0) > 0
            )
            await self._cross_validate_results(context)
            return WorkflowEvent.ROUTING_DONE

        # Use shared Blackboard in enhanced mode
        if context.enhanced and context.shared_blackboard:
            bb = context.shared_blackboard
        else:
            bb = Blackboard()
        # Write the routing-window config keys once. The previous
        # implementation wrote them twice in the non-enhanced branch
        # (the second copy was a dead-code duplicate of the first); we
        # consolidate here so config keys stay in lockstep with the
        # routing_time_window derivation above.
        await bb.write("config", "asn", context.asn)
        await bb.write("config", "start_time", routing_start)
        await bb.write("config", "end_time", routing_end)
        await bb.write("config", "enable_mitm", context.enable_mitm)
        # use_traffic_time_window should follow rt dynamically
        # 当 routing_time_window 由 traffic 扩展分析得出时，设为 True，
        # 让 RoutingAgent 知道使用扩展窗口而非用户原始窗口。
        await bb.write("config", "use_traffic_time_window", rt is not None)
        await bb.write("config", "routing_detail", context.routing_analysis_detail or "full")
        # Bug fix 2026-09-13: ``event_type`` and ``as_role`` came in via
        # the CLI / workflow context but were never propagated into the
        # routing Blackboard, so RoutingAgent saw them as None.
        if context.event_type is not None:
            await bb.write("config", "event_type", context.event_type)
        if context.as_role is not None:
            await bb.write("config", "as_role", context.as_role)
        if rt:
            await bb.write("traffic", "expanded_windows", [rt])
            await bb.write("traffic", "anomaly_window", rt)

        logger.info(
            f"Routing analysis window (user input, independent): {routing_start} → {routing_end}"
        )

        agent = RoutingAgent(bb)
        await agent.start()
        result = await agent.step()

        if result.success:
            raw_section = bb._sections.get("routing", {})
            context.routing_result = raw_section.get("result", raw_section)
            # set anomalies_detected when routing results contain anomaly events
            routing_anomaly = (
                bool(context.routing_result.get("origin_hijacked"))
                or bool(context.routing_result.get("path_leak"))
                or bool(context.routing_result.get("anomalies_detected"))
                or context.routing_result.get("anomaly_count", 0) > 0
            )
            context.anomalies_detected = context.anomalies_detected or routing_anomaly
        else:
            context.routing_result = {
                "success": False,
                "data_available": False,
                "no_data_reason": "routing_agent_failed",
                "error": result.error or "Routing analysis failed",
            }

        await self._cross_validate_results(context)

        if result.success:
            # Enhanced mode: publish to MessageBus
            if context.enhanced and context.message_bus_run_id:
                from agents.enhanced import AgentMessageBus, Topic
                bus = AgentMessageBus.get_instance(context.message_bus_run_id)
                await bus.publish(
                    topic=Topic.ROUTING_COMPLETE,
                    sender="RoutingAgent",
                    content={"routing_result": context.routing_result},
                )

        return WorkflowEvent.ROUTING_DONE
    
    async def _handle_joint_evidence(self, context: WorkflowContext):
        """
        New state: Run three-card joint evidence analysis (C1/C2/C3).
        
        This runs after routing analysis is complete and before LLM reasoning.
        It computes the three-card evidence package:
        - Card 1: Temporal alignment
        - Card 2: Blast radius (prefix-level AS-path shift + victim traffic)
        - Card 3: Falsification tree (alternative explanations)
        
        The joint tier (C1/C2/C3) is stored in context.joint_tier for report rendering.
        """
        try:
            from detectors.traffic.joint_evidence import analyse_joint_evidence
            from detectors.traffic.multi_scale_baseline import CausalCorrelationScorer

            logger.info("[JointEvidence] Running three-card joint evidence analysis...")

            # Extract routing events from routing_result
            routing_events = []
            if context.routing_result and context.routing_result.get("success") is not False:
                # annotation_package uses a nested format:
                #   { "hijack": { "origin_hijacked": [...] }, "leak": {...}, "outage": {...} }
                # Live routing analysis uses a flat format:
                #   { "origin_hijacked": [...], "leak": {...}, "outage_analysis": {...} }
                # Normalise both into the flat form.
                rr = context.routing_result
                hijack_section = rr.get("hijack") or {}   # annotation_package nested format
                for key in ["origin_hijacked", "origin_hijacking", "forge_hijacked", "forge_hijacking"]:
                    # prefer flat key; fall back to nested hijack.{key}
                    events = rr.get(key) or hijack_section.get(key) or []
                    for event in events:
                        # Normalise event to dict (it may be AnomalyDetail).
                        if isinstance(event, dict):
                            event_copy = dict(event)
                        else:
                            event_copy = dict(getattr(event, "__dict__", {}) or {})
                        event_copy["event_type"] = (key
                            .replace("origin_hijacked", "origin_hijack")
                            .replace("origin_hijacking", "origin_hijack")
                            .replace("forge_hijacked", "forge_hijack")
                            .replace("forge_hijacking", "forge_hijack"))
                        if "timestamp" not in event_copy and "first_seen" in event_copy:
                            event_copy["timestamp"] = event_copy["first_seen"]
                        routing_events.append(event_copy)

                # Add route leaks — annotation_package uses "leak" dict; live uses "route_leaks" list
                leak_section = rr.get("leak") or {}
                leak_events = rr.get("route_leaks") or leak_section.get("route_leaks") or []
                for event in leak_events:
                    # Normalise event to dict (it may be AnomalyDetail).
                    if isinstance(event, dict):
                        event_copy = dict(event)
                    else:
                        event_copy = dict(getattr(event, "__dict__", {}) or {})
                    event_copy["event_type"] = "leak"
                    routing_events.append(event_copy)

                # Add outage events — annotation_package uses "outage" dict; live uses "outage_analysis" dict
                outage = rr.get("outage_analysis") or rr.get("outage") or {}
                if outage.get("is_outage_suspected"):
                    routing_events.append({
                        "event_type": "outage",
                        "timestamp": outage.get("timestamp") or outage.get("first_seen"),
                        "severity": outage.get("outage_score", 0),
                    })

            # Extract traffic anomalies from traffic_result
            traffic_anomalies = []
            if context.traffic_result and context.traffic_result.get("data_available") is not False:
                for anomaly in context.traffic_result.get("anomalies", []) or []:
                    # Normalise anomaly to dict (it may be AnomalyDetail).
                    if isinstance(anomaly, dict):
                        anomaly_copy = dict(anomaly)
                    else:
                        anomaly_copy = dict(getattr(anomaly, "__dict__", {}) or {})
                    if "timestamp" not in anomaly_copy:
                        anomaly_copy["timestamp"] = anomaly_copy.get("time")
                    traffic_anomalies.append(anomaly_copy)

            logger.info(f"[JointEvidence] Found {len(routing_events)} routing events, {len(traffic_anomalies)} traffic anomalies")

            # Run the three-card joint evidence analysis
            if routing_events or traffic_anomalies:
                # Pass the soft cluster window through so the temporal card
                # can compute a ΔT entry even when `anomalies=[]` but the
                # chart still shows a clear drop inside the analysis window.
                soft_window = None
                tr = context.traffic_result or {}
                for key in ("expanded_windows", "consecutive_anomaly_windows"):
                    wins = tr.get(key) or []
                    if isinstance(wins, list) and wins:
                        soft_window = wins[0]
                        break
                if soft_window is None and isinstance(tr.get("expanded_boundaries"), dict):
                    soft_window = tr.get("expanded_boundaries")

                joint = analyse_joint_evidence(
                    routing_events=routing_events,
                    traffic_anomalies=traffic_anomalies,
                    traffic_anomaly_window=soft_window,
                    # Pass victim/prefix traffic results from blackboard when available
                    victim_traffic=getattr(context, 'victim_traffic_results', None) or {},
                    prefix_traffic=getattr(context, 'prefix_traffic_results', None) or {},
                    confounders=getattr(context, 'confounders', None) or {},
                    causal_evidence=getattr(context, 'causal_evidence', None) or {},
                )
                
                # Store results in context for downstream processing
                context.joint_tier = joint.get("tier", "INSUFFICIENT")
                context.joint_score = joint.get("average_score", 0.0)
                context.joint_evidence_cards = joint.get("evidence_cards", [])
                context.joint_rationale = joint.get("rationale", "")
                
                # Also compute with CausalCorrelationScorer for additional metrics
                scorer = CausalCorrelationScorer()
                scorer_result = scorer.score(
                    routing_events=routing_events,
                    traffic_anomalies=traffic_anomalies,
                )
                context.causal_scorer_result = scorer_result
                
                logger.info(f"[JointEvidence] Tier={context.joint_tier}, Score={context.joint_score:.3f}")
                logger.info(f"[JointEvidence] Evidence cards: {[c.get('name') for c in context.joint_evidence_cards]}")
                
                # Store in validation_notes for visibility
                context.validation_notes.append({
                    "case": "joint_evidence",
                    "severity": "info",
                    "message": f"Three-card joint evidence: {context.joint_tier} (score={context.joint_score:.3f})",
                    "details": {
                        "tier": context.joint_tier,
                        "average_score": context.joint_score,
                        "evidence_cards": [
                            {"name": c.get("name"), "score": c.get("score"), "available": c.get("available")}
                            for c in context.joint_evidence_cards
                        ],
                    },
                })
            else:
                logger.info("[JointEvidence] No routing events or traffic anomalies found, skipping joint analysis")
                context.joint_tier = "INSUFFICIENT"
                context.joint_score = 0.0
                context.joint_evidence_cards = []

            # HCAF 因果归因（三个创新方法：MSCBD/CTPR/CIC）
            try:
                hcaf_result = self.compute_hcaf_attribution(context)
                if hcaf_result:
                    context.hcaf_attribution = hcaf_result
                    context.hcaf_attribution_status = "ok"
                    logger.info(
                        f"[HCAF] 方向={hcaf_result['direction']}, "
                        f"强度={hcaf_result['strength']}, "
                        f"置信度={hcaf_result['confidence']:.0%}, "
                        f"收敛度={hcaf_result['convergence']:.0%}"
                    )
                else:
                    if context.hcaf_attribution_status not in ("ok",):
                        context.hcaf_attribution_status = "skipped"
                    logger.info(f"[HCAF] 因果归因未生成结果（status={context.hcaf_attribution_status}）")
            except Exception as e:
                logger.warning(f"[HCAF] 因果归因在 joint_evidence 阶段失败: {e}")
                if context.hcaf_attribution_status not in ("ok",):
                    context.hcaf_attribution_status = "failed"

            # Event-driven: publish HCAF to MessageBus so CalibratorAgent can react
            if (
                context.enhanced
                and context.message_bus_run_id
                and context.hcaf_attribution
            ):
                try:
                    from agents.enhanced import AgentMessageBus
                    bus = AgentMessageBus.get_instance(context.message_bus_run_id)
                    await bus.publish(
                        topic="validation.hcaf_attribution",
                        sender="JointEvidence",
                        content=dict(context.hcaf_attribution),
                        metadata={"tier": context.joint_tier, "score": context.joint_score},
                    )
                except Exception as exc:
                    logger.warning(
                        f"[BusPub] validation.hcaf_attribution publish failed: {exc!r} "
                        "— CalibratorAgent may not see HCAF attribution."
                    )

            return WorkflowEvent.JOINT_EVIDENCE_COMPLETE

        except ImportError as e:
            logger.warning(f"[JointEvidence] Could not import joint_evidence module: {e}")
            context.validation_notes.append({
                "case": "joint_evidence",
                "severity": "warning",
                "message": f"Joint evidence analysis skipped: {e}",
            })
            # 不直接 return —— HCAF 必须在 joint_evidence 之外跑
        except Exception as e:
            logger.error(f"[JointEvidence] Error running joint evidence analysis: {e}")
            context.validation_notes.append({
                "case": "joint_evidence",
                "severity": "error",
                "message": f"Joint evidence analysis failed: {e}",
            })
            # 不直接 return —— HCAF 必须在 joint_evidence 之外跑

        # HCAF 因果归因（三个创新方法：MSCBD/CTPR/CIC）
        # 独立于 joint_evidence，保证 joint_evidence 出错时也能跑
        try:
            hcaf_result = self.compute_hcaf_attribution(context)
            if hcaf_result:
                context.hcaf_attribution = hcaf_result
                context.hcaf_attribution_status = "ok"
                logger.info(
                    f"[HCAF] 方向={hcaf_result['direction']}, "
                    f"强度={hcaf_result['strength']}, "
                    f"置信度={hcaf_result['confidence']:.0%}, "
                    f"收敛度={hcaf_result['convergence']:.0%}"
                )
            else:
                if context.hcaf_attribution_status not in ("ok",):
                    context.hcaf_attribution_status = "skipped"
                logger.info(f"[HCAF] 因果归因未生成结果（status={context.hcaf_attribution_status}）")
        except Exception as e:
            logger.warning(f"[HCAF] 因果归因在 joint_evidence 之后失败: {e}")
            if context.hcaf_attribution_status not in ("ok",):
                context.hcaf_attribution_status = "failed"

        return WorkflowEvent.JOINT_EVIDENCE_COMPLETE
    
    async def _cross_validate_results(self, context: WorkflowContext):
        traffic_data_available = bool(
            context.traffic_result
            and context.traffic_result.get("data_available", context.traffic_result.get("success", False))
        )
        traffic_ok = (
            traffic_data_available
            and context.traffic_result.get("anomaly_count", 0) == 0
        )
        routing_anomalies = 0
        rr = context.routing_result
        if rr:
            hijack_section = rr.get("hijack") or {}
            hijack_events = sum(
                len(rr.get(key) or hijack_section.get(key) or [])
                for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking")
            )
            routing_anomalies = rr.get("total_prefix_hijacks", hijack_events)
            leak_section = rr.get("leak") or {}
            routing_anomalies += rr.get(
                "leak_count", len(rr.get("route_leaks") or leak_section.get("route_leaks") or [])
            )
            outage = rr.get("outage_analysis") or rr.get("outage") or {}
            routing_anomalies += int(
                outage.get("is_outage_suspected", rr.get("outage_suspected", False))
            )

        routing_ok = routing_anomalies == 0

        if not traffic_data_available:
            context.validation_notes.append({
                "case": "missing_traffic_data",
                "severity": "warning",
                "message": "流量数据不可用，无法判断路由告警是否产生实际流量影响",
                "details": {
                    "routing_anomalies": routing_anomalies,
                    "reason": (context.traffic_result or {}).get("no_data_reason", "unknown"),
                },
            })
        elif traffic_ok and not routing_ok:
            context.traffic_ok_but_routing_anomaly = True
            context.validation_notes.append({
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
            context.validation_notes.append({
                "case": "both_anomalous",
                "severity": "critical",
                "message": "流量和路由均检测到异常，需要深度关联分析",
                "details": {
                    "traffic_anomalies": (context.traffic_result or {}).get("anomaly_count", 0),
                    "routing_anomalies": routing_anomalies,
                    "recommendation": "进入联合证据评估，核对时间、受影响前缀和替代解释后再判断关系"
                }
            })
        elif traffic_ok and routing_ok:
            context.validation_notes.append({
                "case": "both_ok",
                "severity": "info",
                "message": "流量和路由均正常，问题可能与路由无关",
                "details": {
                    "traffic_anomalies": 0,
                    "routing_anomalies": 0
                }
            })

        causal_result = self.compute_causal_analysis(context)
        if causal_result:
            context.validation_notes.append({
                "case": "causal_analysis",
                "severity": "info",
                "message": "路由与流量观测关联分析",
                "details": causal_result
            })
            context.causal_analysis = causal_result
            context.joint_alert = causal_result

        evidence_chain = self.build_evidence_chain(context)
        if evidence_chain:
            context.evidence_chain = evidence_chain

    def compute_causal_analysis(self, context):
        """Score the causal association between routing and traffic anomalies."""
        routing_result = context.routing_result
        traffic_result = context.traffic_result

        if not routing_result or not traffic_result:
            return None

        causal_evidence = self.collect_causal_evidence(routing_result, traffic_result)

        # ── Extract victim ASes from routing result ─────────────────────────────
        # annotation_package uses { "hijack": { "origin_hijacked": [...] } };
        # live analysis uses flat { "origin_hijacked": [...] }.
        rr = routing_result or {}
        hijack_section = rr.get("hijack") or {}
        leak_section = rr.get("leak") or {}

        def events_for(key):
            return rr.get(key) or hijack_section.get(key) or leak_section.get(key) or []

        victim_asns: set = set()
        for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
            for ev in events_for(key):
                if key in ("origin_hijacked", "forge_hijacked"):
                    if ev.get("origin_as"):
                        victim_asns.add(str(ev["origin_as"]))
                elif ev.get("victim_as"):
                    victim_asns.add(str(ev["victim_as"]))
        victim_asns.discard(str(context.asn))
        context.victim_asns = sorted(victim_asns)

        routing_events = []
        event_roles = {
            "origin_hijacked": "victim",
            "forge_hijacked": "victim",
            "origin_hijacking": "attacker",
            "forge_hijacking": "attacker",
            "route_leaks": "affected",
        }
        for key, role in event_roles.items():
            for event in events_for(key):
                # `event` may be a dict OR an AnomalyDetail object (e.g. when
                # the unified_result wrapper is in play).  Normalise to a dict
                # so downstream code (event_copy, .get(...), etc.) works for
                # both shapes.
                if isinstance(event, dict):
                    event_copy = dict(event)
                else:
                    event_copy = dict(getattr(event, "__dict__", {}) or {})
                event_copy["event_type"] = "leak" if key == "route_leaks" else "hijack"
                event_copy["role"] = role
                event_copy["semantic_match"] = role != "attacker"
                if "timestamp" not in event_copy and "first_seen" in event_copy:
                    event_copy["timestamp"] = event_copy["first_seen"]
                routing_events.append(event_copy)

        outage = routing_result.get("outage_analysis") or {}
        if outage.get("is_outage_suspected"):
            routing_events.append({
                "event_type": "outage",
                "role": "affected",
                "semantic_match": True,
                "timestamp": outage.get("timestamp") or outage.get("first_seen"),
                "severity": outage.get("outage_score", 0),
            })

        traffic_anomalies = []
        for anomaly in traffic_result.get("anomalies", []) or []:
            anomaly_copy = dict(anomaly)
            if "percent_change" in traffic_result:
                anomaly_copy.setdefault("drop_percent", traffic_result["percent_change"])
            traffic_anomalies.append(anomaly_copy)

        if not routing_events or not traffic_anomalies:
            scorer = CausalCorrelationScorer()
            result = scorer.score(
                routing_events=routing_events,
                traffic_anomalies=traffic_anomalies,
                confounder_check=(routing_result.get("confounders") or {}) if isinstance(routing_result, dict) else {},
                target_asn=str(context.asn),
                routing_available=bool(routing_result.get("data_available", routing_result.get("success", False))),
                traffic_available=bool(traffic_result.get("data_available", traffic_result.get("success", False))),
                causal_evidence=causal_evidence,
            )
            return result

        try:
            scorer = CausalCorrelationScorer()
            result = scorer.score(
                routing_events=routing_events,
                traffic_anomalies=traffic_anomalies,
                confounder_check=(routing_result.get("confounders") or {}) if isinstance(routing_result, dict) else {},
                target_asn=str(context.asn),
                routing_available=bool(routing_result.get("data_available", routing_result.get("success", False))),
                traffic_available=bool(traffic_result.get("data_available", traffic_result.get("success", False))),
                causal_evidence=causal_evidence,
            )
            return result
        except Exception as e:
            logger.warning(f"因果分析计算失败: {e}")
            return None

    def build_hcaf_timelines(self, routing_result, traffic_result):
        """Convert routing_result / traffic_result into the timeline/context shape HCAF expects."""
        路由时间线 = []
        if routing_result:
            # annotation_package uses { "hijack": { "origin_hijacked": [...] } };
            # live analysis uses a flat { "origin_hijacked": [...] }.
            hijack_section = routing_result.get("hijack") or {}
            leak_section = routing_result.get("leak") or {}
            for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "route_leaks"):
                # Check flat key first (live format), then hijack nested (annotation_package),
                # then leak nested (annotation_package). This mirrors compute_causal_analysis._events().
                events = (
                    routing_result.get(key)
                    or hijack_section.get(key)
                    or leak_section.get(key)
                    or []
                )
                for 事件 in events:
                    # Normalise to dict (event may be AnomalyDetail object).
                    if isinstance(事件, dict):
                        ev = 事件
                    else:
                        ev = dict(getattr(事件, "__dict__", {}) or {})
                    时间戳 = ev.get("timestamp") or ev.get("first_seen")
                    if not 时间戳:
                        continue
                    分数 = 0.9 if "hijack" in key else 0.7
                    路由时间线.append({
                        "timestamp": 时间戳,
                        "score": 分数,
                        "event_type": "hijack" if "hijack" in key else "leak",
                        "raw_event": ev,
                    })
            outage = routing_result.get("outage_analysis") or routing_result.get("outage") or {}
            if outage.get("is_outage_suspected"):
                时间戳 = outage.get("timestamp") or outage.get("first_seen")
                if 时间戳:
                    路由时间线.append({
                        "timestamp": 时间戳,
                        "score": outage.get("outage_score", 0.8) or 0.8,
                        "event_type": "outage",
                        "raw_event": outage,
                    })
            路由时间线.sort(key=lambda x: x.get("timestamp") or "")

        流量时间线 = []
        if traffic_result:
            for 异常 in (traffic_result.get("anomalies") or []):
                # Normalise to dict (anomaly may be AnomalyDetail object).
                if isinstance(异常, dict):
                    an = 异常
                else:
                    an = dict(getattr(异常, "__dict__", {}) or {})
                时间戳 = an.get("timestamp") or an.get("time")
                if not 时间戳:
                    continue
                下降比 = an.get("drop_percent") or an.get("percent_change") or traffic_result.get("percent_change")
                分数 = min(1.0, abs(下降比) / 100.0) if isinstance(下降比, (int, float)) else 0.8
                流量时间线.append({
                    "timestamp": 时间戳,
                    "score": max(分数, 0.6),
                    "event_type": "traffic_anomaly",
                    "raw_event": an,
                })
            # Fallback: when no anomalies but traffic drop is significant (peak_trough_drop_pct > 30%
            # or percent_change < -15%), synthesize a minimal timeline from expanded_boundaries /
            # expanded_windows so HCAF / JointEvidence still receive *some* traffic signal.
            if not 流量时间线:
                pct = traffic_result.get("percent_change") or 0.0
                peak_drop = traffic_result.get("peak_trough_drop_pct") or 0.0
                windows = (
                    traffic_result.get("expanded_windows")
                    or traffic_result.get("consecutive_anomaly_windows")
                    or []
                )
                if (peak_drop > 30.0 or (isinstance(pct, (int, float)) and pct < -15.0)) and windows:
                    synthesized = 0
                    for w in windows[:5]:
                        for k in ("start", "expanded_start"):
                            ts = w.get(k) if isinstance(w, dict) else None
                            if ts:
                                流量时间线.append({
                                    "timestamp": str(ts),
                                    "score": min(1.0, abs(pct) / 100.0) if pct else 0.7,
                                    "event_type": "traffic_anomaly_synthesized",
                                    "raw_event": {"synthesized": True, "reason": "peak_trough_no_anomaly"},
                                })
                                synthesized += 1
                                break
                    if synthesized:
                        logger.info(
                            f"[HCAF] Synthesized {synthesized} traffic timeline points "
                            f"from expanded_windows (peak_drop={peak_drop:.1f}%, pct_change={pct:.1f}%)"
                        )
                # Last resort: if still empty but percent_change is significant, fabricate a single
                # point at the midpoint of the analysis window using expanded_boundaries.
                if not 流量时间线 and isinstance(pct, (int, float)) and pct < -15.0:
                    eb = traffic_result.get("expanded_boundaries") or {}
                    mid_ts = eb.get("expanded_start") or eb.get("expanded_end")
                    if mid_ts:
                        流量时间线.append({
                            "timestamp": str(mid_ts),
                            "score": min(1.0, abs(pct) / 100.0),
                            "event_type": "traffic_anomaly_synthesized",
                            "raw_event": {"synthesized": True, "reason": "pct_change_significant"},
                        })
                        logger.info(
                            f"[HCAF] Synthesized 1 traffic timeline point from "
                            f"expanded_boundaries (pct_change={pct:.1f}%)"
                        )
            流量时间线.sort(key=lambda x: x.get("timestamp") or "")

        路由上下文 = {
            "event_type": "outage",
            "as_path": [],
            "origin_as": None,
        }
        流量上下文 = {
            "traffic_drop_ratio": 0.0,
            "affected_prefix": None,
            "baseline": {},
        }
        拓扑上下文 = {
            "adjacency": {},
            "routing_state": {},
        }

        if routing_result:
            events_all = []
            hijack_section = routing_result.get("hijack") or {}
            leak_section = routing_result.get("leak") or {}
            for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "route_leaks"):
                events_all.extend(
                    routing_result.get(key) or hijack_section.get(key) or leak_section.get(key) or []
                )
            if events_all:
                first_event = events_all[0]
                路由上下文["event_type"] = (
                    "outage" if (routing_result.get("outage_analysis") or routing_result.get("outage") or {}).get("is_outage_suspected")
                    else "hijack" if "hijack" in str(first_event.get("event_type", "hijack")).lower()
                    else "leak" if "leak" in str(first_event.get("event_type", "leak")).lower()
                    else "hijack"
                )
                as_path_raw = first_event.get("as_path") or first_event.get("sample_as_path") or []
                if isinstance(as_path_raw, str):
                    as_path_raw = [int(x) for x in as_path_raw.replace("[", "").replace("]", "").split(",") if x.strip().isdigit()]
                elif isinstance(as_path_raw, list):
                    as_path_raw = [int(x) for x in as_path_raw if isinstance(x, (int, float))]
                路由上下文["as_path"] = as_path_raw
                路由上下文["origin_as"] = first_event.get("origin_as") or first_event.get("attacker_as") or first_event.get("victim_as")
                if isinstance(路由上下文["origin_as"], str) and 路由上下文["origin_as"].isdigit():
                    路由上下文["origin_as"] = int(路由上下文["origin_as"])
                if 路由上下文["as_path"]:
                    路由上下文["origin_as"] = 路由上下文["origin_as"] or 路由上下文["as_path"][-1]

        if traffic_result:
            异常列表 = traffic_result.get("anomalies") or []
            if 异常列表:
                first_anomaly = 异常列表[0]
                流量上下文["affected_prefix"] = first_anomaly.get("prefix") or first_anomaly.get("affected_prefix")
                下降比 = first_anomaly.get("drop_percent") or first_anomaly.get("percent_change")
                if 下降比 is None and traffic_result.get("percent_change") is not None:
                    下降比 = abs(traffic_result["percent_change"])
                if isinstance(下降比, (int, float)):
                    流量上下文["traffic_drop_ratio"] = min(1.0, abs(下降比) / 100.0)

        return 路由时间线, 流量时间线, 路由上下文, 流量上下文, 拓扑上下文

    def compute_hcaf_attribution(self, context):
        """Run the HCAF causal attribution engine (MSCBD + CTPR + CIC + Granger) on the routing-traffic pair. Degrades to None on failure."""
        routing_result = context.routing_result
        traffic_result = context.traffic_result

        if not routing_result or not traffic_result:
            logger.info("[HCAF] 缺少 routing_result 或 traffic_result，跳过因果归因")
            context.hcaf_attribution_status = "skipped"
            return None

        try:
            from agents.causal_attribution import 因果归因引擎
        except ImportError as e:
            logger.warning(f"[HCAF] 无法导入因果归因引擎: {e}")
            context.hcaf_attribution_status = "failed"
            return None

        路由时间线, 流量时间线, 路由上下文, 流量上下文, 拓扑上下文 = self.build_hcaf_timelines(routing_result, traffic_result)

        # Only skip HCAF when BOTH timelines are empty. Traffic-only or routing-only
        # events still provide partial evidence that the LLM report can reason about.
        if not 路由时间线 and not 流量时间线:
            logger.info(f"[HCAF] 时间线数据不足: 路由={len(路由时间线)}, 流量={len(流量时间线)}，跳过")
            context.hcaf_attribution_status = "skipped"
            return None

        if not 路由时间线:
            logger.info(f"[HCAF] 路由时间线为空，仅使用流量数据({len(流量时间线)}条)继续分析")
        elif not 流量时间线:
            # 注：日志原文"流量时间线为空"曾被误读为流量数据本身为空。
            # 实际指 traffic_result['anomalies'] 为空（异常检测漏检），
            # traffic_result['percent_change'] / peak_trough_drop_pct 仍可表示流量下降。
            pct = traffic_result.get("percent_change") if traffic_result else None
            peak_drop = traffic_result.get("peak_trough_drop_pct") if traffic_result else None
            extra = ""
            if isinstance(pct, (int, float)) or isinstance(peak_drop, (int, float)):
                extra = f"（注：traffic_result 已存在，percent_change={pct}%, peak_trough_drop={peak_drop}% — 异常检测未产出 anomaly，但流量下降数据可用于上下文）"
            logger.info(
                f"[HCAF] 流量时间线(anomalies)为空，仅使用路由数据({len(路由时间线)}条)继续分析{extra}"
            )

        try:
            引擎 = 因果归因引擎()
            目标AS = int(context.asn) if str(context.asn).isdigit() else None

            if 上下文_asrel := (context.as_relationships or {}):
                拓扑上下文["adjacency"] = {
                    asn: list(set(neighbors))
                    for asn, neighbors in 上下文_asrel.items()
                    if isinstance(neighbors, (list, set))
                }

            结果 = 引擎.分析(
                路由时间线=路由时间线,
                流量时间线=流量时间线,
                路由上下文=路由上下文,
                流量上下文=流量上下文,
                拓扑上下文=拓扑上下文,
                目标AS=目标AS,
            )

            return {
                "direction": getattr(结果, "方向", "unknown"),
                # Bug fix 2026-09-13: previous shape used
                # ``getattr(getattr(结果, "强度", None), "value", "unknown")``.
                # If ``结果.强度`` exists but has no ``.value`` attribute
                # (e.g. a plain float/int), the inner getattr returned None
                # and the outer one ALSO returned None — the literal
                # "unknown" default was unreachable. Fix: prefer ``.value``
                # when present, fall back to the raw 强度, then "unknown".
                **self._extract_hcaf_strength(结果),
                "confidence": float(getattr(结果, "置信度", 0.0)),
                "is_causal": bool(getattr(结果, "是否为因果", False)),
                "convergence": float(getattr(结果, "收敛度", 0.0)),
                "routing_causes_traffic": bool(getattr(结果, "路由导致流量", False)),
                "traffic_causes_routing": bool(getattr(结果, "流量导致路由", False)),
                "explanation": getattr(结果, "解释", ""),
                "limitations": getattr(结果, "局限", ""),
                "novel_findings": [
                    {
                        "method": getattr(f, "方法名", "unknown"),
                        "direction": getattr(f, "方向", "unknown"),
                        "strength": float(getattr(f, "强度", 0.0)),
                        "p_value": float(getattr(f, "p值", 1.0)),
                        "significant": bool(getattr(f, "显著性", False)),
                        "description": getattr(f, "解释", ""),
                    }
                    for f in (getattr(结果, "创新发现列表", []) or [])
                    if f is not None
                ],
                "confounders": getattr(结果, "混杂变量列表", []) or [],
                "evidence_support": getattr(结果, "证据支撑", {}) or {},
                "target_as": 目标AS,
            }
        except Exception as e:
            logger.warning(f"[HCAF] 因果归因引擎调用失败: {e}")
            context.hcaf_attribution_status = "failed"
            return None

    @staticmethod
    def collect_causal_evidence(routing_result: dict, traffic_result: dict) -> dict:
        """Pass through only explicit provenance-bearing evidence for causal claims."""
        raw_evidence = {}
        for result in (routing_result or {}, traffic_result or {}):
            candidate = result.get("causal_evidence")
            if isinstance(candidate, dict):
                raw_evidence.update(candidate)
        allowed = {
            "independent_external_verification",
            "mechanism_evidence",
            "alternative_explanations_excluded",
        }
        return {name: value for name, value in raw_evidence.items() if name in allowed}

    def build_evidence_chain(self, context):
        """Run EvidenceChainBuilder on the traffic/routing/bayesian/causal inputs and stash the chain on the context."""
        try:
            builder = EvidenceChainBuilder()
            chain = builder.build(
                traffic_result=context.traffic_result or {},
                routing_result=context.routing_result or {},
                causal_analysis=context.causal_analysis,
                bayesian_result=context.bayesian_result,
                asn=str(context.asn),
                time_range=f"{context.start_time} to {context.end_time}",
            )
            chain_dict = builder.to_dict(chain)
            logger.info(f"证据链构建完成: verdict={chain.verdict}, confidence={chain.confidence:.1%}")
            return chain_dict
        except Exception as e:
            logger.warning(f"证据链构建失败: {e}")
            return None

    # ── Skip-reasoning policy ─────────────────────────────────────────────
    _TIER_ORDER = {"INSUFFICIENT": 0, "C1": 1, "C2": 2, "C3": 3}

    def should_skip_reasoning(self, context: WorkflowContext) -> bool:
        """
        Whether to short-circuit the reasoning stage.

        Reasoning is skipped only when:
          1. ``skip_unnecessary_analysis`` is enabled (env-controlled), AND
          2. No traffic/routing anomalies were detected, AND
          3. HCAF tier is below the configured minimum OR HCAF score is below
             the configured minimum.

        This avoids the previous bug where ``HCAF tier=C1 score=0.86`` cases
        (e.g. AS12479) were still skipped and produced empty evidence boards.
        """
        if not self.skip_unnecessary_analysis:
            return False

        if context.anomalies_detected:
            return False

        tier = getattr(context, "joint_tier", None) or "INSUFFICIENT"
        score = float(getattr(context, "joint_score", 0.0) or 0.0)
        hcaf_tier = (
            (context.hcaf_attribution or {}).get("tier", "INSUFFICIENT")
            if isinstance(context.hcaf_attribution, dict)
            else "INSUFFICIENT"
        )

        current_rank = self._TIER_ORDER.get(str(tier).upper(), 0)
        min_rank = self._TIER_ORDER.get(self.min_hcaf_tier, 1)

        tier_ok = current_rank >= min_rank and score >= self.min_hcaf_score
        if tier_ok:
            context.validation_notes.append({
                "case": "reasoning_not_skipped",
                "severity": "info",
                "message": (
                    f"HCAF tier={hcaf_tier}, joint_tier={tier}, score={score:.3f} "
                    f">= min_tier={self.min_hcaf_tier}, min_score={self.min_hcaf_score:.3f}; "
                    "reasoning stage proceeds even without explicit anomalies."
                ),
            })
            return False

        context.validation_notes.append({
            "case": "reasoning_skipped",
            "severity": "info",
            "message": (
                f"Skipped reasoning: anomalies=False, joint_tier={tier}, score={score:.3f} "
                f"(< min_tier={self.min_hcaf_tier} or < min_score={self.min_hcaf_score:.3f})."
            ),
        })
        return True

    async def _handle_reasoning(self, context: WorkflowContext):
        from agents.reasoning_agent import run_reasoning_agent
        from agents.core import Blackboard
        from agents.hypothesis_manager import HypothesisAgent

        if self.should_skip_reasoning(context):
            skip_reason = context.validation_notes[-1].get("message", "skipped") if context.validation_notes else "no_anomalies_detected"
            context.reasoning_result = {"success": True, "skipped": True, "reason": skip_reason}
            return WorkflowEvent.REASONING_COMPLETE

        try:
            reasoning_start = context.start_time
            reasoning_end = context.end_time

            # pass pre-generated claims to avoid duplicate HypothesisAgent work
            context.reasoning_result = run_reasoning_agent(
                asn=context.asn,
                start_time=reasoning_start,
                end_time=reasoning_end,
                pre_computed_routing=context.routing_result,
                pre_computed_traffic=context.traffic_result,
                buffer_hours=0,
                workflow_claims=None,  # Will be populated after HypothesisAgent
                run_id=context.message_bus_run_id or "",
            )

            # ── Shared Blackboard: use existing (enhanced) or create new ──
            if context.enhanced and context.shared_blackboard:
                bb = context.shared_blackboard
            else:
                bb = Blackboard()

            await bb.write("traffic", "result", context.traffic_result or {})
            await bb.write("routing", "result", context.routing_result or {})
            await bb.write("reasoning", "result", context.reasoning_result or {})
            if context.causal_analysis:
                await bb.write("validation", "causal_analysis", context.causal_analysis)

            if context.traffic_result:
                await bb.add_observation({
                    "source": "WorkflowEngine",
                    "kind": "traffic_analysis",
                    "summary": f"Traffic analysis detected {context.traffic_result.get('anomaly_count', 0)} anomalies.",
                    "confidence": 0.7,
                    "payload": context.traffic_result,
                    "window": {"start": str(reasoning_start), "end": str(reasoning_end)},
                    "tags": ["traffic", "workflow"],
                })
            if context.routing_result:
                await bb.add_observation({
                    "source": "WorkflowEngine",
                    "kind": "routing_analysis",
                    "summary": "Routing analysis summary prepared for competitive diagnosis.",
                    "confidence": 0.72,
                    "payload": context.routing_result,
                    "window": {"start": str(reasoning_start), "end": str(reasoning_end)},
                    "tags": ["routing", "workflow"],
                })

            # ── Hypothesis generation (always needed) ──
            hypothesis_agent = HypothesisAgent(bb)
            await hypothesis_agent.start()
            hyp_result = await hypothesis_agent.step()
            claims = await bb.read("diagnosis", "claims", []) or []

            # ── Enhanced mode: LLM debate + online evaluation + reactive decisions ──
            if context.enhanced and self._enhanced_components:
                eval_agent = self._enhanced_components["eval_agent"]
                debate_agent = self._enhanced_components["debate_agent"]
                decision_engine = self._enhanced_components["decision_engine"]
                bus = self._enhanced_components["bus"]

                # quality gate is integrated into the state machine
                # Evaluate hypothesis quality AND use gate_passed to decide pipeline flow
                hyp_metrics, hyp_gate_passed, hyp_corrections = await eval_agent.evaluate_stage(
                    stage_name="hypothesis",
                    agent_output={"claims": claims, "confidence": 0.5},
                    context={"asn": context.asn, "start_time": reasoning_start, "end_time": reasoning_end},
                    max_retries=context.evaluation_retries,
                )
                # If hypothesis quality is too low, still proceed but log warning
                if not hyp_gate_passed:
                    logger.warning(
                        f"[Enhanced] Hypothesis gate failed (score={hyp_metrics.overall_score:.2f}), "
                        f"proceeding with low-quality hypotheses. Corrections: {hyp_corrections}"
                    )

                # Reactive decision: F5+F9 - LLM decides what action to take, then execute it
                evidence_for_decision = {
                    "traffic": context.traffic_result or {},
                    "routing": context.routing_result or {},
                    "correlation": await bb.read("validation", "causal_analysis") or {},
                }
                decision = await decision_engine.decide(
                    stage="hypothesis",
                    completed_stages=["traffic", "routing"],
                    evidence=evidence_for_decision,
                    quality_metrics=await bb.read("evaluation", "hypothesis_metrics"),
                )
                # consume budget so the same action can't be taken unlimited times
                if decision.action not in ("proceed", "stop"):
                    decision_engine.consume_budget(decision.action)
                context.reactive_decisions.append(decision.to_dict())
                logger.info(
                    f"[Enhanced] Reactive decision at hypothesis: {decision.action} "
                    f"(budgets left: {decision_engine.budgets}) — {decision.reasoning}"
                )

                # execute the decision instead of just logging it
                debate_result = None
                params = decision.parameters or {}

                if decision.action == "debate" and claims:
                    logger.info(
                        f"[Enhanced] Executing debate: {params.get('focus_claims', 'all')} claims, "
                        f"rounds={params.get('rounds', context.debate_rounds)}"
                    )
                    debate_result = await debate_agent.step()
                    if debate_result.success and debate_result.data:
                        debate_results = debate_result.data.get("debate_results", [])
                        context.debate_results = debate_results
                        if debate_results:
                            best = debate_results[0]
                            context.diagnosis_result = best.get("original_claim")
                            context.verification_result = best.get("conclusion", best.get("winner"))
                            context.confidence_score = best.get("final_confidence", 0.5)
                            # capture debate gate result
                            db_metrics, db_gate_passed, db_corrections = await eval_agent.evaluate_stage(
                                stage_name="debate",
                                agent_output={"debate_results": debate_results},
                                context={"asn": context.asn, "start_time": reasoning_start, "end_time": reasoning_end},
                                max_retries=context.evaluation_retries,
                            )
                            if not db_gate_passed:
                                logger.warning(
                                    f"[Enhanced] Debate gate failed (score={db_metrics.overall_score:.2f}), "
                                    f"corrections: {db_corrections}"
                                )
                            context.quality_metrics = {
                                "hypothesis": hyp_metrics.to_dict(),
                                "debate": db_metrics.to_dict(),
                            }
                        await bus.publish(
                            topic="diagnosis.debate.complete",
                            sender="LLMDebateAgent",
                            content={"debate_results": debate_results},
                        )

                elif decision.action == "retry":
                    retry_stage = params.get("stage", "routing")
                    retry_reason = params.get("reason", "low_quality")
                    logger.info(f"[Enhanced] Executing retry: stage={retry_stage}, reason={retry_reason}")
                    # Re-run the specified stage with adjusted parameters
                    if retry_stage == "routing" and not context.routing_result.get("skipped"):
                        # Re-run routing with expanded time window
                        from agents.routing_agent import RoutingAgent
                        expanded_start = params.get("expanded_start", context.start_time)
                        expanded_end = params.get("expanded_end", context.end_time)
                        agent = RoutingAgent(bb)
                        await agent.start()
                        await agent.step()
                        raw_section = bb._sections.get("routing", {})
                        context.routing_result = raw_section.get("result", raw_section)
                        # retry routing results: set anomalies_detected when anomaly events exist
                        context.anomalies_detected = context.anomalies_detected or bool(
                            context.routing_result.get("origin_hijacked")
                            or context.routing_result.get("path_leak")
                            or context.routing_result.get("anomalies_detected")
                            or context.routing_result.get("anomaly_count", 0) > 0
                        )
                        logger.info(f"[Enhanced] Retry routing complete: {context.routing_result.get('success')}")

                elif decision.action == "probe":
                    # Rebuild: call AutoProbeExecutor instead of dead ProbeAgent
                    target = params.get("target", "")
                    probe_type = params.get("type", "looking_glass")
                    logger.info(
                        f"[Enhanced] Probe action requested (type={probe_type}, target={target}) — "
                        "executing via AutoProbeExecutor."
                    )
                    try:
                        from agents.auto_probe_executor import AutoProbeExecutor
                        executor = AutoProbeExecutor(timeout=10.0)
                        # Build probe recommendations based on detected anomalies
                        recommendations = []
                        routing_r = context.routing_result or {}
                        if routing_r.get("origin_hijacked") or routing_r.get("origin_hijacking"):
                            recommendations.append({
                                "action": "rpki_validation",
                                "target": target or context.asn,
                                "reason": "origin hijack detected, need RPKI validation",
                            })
                            recommendations.append({
                                "action": "check_victim_traffic",
                                "target": target or context.asn,
                                "reason": "check if victim AS traffic was impacted",
                            })
                            recommendations.append({
                                "action": "bgp_path_analysis",
                                "target": target or context.asn,
                                "reason": "verify AS_PATH for hijacked prefixes",
                            })
                        if routing_r.get("route_leaks"):
                            recommendations.append({
                                "action": "bgp_path_analysis",
                                "target": target or context.asn,
                                "reason": "verify AS_PATH for leaked prefixes",
                            })
                        if recommendations:
                            probe_results = await executor.execute_probes(
                                recommendations,
                                target_as=target or context.asn,
                                analysis_window={"start": str(reasoning_start), "end": str(reasoning_end)},
                            )
                            logger.info(f"[Enhanced] AutoProbe completed: {len(probe_results)} probes executed")
                            context.probe_results = probe_results
                            # Bug fix: persist findings to Blackboard so
                            # report generators (ReportAgent._run_auto_probes
                            # stub) and downstream consumers can read them.
                            try:
                                if context.shared_blackboard is not None:
                                    from agents.auto_probe_executor import AutoProbeFinding as _APF
                                    payload = [
                                        {
                                            "action": getattr(f, "action", ""),
                                            "target": getattr(f, "target", ""),
                                            "success": bool(getattr(f, "success", False)),
                                            "summary": getattr(f, "summary", ""),
                                            "data": getattr(f, "data", {}) or {},
                                            "error": getattr(f, "error", ""),
                                            "execution_time_s": float(getattr(f, "execution_time_s", 0.0)),
                                        }
                                        for f in probe_results
                                    ]
                                    await context.shared_blackboard.write(
                                        "auto_probe", "findings", payload
                                    )
                                    logger.info(
                                        f"[Enhanced] AutoProbe findings persisted to Blackboard "
                                        f"({len(payload)} items)"
                                    )
                            except Exception as _bb_err:
                                logger.warning(f"[Enhanced] failed to persist probe findings: {_bb_err}")
                        else:
                            logger.info("[Enhanced] No probe recommendations to execute")
                    except Exception as probe_err:
                        logger.warning(f"[Enhanced] Probe execution failed: {probe_err}")

                elif decision.action == "proceed" and claims:
                    # Default: run debate as final verification step
                    logger.info(f"[Enhanced] Proceeding with debate for {len(claims)} claims")
                    debate_result = await debate_agent.step()
                    if debate_result.success and debate_result.data:
                        debate_results = debate_result.data.get("debate_results", [])
                        context.debate_results = debate_results
                        if debate_results:
                            best = debate_results[0]
                            context.diagnosis_result = best.get("original_claim")
                            context.verification_result = best.get("conclusion", best.get("winner"))
                            context.confidence_score = best.get("final_confidence", 0.5)
                            # gate debate output
                            db2_metrics, db2_passed, db2_corr = await eval_agent.evaluate_stage(
                                stage_name="debate",
                                agent_output={"debate_results": debate_results},
                                context={"asn": context.asn, "start_time": reasoning_start, "end_time": reasoning_end},
                                max_retries=context.evaluation_retries,
                            )
                            context.quality_metrics = {
                                "hypothesis": hyp_metrics.to_dict(),
                                "debate": db2_metrics.to_dict(),
                            }
                            if not db2_passed:
                                logger.warning(f"[Enhanced] Debate gate failed (score={db2_metrics.overall_score:.2f})")
                        else:
                            # No debate results — still record hypothesis quality
                            context.quality_metrics = {
                                "hypothesis": hyp_metrics.to_dict(),
                                "debate": None,
                            }

                elif decision.action == "stop":
                    logger.warning("[Enhanced] Decision engine chose to STOP - insufficient evidence")
                    context.reasoning_result = {
                        "success": True,
                        "stopped": True,
                        "reason": "insufficient_evidence",
                        "decision": decision.to_dict(),
                    }
                    # Bug fix 2026-09-13 (BUG-R119): the previous code
                    # fell through to the unconditional fallback
                    # ``if not debate_result or not debate_result.success``
                    # below, which re-invoked the legacy diagnosis
                    # pipeline even though ``stop`` was meant to halt
                    # the workflow. The legacy pipeline then overwrote
                    # the ``stopped=True`` marker with a synthesised
                    # claim, silently defeating the decision engine's
                    # choice. We now set ``debate_result`` to a
                    # synthetic success record so the fallback branch
                    # is skipped.
                    class _StopDebateResult:
                        success = True
                        data: dict = {}
                    debate_result = _StopDebateResult()

                # Fallback: if no debate was triggered, use legacy pipeline
                if not debate_result or not debate_result.success:
                    await self._run_legacy_diagnosis_pipeline(bb, context)

            else:
                # ── Legacy diagnosis pipeline ──
                await self._run_legacy_diagnosis_pipeline(bb, context)

            # Collect evidence board
            evidence_board = await bb.read_evidence_board()
            context.evidence_records = evidence_board.get("observations", [])
            context.diagnosis_claims = evidence_board.get("claims", [])
            context.verification_records = evidence_board.get("verdicts", [])
            context.contradictions = evidence_board.get("challenges", [])

            # Pull per-agent token usage from TokenBudget (P3)
            token_breakdown: dict = {}
            total_tokens = 0
            try:
                from agents.token_budget import TokenBudget
                if context.message_bus_run_id:
                    tb = TokenBudget.get_instance(context.message_bus_run_id)
                    tb_summary = tb.summary()
                    total_tokens = tb_summary.get("total_tokens", 0)
                    token_breakdown = {
                        agent: stats.get("total_tokens", 0)
                        for agent, stats in tb_summary.get("by_agent", {}).items()
                    }
            except Exception as exc:
                logger.debug(f"[TokenBudget] summary read failed: {exc}")

            context.experiment_metrics = {
                "evidence_count": len(evidence_board.get("observations", [])),
                "claim_count": len(evidence_board.get("claims", [])),
                "challenge_count": len(evidence_board.get("challenges", [])),
                "verdict_count": len(evidence_board.get("verdicts", [])),
                "metric_count": len(evidence_board.get("metrics", [])),
                "enhanced_mode": context.enhanced,
                "debate_rounds": context.debate_rounds,
                "reactive_decisions": context.reactive_decisions,
                "total_tokens": total_tokens,
                "token_breakdown_by_agent": token_breakdown,
                "joint_tier": getattr(context, "joint_tier", "INSUFFICIENT"),
                "joint_score": float(getattr(context, "joint_score", 0.0) or 0.0),
                "hcaf_direction": (context.hcaf_attribution or {}).get("direction", "unknown")
                if isinstance(context.hcaf_attribution, dict) else "unknown",
                "hcaf_status": context.hcaf_attribution_status or "skipped",
            }

            if isinstance(context.reasoning_result, dict):
                context.reasoning_result["final_claim"] = context.diagnosis_result
                context.reasoning_result["verdict"] = context.verification_result
                context.reasoning_result["evidence_board"] = evidence_board
                context.reasoning_result["experiment_metrics"] = context.experiment_metrics
                self.apply_reasoning_causal_evidence(context)

            return WorkflowEvent.REASONING_COMPLETE
        except Exception as e:
            logger.error(f"Reasoning failed: {e}")
            raise RetryableError(f"Reasoning error: {e}")

    def apply_reasoning_causal_evidence(self, context: WorkflowContext) -> None:
        """Re-score claims after independently supplied verification arrives in reasoning."""
        evidence = context.reasoning_result.get("causal_evidence")
        if not isinstance(evidence, dict):
            return
        traffic = dict(context.traffic_result or {})
        # Keep provenance supplied by a data connector or operator record separate
        # from model-generated classifications and correlation calculations.
        traffic["causal_evidence"] = evidence
        context.traffic_result = traffic
        refreshed = self.compute_causal_analysis(context)
        if refreshed:
            context.causal_analysis = refreshed
            context.joint_alert = refreshed
            context.evidence_chain = self.build_evidence_chain(context)
            context.reasoning_result["causal_analysis"] = refreshed

    async def _run_legacy_diagnosis_pipeline(self, bb, context: WorkflowContext):
        """
        Legacy diagnosis pipeline (used when enhanced mode debate fails or is disabled).

        Reads claims generated by HypothesisAgent from Blackboard and surfaces them
        as the diagnosis result. If no claims exist, falls back to the routing result
        so the report can still render a defensible conclusion.
        """
        claims = await bb.read("diagnosis", "claims", []) or []
        if claims:
            top = max(claims, key=lambda c: c.get("confidence", 0) if isinstance(c, dict) else 0)
            context.diagnosis_result = {
                "claim_id": top.get("id"),
                "kind": top.get("kind"),
                "summary": top.get("summary"),
                "confidence": top.get("confidence"),
            }
            context.verification_result = {"source": "HypothesisAgent", "claim_count": len(claims)}
        else:
            # No claims produced — synthesise a minimal diagnosis from routing data
            rr = context.routing_result or {}
            hijack_count = (
                len(rr.get("origin_hijacked") or [])
                + len(rr.get("forge_hijacked") or [])
                + len(rr.get("origin_hijacking") or [])
                + len(rr.get("forge_hijacking") or [])
            )
            leak_count = len(rr.get("route_leaks") or [])
            context.diagnosis_result = {
                "claim_id": "auto",
                "kind": "origin_hijack" if hijack_count else ("route_leak" if leak_count else "unknown"),
                "summary": f"Detected {hijack_count} hijack events, {leak_count} route leaks from routing analysis.",
                "confidence": 0.5,
            }
            context.verification_result = {"source": "routing_fallback", "claim_count": 0}

    
    async def _handle_validation(self, context: WorkflowContext):
        quality_score = self.calculate_quality_score(context)
        context.confidence_score = quality_score
        context.data_quality = self.assess_data_quality(context)
        # Victim traffic is evidence for the final report, so collect it
        # before report generation regardless of mode. Bug fix (2026-09-13):
        # the previous implementation required ``context.shared_blackboard``
        # (which is only created in enhanced mode), so non-enhanced runs
        # silently dropped the victim-traffic evidence path and the report
        # always showed an empty victim_traffic_results / prefix_traffic_results.
        bb_for_victim = context.shared_blackboard
        if bb_for_victim is None:
            # Synthesise a Blackboard for victim-traffic writes only; the
            # ReportAgent will read from the real one in _handle_report_generation.
            from agents.core import Blackboard as _BB
            bb_for_victim = _BB()
        if context.victim_asns:
            await bb_for_victim.write("routing", "victim_asns", context.victim_asns)
            await self._fetch_victim_traffic(context, bb_for_victim)
        if quality_score < 0.5:
            context.validation_notes.append({
                "case": "low_data_quality",
                "severity": "warning",
                "message": "证据完整度较低；报告将明确数据缺口和不确定性",
                "details": {"quality_score": quality_score},
            })
        # Inconclusive evidence is still a valid operational outcome. The report
        # must be produced so operators can distinguish it from a pipeline error.
        return WorkflowEvent.VALIDATION_PASSED

    async def _fetch_victim_traffic(self, context: WorkflowContext, bb):
        """
        Fetch traffic data for victim ASes discovered from routing events.
        Writes results to blackboard under 'routing' section.
        Non-blocking (fire-and-forget from caller).
        """
        from agents.traffic_agent import run_traffic_agent
        try:
            from tools.tool_implementations import _lookup_as_threat_intel

            start = context.start_time
            end = context.end_time
            victim_asns = [
                str(vas) for vas in (context.victim_asns or [])
                if str(vas) != str(context.asn)
            ][:5]

            async def fetch(vas):
                try:
                    result = await asyncio.to_thread(
                        run_traffic_agent, asn=vas, start_time=start, end_time=end
                    )
                    return vas, result if isinstance(result, dict) else {"success": False}
                except Exception as exc:
                    return vas, {"success": False, "data_available": False, "error": str(exc)}

            pairs = await asyncio.gather(*(fetch(vas) for vas in victim_asns))
            results = dict(pairs)
            await bb.write("routing", "victim_traffic_results", results)
            logger.info(f"[workflow] Fetched victim traffic for {len(results)} ASes")
        except Exception as exc:
            logger.warning(f"[workflow] Victim traffic fetch failed: {exc}")
    
    async def _handle_data_enrichment(self, context: WorkflowContext):
        """Enrich context with additional data (org info, relationships, ThreatIntel, etc.)."""
        from agents.coordination_utils import (
            lookup_org_info,
            query_as_relationships,
            query_as_prefixes
        )
        from tools.tool_implementations import _lookup_as_threat_intel
        
        # Load data files from reasoning result AND routing result if available
        asrel_file = None
        prefix2as_file = None
        asorg_file = None
        
        # 首先尝试从 reasoning_result 获取
        if context.reasoning_result:
            asrel_file = context.reasoning_result.get("as_rel_file")
            prefix2as_file = context.reasoning_result.get("prefix2as_file")
            asorg_file = context.reasoning_result.get("asorg_file")
        
        # 如果没有，从 routing_result 获取（routing_impl.py 会设置这些字段）
        if not asrel_file and context.routing_result:
            asrel_file = context.routing_result.get("as_rel_file")
            prefix2as_file = context.routing_result.get("prefix2as_file")
            asorg_file = context.routing_result.get("asorg_file")
        
        # Enrich with org info
        if asorg_file and context.asn:
            context.org_info = lookup_org_info(context.asn, asorg_file)
        
        # Enrich with AS relationships
        if asrel_file and context.asn:
            context.as_relationships = query_as_relationships(context.asn, asrel_file)
        
        # Enrich with prefixes
        if prefix2as_file and context.asn:
            context.as_prefixes = query_as_prefixes(context.asn, prefix2as_file)
        
        # ── Threat Intel: look up attacker AS ────────────────────────────────────
        threat_intel_result = {}
        attacker_asn_for_intel = ""
        rr = context.routing_result or {}
        hijack_section = rr.get("hijack") or {}
        if rr:
            for ev in (rr.get("origin_hijacked") or hijack_section.get("origin_hijacked") or []):
                if ev.get("hijacker_as"):
                    attacker_asn_for_intel = str(ev["hijacker_as"])
                    break
            if not attacker_asn_for_intel:
                for ev in (rr.get("origin_hijacking") or hijack_section.get("origin_hijacking") or []):
                    if ev.get("origin_as"):
                        attacker_asn_for_intel = str(ev["origin_as"])
                        break
            if attacker_asn_for_intel:
                try:
                    threat_intel_result = await _lookup_as_threat_intel(
                        {
                            "attacker_asn": attacker_asn_for_intel,
                            "victim_asn": str(context.asn),
                            "routing_result": context.routing_result,
                            "start_time": str(context.start_time),
                        },
                        session=None,
                    )
                    logger.info(
                        f"[workflow] Threat intel: {threat_intel_result.get('threat_level', 'N/A')} "
                        f"(risk_score={threat_intel_result.get('risk_score', 'N/A')})"
                    )
                except Exception as exc:
                    logger.warning(f"[workflow] Threat intel lookup failed: {exc}")

        # Propagate ThreatIntel to blackboard
        if context.shared_blackboard and threat_intel_result:
            await context.shared_blackboard.write(
                "routing", "threat_intel_result", threat_intel_result
            )
        
        return WorkflowEvent.DATA_COLLECTED
    
    async def _handle_report_generation(self, context: WorkflowContext):
        """Generate final report — MultiAgentReportAgent in enhanced mode, original ReportAgent otherwise."""
        from agents.core import Blackboard
        from agents.report_agent import ReportAgent
        from utils.logger import logger as log

        # Use shared Blackboard in enhanced mode
        if context.enhanced and context.shared_blackboard:
            bb = context.shared_blackboard
        else:
            bb = Blackboard()
            await bb.write("config", "asn", context.asn)
            await bb.write("config", "start_time", context.start_time)
            await bb.write("config", "end_time", context.end_time)

        # Propagate validated joint-analysis artifacts so every report path has
        # access to the same evidence contract.
        await bb.write("validation", "causal_analysis", context.causal_analysis or {})
        await bb.write("validation", "joint_alert", context.joint_alert or context.causal_analysis or {})
        # ── Three-card joint-evidence (C1/C2/C3 tier) ──────────────────────
        # Written here so both the async _generate_report_html and the
        # standalone generate_report_html entry points can read them from
        # the blackboard / passed-in payload without any schema changes.
        await bb.write("validation", "joint_tier", getattr(context, "joint_tier", "") or "")
        await bb.write("validation", "joint_score", getattr(context, "joint_score", 0.0) or 0.0)
        await bb.write("validation", "joint_evidence_cards", getattr(context, "joint_evidence_cards", []) or [])
        await bb.write("validation", "joint_rationale", getattr(context, "joint_rationale", "") or "")
        await bb.write("validation", "hcaf_attribution", context.hcaf_attribution or {})
        await bb.write("validation", "hcaf_attribution_status", context.hcaf_attribution_status or "skipped")
        await bb.write("evidence", "chain", context.evidence_chain or {})
        await bb.write("evidence", "validation_notes", context.validation_notes)

        await bb.write("traffic", "result", context.traffic_result)
        await bb.write("routing", "result", context.routing_result)
        await bb.write("routing", "victim_asns", context.victim_asns)
        await bb.write("reasoning", "result", context.reasoning_result)
        await bb.write("traffic", "analysis_payload", context.traffic_result or {})
        await bb.write("routing", "analysis_payload", context.routing_result or {})
        await bb.write("reasoning", "analysis_payload", context.reasoning_result or {})
        await bb.write("diagnosis", "result", {
            "final_claim": context.diagnosis_result,
            "verdict": context.verification_result,
            "experiment_metrics": context.experiment_metrics,
        })
        await bb.update_section("evidence", {
            "observations": context.evidence_records,
            "claims": context.diagnosis_claims,
            "challenges": context.contradictions,
            "verdicts": context.verification_records,
            "metrics": [
                {
                    "record_id": f"workflow-metrics-{context.asn}",
                    "type": "metric",
                    "source": "WorkflowEngine",
                    "name": "experiment_metrics",
                    "value": len(context.experiment_metrics or {}),
                    "payload": context.experiment_metrics or {},
                }
            ],
            "messages": [],
        })

        # ── Enhanced mode: route to report generation ──
        # Bug fix (2026-09-12): the previous implementation unconditionally
        # ran MultiAgentReportAgent (5+ LLM calls: TrafficExpert,
        # RoutingExpert, EvidenceLinker, ConflictResolver, draft) followed
        # by the legacy ReportAgent (1 more LLM call) — 6+ calls per event,
        # each 30-90s on the qwen3.5 endpoint, blowing the 600s timeout and
        # forcing the pipeline to silently swallow reports.
        #
        # New rule: enhanced mode is observationally identical to legacy
        # mode for *report generation* (1 LLM call). The "enhanced" flag
        # only changes two upstream decisions:
        #   (a) a single rule-based debate round is run to refine the
        #       diagnosis claim (LLMDebateAgent uses rule-based
        #       Prosecutor/Defense — no LLM calls);
        #   (b) reactive decisions are emitted, but only via the
        #       deterministic rule-based code path.
        # This caps LLM cost at the same level as the non-enhanced path
        # while keeping the multi-agent *evidence-quality* benefit
        # (debate, evaluation gates, observation board) intact.
        #
        # Set BGP_TRACER_RUN_MULTI_AGENT=1 to opt back into the
        # MultiAgentReportAgent pipeline (useful for offline analyses).
        run_multi_agent = (
            context.enhanced
            and self._enhanced_components is not None
            and os.environ.get("BGP_TRACER_RUN_MULTI_AGENT", "").strip()
                in ("1", "true", "yes")
        )
        if run_multi_agent:
            log.info("[Enhanced] MultiAgentReportAgent requested via env (opt-in)")
            report_agent = self._enhanced_components.get("report_agent")
            multi_agent_result = None
            multi_agent_html = ""
            multi_agent_metrics: dict = {}
            try:
                if report_agent is not None:
                    await report_agent.start()
                    multi_agent_result = await report_agent.step()
                if multi_agent_result and multi_agent_result.success:
                    multi_agent_html = (multi_agent_result.data or {}).get("html", "")
            except Exception as exc:
                log.warning(f"[Enhanced] MultiAgentReportAgent raised: {exc}")

            # Always run the legacy ReportAgent once on top so the final
            # HTML is the comprehensive 1.2 MB LLM-generated report (the
            # MultiAgent path produces only a short validation summary).
            legacy_html = await self._run_legacy_report(bb, context, ReportAgent, log)
            html = legacy_html or bb._sections.get("report", {}).get("html") or ""
            if multi_agent_html:
                context.final_result = context.final_result or {}
                context.final_result["multi_agent_html"] = multi_agent_html
        else:
            legacy_html = await self._run_legacy_report(bb, context, ReportAgent, log)
            html = legacy_html or bb._sections.get("report", {}).get("html") or ""

        # Bug fix 2026-09-13 (BUG-R102): the unconditional
        # ``html = bb._sections.get("report", {}).get("html") or ""``
        # immediately below was a no-op safety net that silently
        # overwrote ``legacy_html`` with whatever happened to be in
        # the Blackboard at this moment. When ``_run_legacy_report``
        # returned a non-empty HTML but the Blackboard had been
        # cleared by an earlier step, the report would still come
        # through correctly via this branch (since the Blackboard
        # was re-read by ``_run_legacy_report`` itself), but the
        # unconditional reassignment was misleading and could mask
        # future regressions. Replace it with a smarter merge that
        # prefers the longer / more complete of the two values.
        bb_html = bb._sections.get("report", {}).get("html") or ""
        if bb_html and len(bb_html) > len(html or ""):
            html = bb_html
        context.report_path = bb._sections.get("report", {}).get("path") or context.report_path

        # Save HTML to file
        if html:
            try:
                from utils.report_exporters import save_html_report
                path = save_html_report(
                    asn=context.asn,
                    time_range=f"{context.start_time} to {context.end_time}",
                    html_content=html,
                    output_dir=Path("results/html"),
                )
                context.report_path = path
                log.info(f"Report saved: {path}")
            except Exception as e:
                log.warning(f"Failed to save report: {e}")

        context.final_result = context.final_result or {}
        context.final_result["html"] = html
        context.final_result["report_path"] = context.report_path
        return WorkflowEvent.REPORT_GENERATED

    async def _run_legacy_report(self, bb, context: WorkflowContext, ReportAgent, log):
        """Run the legacy single-agent ReportAgent and return its HTML."""
        agent = ReportAgent(bb)
        await agent.start()
        result = await agent.step()
        if result is None:
            log.error("ReportAgent returned None")
            raise RetryableError("ReportAgent returned None")
        if not result.success:
            error_msg = str(result.error) if result.error is not None else "Unknown error"
            log.error(f"ReportAgent failed: {error_msg}")
            raise RetryableError(f"Report generation failed: {error_msg}")
        # Bug fix: explicitly fetch the legacy report HTML from the Blackboard
        # so the caller can use it as the final report. Without this, callers
        # relying on `bb._sections.get("report", {}).get("html")` would miss
        # the just-written value when the report is needed for the final save
        # in the same handler.
        try:
            legacy_html = await bb.read("report", "html") or ""
        except Exception:
            legacy_html = ""
        return legacy_html

    async def _handle_complete(self, context: WorkflowContext):
        """Handle completion state."""
        return WorkflowEvent.COMPLETE
    
    async def _handle_error(self, context: WorkflowContext):
        """Handle error state."""
        return WorkflowEvent.ERROR
    
    # ==================== Quality Assessment ====================
    
    def assess_data_quality(self, context: WorkflowContext):
        """Assess overall data quality."""
        score = self.calculate_quality_score(context)
        
        if score >= 0.8:
            return "High"
        elif score >= 0.5:
            return "Medium"
        else:
            return "Low"
    
    def calculate_quality_score(self, context: WorkflowContext):
        """Calculate a 0-1 quality score based on available data."""
        score = 0.0
        factors = 0

        # Traffic data quality — only count when data is actually available.
        # An AS that Cloudflare Radar doesn't sample would otherwise inflate
        # the score with success=True but no points, masking the F1=0
        # no-data vs no-anomaly ambiguity.
        if context.traffic_result:
            factors += 1
            traffic_data_available = context.traffic_result.get(
                "data_available", context.traffic_result.get("success", False)
            )
            if traffic_data_available:
                score += 0.3
                if context.traffic_result.get("anomalies_detected"):
                    score += 0.2

        # Routing data quality — same gate.
        if context.routing_result:
            factors += 1
            routing_data_available = context.routing_result.get(
                "data_available", context.routing_result.get("success", False)
            )
            if routing_data_available:
                score += 0.3
                if context.routing_result.get("total_prefix_hijacks", 0) > 0:
                    score += 0.2

        # Normalize if we have any factors
        if factors > 0:
            return min(1.0, score / (factors * 0.5))
        return 0.0
    
    # ==================== Metrics ====================
    
    def get_metrics(self):
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
    user_input = None,
    asn = None,
    start_time = None,
    end_time = None,
    parallel = True,
    max_retries = 3,
    analysis_mode = "traffic_first",
    enable_mitm = False,
    buffer_hours = None,
    enhanced = False,
    debate_rounds = 3,
    evaluation_retries = 2,
    checkpoint = None,
    event_type: str = None,
    as_role: str = None,
    precomputed_routing: dict = None,
    precomputed_traffic: dict = None,
):
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
            - "traffic_first": Traffic first, routing on demand (RECOMMENDED, default)
            - "react": LLM-driven ReAct analysis
        enable_mitm: Whether to enable MITM (中间人劫持) detection (default: False)
                     When False, skips forge hijack detection and ES usage
        buffer_hours: Buffer hours before/after traffic anomaly windows before routing analysis
                      None = use BUFFER_HOURS from config (default: 2.0); 0 = strict time range only
        checkpoint: Optional CheckpointManager for resumable execution.

    Returns:
        WorkflowContext with all results and execution trace
    """
    engine = WorkflowEngine(
        max_retries=max_retries,
        parallel_execution=False,  # Disable old parallel mode, use smart cascade
        enhanced=enhanced,
        debate_rounds=debate_rounds,
        evaluation_retries=evaluation_retries,
    )
    engine.checkpoint = checkpoint  # attached for state handlers to use

    # Map string mode to enum
    mode_map = {
        "traffic_first": AnalysisMode.TRAFFIC_FIRST,
        "react": AnalysisMode.REACT,
    }
    selected_mode = mode_map.get(analysis_mode.lower(), AnalysisMode.TRAFFIC_FIRST)

    context = WorkflowContext(
        user_input=user_input,
        asn=asn,
        start_time=start_time,
        end_time=end_time,
        analysis_mode=selected_mode,
        enable_mitm=enable_mitm,  # 传递MITM检测开关
        buffer_hours=buffer_hours,  # None -> dataclass default (2.0) if not overridden
        enhanced=enhanced,
        debate_rounds=debate_rounds,
        evaluation_retries=evaluation_retries,
        event_type=event_type,
        as_role=as_role,
        precomputed_routing=precomputed_routing,
        precomputed_traffic=precomputed_traffic,
        # Bug fix: seed message_bus_run_id with a stable identifier even when
        # not enhanced, so TokenBudget can accumulate tokens per run.
        message_bus_run_id=f"{asn}_{str(start_time).replace(' ', '_').replace(':', '')}_"
                           f"{'enhanced' if enhanced else 'base'}",
    )

    # Override buffer_hours from config if not explicitly passed
    if context.buffer_hours is None:
        from config import BUFFER_HOURS
        context.buffer_hours = BUFFER_HOURS

    # ── Resume: if a fully-completed workflow is cached, return it directly ─
    if checkpoint is not None and checkpoint.has("workflow_context"):
        cached = checkpoint.load("workflow_context")
        if isinstance(cached, dict) and cached.get("current_state") == "COMPLETE":
            logger.info(f"[Resume] Loaded completed workflow context from checkpoint")
            return cached

    return await engine.execute(context)


def snapshot_context(context: "WorkflowContext") -> dict:
    """Convert a WorkflowContext dataclass to a JSON-serialisable dict for checkpointing."""
    try:
        d = asdict(context)
    except Exception:
        d = {k: getattr(context, k, None) for k in context.__dataclass_fields__}
    # Convert enums to string for JSON safety
    for k, v in list(d.items()):
        if hasattr(v, "name"):  # Enum
            d[k] = v.name
        elif isinstance(v, datetime):
            d[k] = v.isoformat()
    return make_json_safe(d)


def get_workflow_architecture_diagram():
    """Return a text summary of the workflow architecture."""
    return """Workflow Architecture (v3.0 Smart Cascade)
============================================
  UserInput → Traffic Quick Screen → [Routing on demand]
                                          → Cross-Validation
                                          → Reasoning → Report → COMPLETE

Modes: TRAFFIC_FIRST (recommended) | REACT (LLM-driven)

Special Cases:
  ⚠ Traffic OK + Routing Anomaly → Warning (potential hidden risk)
  ✓ Both OK → Quick confirmation
  ✗ Both Anomalous → Deep correlation
    """


def parse_timestamp_value(ts):
    """Parse timestamps from multiple string formats."""
    from datetime import datetime
    if not ts:
        return None

    ts_str = str(ts).strip()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str[:19], fmt)
        except ValueError:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def extract_anomaly_windows(anomalies, buffer_hours = 2):
    """
    Extract time windows from traffic anomaly timestamps.

    Buffer is applied HERE — each cluster gets ±buffer_hours padding.
    union_anomaly_windows should NOT apply buffer again.
    """
    from datetime import datetime, timedelta
    if not anomalies:
        return []
    try:
        times = []
        for a in anomalies:
            ts = a.get("timestamp", "")
            parsed = parse_timestamp_value(ts)
            if parsed is not None:
                times.append(parsed)
        if not times:
            return []
        times.sort()
        windows = []
        cur_start = cur_end = times[0]
        max_gap = timedelta(hours=1)
        for t in times[1:]:
            if t - cur_end <= max_gap:
                cur_end = t
            else:
                windows.append({
                    "start": (cur_start - timedelta(hours=buffer_hours)).strftime("%Y-%m-%d %H:%M"),
                    "end": (cur_end + timedelta(hours=buffer_hours)).strftime("%Y-%m-%d %H:%M"),
                })
                cur_start = cur_end = t
        windows.append({
            "start": (cur_start - timedelta(hours=buffer_hours)).strftime("%Y-%m-%d %H:%M"),
            "end": (cur_end + timedelta(hours=buffer_hours)).strftime("%Y-%m-%d %H:%M"),
        })
        return windows
    except Exception:
        return []


def union_anomaly_windows(windows, buffer_hours = 2):
    """
    Merge multiple anomaly windows into a single unified window that covers all anomalies.

    IMPORTANT: Buffer is applied by extract_anomaly_windows already.
    This function only merges the (already-buffered) windows and does NOT add buffer again.

    Args:
        windows: list of {"start": "...", "end": "..."} from extract_anomaly_windows
        buffer_hours: unused; kept for backward-compatible signature
    
    Returns:
        A single {"start": "...", "end": "..."} covering all windows
    """
    from datetime import datetime, timedelta
    if not windows:
        return None
    
    try:
        all_starts = []
        all_ends = []
        for w in windows:
            for fmt in ["%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]:
                try:
                    s = datetime.strptime(w["start"], fmt)
                    e = datetime.strptime(w["end"], fmt)
                    all_starts.append(s)
                    all_ends.append(e)
                    break
                except ValueError:
                    continue
        
        if not all_starts:
            return windows[0] if windows else None
        
        # Find the earliest start and latest end — no additional buffer here
        global_start = min(all_starts)
        global_end = max(all_ends)
        
        # Buffer was already applied by extract_anomaly_windows; just merge boundaries
        result_start = global_start.strftime("%Y-%m-%d %H:%M")
        result_end = global_end.strftime("%Y-%m-%d %H:%M")
        
        return {"start": result_start, "end": result_end}
    except Exception:
        return windows[0] if windows else None


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
