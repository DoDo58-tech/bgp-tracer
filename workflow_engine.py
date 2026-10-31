"""BGP Tracer Multi-Agent Workflow Engine
======================================
State machine: INITIAL → TRAFFIC_ANALYSIS → ROUTING_ANALYSIS → REASONING → REPORT → COMPLETE/ERROR"""

from __future__ import annotations

import asyncio
import os
import traceback
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Callable
from time import perf_counter

from utils.helpers import make_json_safe
from utils.logger import logger
from agents.ablation_switches import (
    ablation_campaign_active,
    ablation_switches,
)
from detectors.traffic.multi_scale_baseline import CausalCorrelationScorer
from detectors.evidence_chain_builder import EvidenceChainBuilder


def paddle_parse(value):
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


def paddle_explanation(verdict):
    """A one-line account of what the estimator decided and why."""
    if verdict.committed:
        return (
            "PADDLE committed %s: the %s control-plane channel was at "
            "%.3fx its same-clock baseline when the traffic trough fell, "
            "%s seconds before it, and exceeded the placebo null by %.2fx."
            % (verdict.direction, verdict.channel or "strongest",
               verdict.tau_control or 0.0,
               verdict.lag_seconds if verdict.lag_seconds is not None else 0.0,
               verdict.exclusivity_ratio or 0.0)
        )
    vetoes = ", ".join(
        "%s=%s" % (k, v) for k, v in (verdict.vetoes or {}).items())
    return "PADDLE abstained (%s; vetoes: %s)." % (verdict.reason, vetoes)


def paddle_limitations(verdict):
    """What the verdict does *not* establish."""
    if verdict.committed:
        return ("Direction only; the magnitude of the traffic impact and "
                "the mechanism behind the routing change are out of scope.")
    return (
        "The window does not support a directional claim: "
        "%s. Only the committed direction is reported." % verdict.reason)


def build_routing_state(prefix2as_file, prefixes, max_prefixes=200):
    """Build the ASN -> prefixes map the routing-state consumer needs.

    Returns:
    dict mapping ASN string -> list of prefixes it originates. Only
    the ASes that actually originate one of ``prefixes`` are
    included, so the map stays small."""
    if not prefix2as_file or not Path(prefix2as_file).exists():
        return {}
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    prefixes = [p for p in (prefixes or []) if p]
    if not prefixes:
        return {}

    try:
        from agents.coordination_utils import load_json
        table = load_json(prefix2as_file)
    except (AttributeError) as exc:  # noqa: BLE001 - degrade, never crash the pipeline
        logger.warning(f"[HCAF] routing_state: failed to load {prefix2as_file}: {exc}")
        return {}
    if not isinstance(table, dict):
        return {}

    wanted = set(prefixes[:max_prefixes])
    state = {}
    for prefix, origins in table.items():
        if prefix not in wanted:
            continue
        if isinstance(origins, str):
            origins = [origins]
        for origin_asn in origins or []:
            key = str(origin_asn).strip().upper().lstrip("AS")
            if not key:
                continue
            state.setdefault(key, []).append(prefix)
    return state


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


# Analysis Mode Configuration

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
    # ── Event metadata ────────────────────────────────────────────────────────────
    event_type: str = None   # "hijack", "leak", "outage" - decides whether routing analysis is forced
    as_role: str = None      # "victim", "attacker" - AS role for the analysis
    # ── Precomputed data (from annotation_package or similar external sources)─────────────────────
    precomputed_routing: dict = None  # precomputed routing data, e.g. route_check.json
    precomputed_traffic: dict = None  # precomputed traffic data
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
    # Typed records for the alternatives the analysis ruled out and the
    evidence_alternatives: list = field(default_factory=list)
    evidence_gaps: list = field(default_factory=list)
    traffic_ok_but_routing_anomaly: bool = False
    causal_analysis: dict = None
    joint_alert: dict = None
    evidence_chain: dict = None
    bayesian_result: dict = None
    # Which coordination stages actually ran, and which were ablated.
    # Written by the engine as each stage executes, so a run can be
    # audited for single-variability after the fact instead of the
    # property being taken on trust.
    stage_execution: dict = field(default_factory=dict)
    # ── HCAF causal attribution result (three innovation methods: MSCBD/CTPR/CIC)─────────────
    hcaf_attribution: dict = None
    hcaf_attribution_status: str = "skipped"  # "ok" / "skipped" / "failed"
    buffer_hours: float = 2.0
    # ── Enhanced multi-agent fields ──────────────────────────────────────────
    enhanced: bool = False              # enable enhanced multi-agent mode
    shared_blackboard = None           # the one Blackboard shared by every stage
    message_bus_run_id: str = ""       # unique run_id for legacy MessageBus instance
    # debate_rounds / evaluation_retries / reactive_decisions /
    debate_rounds: int = 3
    evaluation_retries: int = 2

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

    def get_blackboard(self):
        """Return the single Blackboard shared by every stage of this run."""
        if self.shared_blackboard is None:
            from agents.core import Blackboard
            self.shared_blackboard = Blackboard()
        return self.shared_blackboard


class WorkflowError(Exception):
    """Base exception for workflow errors."""
    def __init__(self, message, stage, context):
        self.message = message
        self.stage = stage
        self.context = context
        super().__init__(message)


class RetryableError(Exception):
    """Error that can be retried."""
    pass


class WorkflowEngine:
    """Graph-based workflow engine with state machine."""

    def __init__(
        self,
        max_retries = 3,
        parallel_execution = True,
        skip_unnecessary_analysis = None,
        enhanced = None,
        debate_rounds = None,
        evaluation_retries = None,
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

        # ── Component ablation switches ────────────────────────────────────────
        # Read through the shared module so that every component which
        # honours a switch -- the workflow engine, the tool layer, the
        # sub-agents -- sees the same state.  A stage that is switched
        # off must be off *everywhere*; a component that read the
        # environment variable on its own could disagree with the
        # engine, and the arm would then measure a mixture of two
        # configurations rather than one.
        self.ablate = ablation_switches()
        if any(self.ablate.values()):
            logger.info(f"[Workflow] component ablation active: "
                        f"{[k for k, v in self.ablate.items() if v]}")
        # Optional kwargs accepted for API compatibility with callers that pass
        # through ChiefExpertAgent-style parameters. Stored for handler introspection.
        self._enhanced_flag = enhanced
        self._debate_rounds = debate_rounds
        self._evaluation_retries = evaluation_retries

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

    def register_default_handlers(self):
        """Register default state handlers."""
        self._state_handlers = {
            WorkflowState.INITIAL: self.handle_initial,
            WorkflowState.PARSING_INPUT: self.handle_parsing_input,
            WorkflowState.TRAFFIC_SCREENING: self.handle_traffic_screening,
            WorkflowState.TRAFFIC_ANALYSIS: self.handle_traffic_analysis,
            WorkflowState.ROUTING_ANALYSIS: self.handle_routing_analysis,
            WorkflowState.JOINT_EVIDENCE: self.handle_joint_evidence,  # New state for three-card analysis
            WorkflowState.REASONING: self.handle_reasoning,
            WorkflowState.VALIDATION: self.handle_validation,
            WorkflowState.DATA_ENRICHMENT: self.handle_data_enrichment,
            WorkflowState.REPORT_GENERATION: self.handle_report_generation,
            WorkflowState.COMPLETE: self.handle_complete,
            WorkflowState.ERROR: self.handle_error,
        }

    async def execute(self, context):
        """Execute the workflow starting from INITIAL state.
        
        Returns:
        Updated context with all results and execution trace"""
        _t0 = perf_counter()
        self.metrics["total_runs"] += 1

        # Hard cap on total workflow runtime to avoid the enhanced mode
        try:
            from config import WORKFLOW_TOTAL_TIMEOUT_S
        except (ValueError):
            WORKFLOW_TOTAL_TIMEOUT_S = 900.0
        workflow_timeout_s = float(
            os.environ.get("BGP_TRACER_WORKFLOW_TIMEOUT_S", WORKFLOW_TOTAL_TIMEOUT_S)
        )

        context.add_transition(
            WorkflowState.INITIAL,
            WorkflowState.INITIAL,
            WorkflowEvent.START
        )

        bb_seed = getattr(context, "shared_blackboard", None)
        if bb_seed is not None:
            if context.event_type is not None:
                await bb_seed.write("config", "event_type", context.event_type)
            if context.as_role is not None:
                await bb_seed.write("config", "as_role", context.as_role)

        try:
            # enhanced mode removed 2026-09-29; nothing to initialise here.

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
                    except (AttributeError) as e:
                        logger.warning(f"[Checkpoint] Failed to save after {prev_state.name}: {e}")

            if timed_out and context.current_state != WorkflowState.COMPLETE:
                # Fallback reached: jump to report generation and let it
                logger.warning(
                    "[Workflow] timeout-fallback: invoking _handle_report_generation "
                    "directly to salvage a partial report"
                )
                try:
                    handler = self._state_handlers.get(context.current_state)
                    if handler is not None:
                        await handler(context)
                except (AttributeError) as fb_exc:
                    logger.error(f"[Workflow] timeout-fallback failed: {fb_exc!r}")

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
                except (AttributeError) as save_err:
                    logger.warning(f"[Checkpoint] Failed to save error state: {save_err}")

        finally:
            context.execution_time_ms = (perf_counter() - _t0) * 1000
            self.metrics["total_execution_time_ms"] += context.execution_time_ms

            # Clean up MessageBus if enhanced mode was used
            if context.message_bus_run_id:
                # enhanced mode removed 2026-09-29; no bridge to stop.
                pass
            if context.message_bus_run_id:
                try:
                    from agents.token_budget import TokenBudget
                    TokenBudget.clear_instance(context.message_bus_run_id)
                except (AttributeError) as _tb_err:
                    logger.debug(f"[Cleanup] TokenBudget.clear_instance failed: {_tb_err}")

            # ── Final checkpoint: save fully-completed context ──
            ckpt = getattr(self, "checkpoint", None)
            if ckpt is not None and ckpt.enabled and context.current_state == WorkflowState.COMPLETE:
                try:
                    ckpt.save("workflow_context", snapshot_context(context))
                except (AttributeError) as e:
                    logger.warning(f"[Checkpoint] Failed to save final context: {e}")

        return context
    
    def get_next_state(self, current, event, context=None):
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

    async def handle_initial(self, context):
        return WorkflowEvent.START

    async def handle_parsing_input(self, context):
        from agents.traffic_agent import (
            parse_traffic_outage_input,
            parse_multiple_as_input,
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
    
    async def handle_traffic_screening(self, context):
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

        except (AttributeError) as e:
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
    
    async def handle_traffic_analysis(self, context):
        from agents.traffic_agent import TrafficAgent

        logger.info(f"[_handle_traffic_analysis] precomputed_traffic={bool(context.precomputed_traffic)}")

        # One Blackboard per run, shared by every stage (see
        # ``WorkflowContext.get_blackboard``).
        bb = context.get_blackboard()
        await bb.write("config", "asn", context.asn)
        await bb.write("config", "start_time", context.start_time)
        await bb.write("config", "end_time", context.end_time)

        # ── Inject precomputed data (from annotation_package route_check.json)─────────────
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
        return WorkflowEvent.TRAFFIC_DONE
    
    async def handle_routing_analysis(self, context):
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
            if isinstance(rt, dict):
                if rt.get("start") or rt.get("start_time"):
                    routing_start = str(rt.get("start") or rt.get("start_time"))
                if rt.get("end") or rt.get("end_time"):
                    routing_end = str(rt.get("end") or rt.get("end_time"))
            logger.info(f"[RoutingAnalysis] Using traffic-expanded routing window: {routing_start} → {routing_end}")
        else:
            context.traffic_anomaly_window = None

        # ── Inject precomputed routing data ────────────────────────────────────────────────
        if context.precomputed_routing:
            logger.info(f"[RoutingAnalysis] Using precomputed routing data from annotation_package "
                        f"(keys={list(context.precomputed_routing.keys())[:5]})")
            context.routing_result = context.precomputed_routing
            # Ensure the precomputed data is marked as successful
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
            await self.cross_validate_results(context)
            return WorkflowEvent.ROUTING_DONE

        # One Blackboard per run, shared by every stage (see
        # ``WorkflowContext.get_blackboard``).
        bb = context.get_blackboard()
        # Write the routing-window config keys once. The previous
        await bb.write("config", "asn", context.asn)
        # The routing window may be *wider* than the analysis window (it is
        await bb.write("config", "routing_start_time", routing_start)
        await bb.write("config", "routing_end_time", routing_end)
        await bb.write("config", "enable_mitm", context.enable_mitm)
        # use_traffic_time_window should follow rt dynamically
        # Set True when routing_time_window comes from the extended traffic analysis,
        # so RoutingAgent knows to use the extended window instead of the original one.
        await bb.write("config", "use_traffic_time_window", rt is not None)
        await bb.write("config", "routing_detail", context.routing_analysis_detail or "full")
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

        await self.cross_validate_results(context)

        return WorkflowEvent.ROUTING_DONE
    
    async def handle_joint_evidence(self, context):
        """New state: Run three-card joint evidence analysis (C1/C2/C3)."""
        try:
            from detectors.traffic.joint_evidence import analyse_joint_evidence
            from detectors.traffic.multi_scale_baseline import CausalCorrelationScorer

            logger.info("[JointEvidence] Running three-card joint evidence analysis...")

            # Extract routing events from routing_result
            routing_events = []
            if context.routing_result and context.routing_result.get("success") is not False:
                # annotation_package uses a nested format:
                rr = context.routing_result
                hijack_section = rr.get("hijack") or {}   # annotation_package nested format
                for key in ["origin_hijacked", "origin_hijacking", "forge_hijacked", "forge_hijacking"]:
                    # prefer flat key; fall back to nested hijack.{key}
                    events = rr.get(key) or hijack_section.get(key) or []
                    for event in events:
                        # Normalise event to dict (it may be AnomalyDetail dataclass).
                        if isinstance(event, dict):
                            event_copy = dict(event)
                        elif is_dataclass(event):
                            event_copy = asdict(event)
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
                    # Normalise event to dict (it may be AnomalyDetail dataclass).
                    if isinstance(event, dict):
                        event_copy = dict(event)
                    elif is_dataclass(event):
                        event_copy = asdict(event)
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
                    # Normalise anomaly to dict (it may be AnomalyDetail dataclass).
                    # Use asdict() for dataclasses so all fields are extracted.
                    if isinstance(anomaly, dict):
                        anomaly_copy = dict(anomaly)
                    elif is_dataclass(anomaly):
                        anomaly_copy = asdict(anomaly)
                    else:
                        anomaly_copy = dict(getattr(anomaly, "__dict__", {}) or {})
                    if "timestamp" not in anomaly_copy:
                        anomaly_copy["timestamp"] = anomaly_copy.get("time")
                    traffic_anomalies.append(anomaly_copy)

            logger.info(f"[JointEvidence] Found {len(routing_events)} routing events, {len(traffic_anomalies)} traffic anomalies")

            # Run the three-card joint evidence analysis
            if self.ablate.get("joint_evidence"):
                logger.info("[JointEvidence] ablated — skipping three-card joint evidence")
                context.joint_tier = "INSUFFICIENT"
                context.joint_score = 0.0
                context.joint_evidence_cards = []
                context.joint_rationale = "joint evidence ablated"
                context.validation_notes.append({
                    "case": "joint_evidence_ablated",
                    "severity": "warning",
                    "message": "Three-card joint evidence was ablated for this run",
                })
                self.record_stage_execution(
                    context, "joint_evidence", ran=False,
                    detail="ablated by BGP_TRACER_ABLATE_JOINT_EVIDENCE")
            elif routing_events or traffic_anomalies:
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
                self.record_stage_execution(
                    context, "joint_evidence", ran=True,
                    detail=f"tier={context.joint_tier}")
            else:
                logger.info("[JointEvidence] No routing events or traffic anomalies found, skipping joint analysis")
                context.joint_tier = "INSUFFICIENT"
                context.joint_score = 0.0
                context.joint_evidence_cards = []
                self.record_stage_execution(
                    context, "joint_evidence", ran=False,
                    detail="no routing events or traffic anomalies to fuse")

            # ── Record the ruled-out alternatives as first-class records ──
            try:
                bb_joint = context.get_blackboard()
                falsification = next(
                    (c for c in (context.joint_evidence_cards or [])
                     if c.get("name") == "falsification"),
                    None,
                )
                for note in (falsification or {}).get("alternative_explanations") or []:
                    if not note or note == "no alternative explanations identified":
                        continue
                    await bb_joint.add_alternative({
                        "source": "JointEvidenceFalsification",
                        "alternative": str(note),
                        "summary": (
                            f"Alternative explanation considered and discounted: {note}"
                        ),
                        "competes_with": "routing_caused_traffic_anomaly",
                        "rejected_because": (
                            f"Falsification card score "
                            f"{(falsification or {}).get('score', 0)} with the "
                            f"competing explanation noted but not established"
                        ),
                        "confidence": float((falsification or {}).get("score", 0.5) or 0.0),
                        "derived_from": ["joint_evidence.falsification"],
                    })
            except (AttributeError) as exc:  # noqa: BLE001
                logger.warning(f"[JointEvidence] failed to record alternatives: {exc}")

            # HCAF causal attribution (three innovation methods: MSCBD/CTPR/CIC)
            try:
                if self.ablate.get("hcaf"):
                    logger.info("[HCAF] ablated — skipping causal attribution")
                    context.hcaf_attribution = {}
                    context.hcaf_attribution_status = "ablated"
                    self.record_stage_execution(
                        context, "hcaf", ran=False,
                        detail="ablated by BGP_TRACER_ABLATE_HCAF")
                else:
                    hcaf_result = self.compute_hcaf_attribution(context)
                    if hcaf_result:
                        context.hcaf_attribution = hcaf_result
                        context.hcaf_attribution_status = "ok"
                        self.record_stage_execution(
                            context, "hcaf", ran=True,
                            detail=f"direction={hcaf_result.get('direction')}")
                        logger.info(
                            f"[HCAF] direction_val={hcaf_result['direction']}, "
                            f"strength_val={hcaf_result['strength']}, "
                            f"confidence={hcaf_result['confidence']:.0%}, "
                            f"convergence={hcaf_result['convergence']:.0%}"
                        )
                    else:
                        if context.hcaf_attribution_status not in ("ok",):
                            context.hcaf_attribution_status = "skipped"
                        self.record_stage_execution(
                            context, "hcaf", ran=False,
                            detail="attribution produced no result")
                        logger.info(f"[HCAF] causal attribution produced no result (status={context.hcaf_attribution_status})")
            except (AttributeError) as e:
                logger.warning(f"[HCAF] causal attribution failed in joint_evidence stage: {e}")
                if context.hcaf_attribution_status not in ("ok",):
                    context.hcaf_attribution_status = "failed"

            # Event-driven HCAF publish removed 2026-09-29 (enhanced mode deleted).

            return WorkflowEvent.JOINT_EVIDENCE_COMPLETE

        except ImportError as e:
            logger.warning(f"[JointEvidence] Could not import joint_evidence module: {e}")
            context.validation_notes.append({
                "case": "joint_evidence",
                "severity": "warning",
                "message": f"Joint evidence analysis skipped: {e}",
            })
            # Do not return here - HCAF must run outside joint_evidence
        except (AttributeError) as e:
            logger.error(f"[JointEvidence] Error running joint evidence analysis: {e}")
            context.validation_notes.append({
                "case": "joint_evidence",
                "severity": "error",
                "message": f"Joint evidence analysis failed: {e}",
            })
            # Do not return here - HCAF must run outside joint_evidence

        # HCAF causal attribution (three innovation methods: MSCBD/CTPR/CIC)
        # Independent of joint_evidence so it still runs when joint_evidence fails
        try:
            hcaf_result = self.compute_hcaf_attribution(context)
            if hcaf_result:
                context.hcaf_attribution = hcaf_result
                context.hcaf_attribution_status = "ok"
                logger.info(
                    f"[HCAF] direction_val={hcaf_result['direction']}, "
                    f"strength_val={hcaf_result['strength']}, "
                    f"confidence={hcaf_result['confidence']:.0%}, "
                    f"convergence={hcaf_result['convergence']:.0%}"
                )
            else:
                if context.hcaf_attribution_status not in ("ok",):
                    context.hcaf_attribution_status = "skipped"
                logger.info(f"[HCAF] causal attribution produced no result (status={context.hcaf_attribution_status})")
        except (AttributeError) as e:
            logger.warning(f"[HCAF] causal attribution failed after joint_evidence: {e}")
            if context.hcaf_attribution_status not in ("ok",):
                context.hcaf_attribution_status = "failed"

        return WorkflowEvent.JOINT_EVIDENCE_COMPLETE
    
    async def cross_validate_results(self, context):
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
            routing_anomalies = rr.get("total_prefix_hijacks") or hijack_events
            leak_section = rr.get("leak") or {}
            routing_anomalies += rr.get(
                "leak_count"
            ) or len(rr.get("route_leaks") or leak_section.get("route_leaks") or [])
            outage = rr.get("outage_analysis") or rr.get("outage") or {}
            # NOTE: ``is_outage_suspected`` / ``outage_suspected`` may be present
            outage_flag = outage.get("is_outage_suspected", rr.get("outage_suspected", False))
            routing_anomalies += int(bool(outage_flag))

        routing_ok = routing_anomalies == 0

        if not traffic_data_available:
            context.validation_notes.append({
                "case": "missing_traffic_data",
                "severity": "warning",
                "message": "Traffic data unavailable; cannot determine whether the routing alert caused real traffic impact",
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
                "message": "Traffic is normal but routing anomalies were detected; latent risk may remain",
                "details": {
                    "traffic_anomalies": 0,
                    "routing_anomalies": routing_anomalies,
                    "possible_reasons": [
                        "Routing problem was repaired automatically",
                        "Routing is unstable but has not yet affected traffic",
                        "Traffic may be shielded by CDN/caching",
                        "A backup route is present"
                    ],
                    "recommendation": "Keep monitoring; routing anomalies may foreshadow future problems"
                }
            })
            logger.warning(
                f"⚠️ Cross-validation alert: Traffic OK but routing has {routing_anomalies} anomalies"
            )
        elif not traffic_ok and not routing_ok:
            context.validation_notes.append({
                "case": "both_anomalous",
                "severity": "critical",
                "message": "Anomalies detected in both traffic and routing; deep correlation analysis needed",
                "details": {
                    "traffic_anomalies": (context.traffic_result or {}).get("anomaly_count", 0),
                    "routing_anomalies": routing_anomalies,
                    "recommendation": "Proceed to joint-evidence review: reconcile timing, affected prefixes, and alternative explanations before judging the relationship"
                }
            })
        elif traffic_ok and routing_ok:
            context.validation_notes.append({
                "case": "both_ok",
                "severity": "info",
                "message": "Both traffic and routing look normal; the problem is likely unrelated to routing",
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
                "message": "Correlation analysis between routing and traffic observations",
                "details": causal_result
            })
            context.causal_analysis = causal_result
            context.joint_alert = causal_result

        evidence_chain = await self.build_evidence_chain(context)
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

        def normalise_event(ev):
            """Convert AnomalyDetail objects (or any dataclass) to dict.
            Several routing detector return lists of ``AnomalyDetail`` instances
            which are not JSON-serialisable and don't expose ``.get``. The rest
            of the workflow assumes dicts, so coerce here. Bug fix 2026-09-16:
            leak_cox_2025 hit ``ev.get("origin_as")`` on an AnomalyDetail and
            crashed ``compute_causal_analysis``."""
            if isinstance(ev, dict):
                return ev
            if hasattr(ev, "__dict__"):
                return {k: v for k, v in ev.__dict__.items() if not k.startswith("_")}
            return {}

        victim_asns: set = set()
        for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
            for ev in events_for(key):
                ev = normalise_event(ev)
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
        except (AttributeError) as e:
            logger.warning(f"causal analysis computation failed: {e}")
            return None

    def build_hcaf_timelines(self, routing_result, traffic_result):
        """Convert routing_result / traffic_result into the timeline/context shape HCAF expects."""
        routing_timeline = []
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
                # Quick caches sometimes serialise AnomalyDetail via repr() in top-level keys but
                # keep a rich dict list under leak_analysis.anomalies — prefer those when present.
                if key == "route_leaks" and not any(isinstance(x, dict) for x in events):
                    events = routing_result.get("leak_analysis", {}).get("anomalies") or events
                for ev_item in events:
                    # Normalise to dict (event may be AnomalyDetail object or a string repr).
                    if isinstance(ev_item, dict):
                        ev = ev_item
                    elif isinstance(ev_item, str):
                        # Quick caches sometimes serialise AnomalyDetail via repr() — try to
                        # extract timestamp from the kwarg form, otherwise skip.
                        import re as _re
                        m = _re.search(r"timestamp=[\"']([^\"']+)[\"']", ev_item)
                        ev = {"timestamp": m.group(1)} if m else {}
                        # Best-effort: also pull score from confidence if present.
                        m2 = _re.search(r"confidence=([\d.]+)", ev_item)
                        if m2:
                            ev["confidence"] = float(m2.group(1))
                    else:
                        ev = dict(getattr(ev_item, "__dict__", {}) or {})
                    ts_value = ev.get("timestamp") or ev.get("first_seen")
                    if not ts_value:
                        continue
                    score_val = 0.9 if "hijack" in key else 0.7
                    routing_timeline.append({
                        "timestamp": ts_value,
                        "score": score_val,
                        "event_type": "hijack" if "hijack" in key else "leak",
                        "raw_event": ev,
                    })
            outage = routing_result.get("outage_analysis") or routing_result.get("outage") or {}
            if outage.get("is_outage_suspected"):
                ts_value = outage.get("timestamp") or outage.get("first_seen")
                if ts_value:
                    routing_timeline.append({
                        "timestamp": ts_value,
                        "score": outage.get("outage_score", 0.8) or 0.8,
                        "event_type": "outage",
                        "raw_event": outage,
                    })
            routing_timeline.sort(key=lambda x: x.get("timestamp") or "")

        traffic_timeline = []
        if traffic_result:
            for exc_item in (traffic_result.get("anomalies") or []):
                # Normalise to dict (anomaly may be AnomalyDetail object).
                if isinstance(exc_item, dict):
                    an = exc_item
                else:
                    an = dict(getattr(exc_item, "__dict__", {}) or {})
                ts_value = an.get("timestamp") or an.get("time")
                if not ts_value:
                    continue
                drop_ratio_val = an.get("drop_percent") or an.get("percent_change") or traffic_result.get("percent_change")
                score_val = min(1.0, abs(drop_ratio_val) / 100.0) if isinstance(drop_ratio_val, (int, float)) else 0.8
                traffic_timeline.append({
                    "timestamp": ts_value,
                    "score": max(score_val, 0.6),
                    "event_type": "traffic_anomaly",
                    "raw_event": an,
                })
            # Fallback: when no anomalies but traffic drop is significant (peak_trough_drop_pct > 30%
            # or percent_change < -15%), synthesize a minimal timeline from expanded_boundaries /
            # expanded_windows so HCAF / JointEvidence still receive *some* traffic signal.
            if not traffic_timeline:
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
                                traffic_timeline.append({
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
                if not traffic_timeline and isinstance(pct, (int, float)) and pct < -15.0:
                    eb = traffic_result.get("expanded_boundaries") or {}
                    mid_ts = eb.get("expanded_start") or eb.get("expanded_end")
                    if mid_ts:
                        traffic_timeline.append({
                            "timestamp": str(mid_ts),
                            "score": min(1.0, abs(pct) / 100.0),
                            "event_type": "traffic_anomaly_synthesized",
                            "raw_event": {"synthesized": True, "reason": "pct_change_significant"},
                        })
                        logger.info(
                            f"[HCAF] Synthesized 1 traffic timeline point from "
                            f"expanded_boundaries (pct_change={pct:.1f}%)"
                        )
            traffic_timeline.sort(key=lambda x: x.get("timestamp") or "")

        routing_context = {
            "event_type": "outage",
            "as_path": [],
            "origin_as": None,
        }
        traffic_context = {
            "traffic_drop_ratio": 0.0,
            "affected_prefix": None,
            "baseline": {},
        }
        topology_context = {
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

            # ── Observable routing signals for the confounder detector ─────
            routing_context["has_routing_withdrawal"] = bool(
                (routing_result.get("outage_analysis") or {}).get("is_outage_suspected")
                or routing_result.get("outage_suspected")
            )
            routing_context["has_routing_origin"] = bool(
                routing_result.get("origin_hijacked")
                or routing_result.get("forge_hijacked")
                or hijack_section.get("origin_hijacked")
                or hijack_section.get("forge_hijacked")
            )
            routing_context["has_route_leak"] = bool(
                routing_result.get("route_leaks") or leak_section.get("route_leaks")
            )
            routing_context["leak_count"] = len(
                routing_result.get("route_leaks") or leak_section.get("route_leaks") or []
            )
            routing_context["hijack_count"] = len(
                routing_result.get("origin_hijacked") or hijack_section.get("origin_hijacked") or []
            )
            # Distinct event types co-occurring in the window.
            _event_types = set()
            for ev in events_all:
                if isinstance(ev, dict):
                    et = ev.get("event_type") or ev.get("type")
                    if et:
                        _event_types.add(str(et).lower())
            routing_context["event_types"] = sorted(_event_types)

            if events_all:
                first_event = events_all[0]
                # Some detectors serialise events as strings (AnomalyDetail
                first_event = next(
                    (e for e in events_all if isinstance(e, dict)),
                    {}
                )
                if not first_event:
                    first_event = {}
                routing_context["event_type"] = (
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
                routing_context["as_path"] = as_path_raw
                routing_context["origin_as"] = first_event.get("origin_as") or first_event.get("attacker_as") or first_event.get("victim_as")
                if isinstance(routing_context["origin_as"], str) and routing_context["origin_as"].isdigit():
                    routing_context["origin_as"] = int(routing_context["origin_as"])
                if routing_context["as_path"]:
                    routing_context["origin_as"] = routing_context["origin_as"] or routing_context["as_path"][-1]

        # Collect every prefix the routing detectors flagged. The cascade
        # estimator needs the full set, not just the first event's, so a
        # multi-prefix event propagates along every affected prefix.
        affected_prefixes = set()
        if routing_result:
            hijack_section = routing_result.get("hijack") or {}
            leak_section = routing_result.get("leak") or {}
            for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                        "forge_hijacking", "route_leaks"):
                for ev in (routing_result.get(key) or hijack_section.get(key)
                           or leak_section.get(key) or []):
                    if not isinstance(ev, dict):
                        continue
                    for pkey in ("prefix", "affected_prefix", "prefixes", "victim_prefix"):
                        pval = ev.get(pkey)
                        if isinstance(pval, str) and pval:
                            affected_prefixes.add(pval)
                        elif isinstance(pval, list):
                            affected_prefixes.update(x for x in pval if isinstance(x, str) and x)
        if traffic_result:
            for anom in (traffic_result.get("anomalies") or []):
                if not isinstance(anom, dict):
                    continue
                for pkey in ("prefix", "affected_prefix"):
                    pval = anom.get(pkey)
                    if isinstance(pval, str) and pval:
                        affected_prefixes.add(pval)

        if traffic_result:
            exc_list = traffic_result.get("anomalies") or []
            if exc_list:
                first_anomaly = exc_list[0]
                traffic_context["affected_prefix"] = first_anomaly.get("prefix") or first_anomaly.get("affected_prefix")
                drop_ratio_val = first_anomaly.get("drop_percent") or first_anomaly.get("percent_change")
                if drop_ratio_val is None and traffic_result.get("percent_change") is not None:
                    drop_ratio_val = abs(traffic_result["percent_change"])
                if isinstance(drop_ratio_val, (int, float)):
                    traffic_context["traffic_drop_ratio"] = min(1.0, abs(drop_ratio_val) / 100.0)

        # ── routing_state: which ASes originate the affected prefixes ──────
        prefix2as_file = None
        if isinstance(routing_result, dict):
            prefix2as_file = routing_result.get("prefix2as_file")
        if prefix2as_file and affected_prefixes:
            topology_context["routing_state"] = build_routing_state(
                prefix2as_file, sorted(affected_prefixes),
            )
            logger.info(
                f"[HCAF] routing_state: {len(topology_context['routing_state'])} ASes "
                f"originate {len(affected_prefixes)} affected prefix(es)"
            )

        return routing_timeline, traffic_timeline, routing_context, traffic_context, topology_context

    def compute_hcaf_attribution(self, context):
        """Attribute the direction of a routing/traffic pair with PADDLE.

        PADDLE -- Paired Displacement, Difference-in-differences, with
        Ledger Evidence -- is the only causal estimator in this
        codebase.  It anchors on the **data plane's trough** (the moment
        the traffic stopped, which is sharp and well located) and asks
        the control plane, at that moment, how far from its same-clock
        ordinary-day behaviour it was.  The direction is committed only
        when all four vetoes pass: precedence, exclusivity against the
        placebo null, scope, and congruence.

        The estimator abstains rather than guessing, and it reports which
        veto stopped it.
        """
        routing_result = context.routing_result
        traffic_result = context.traffic_result

        if not routing_result or not traffic_result:
            logger.info("[HCAF] missing routing_result or traffic_result; skipping causal attribution")
            context.hcaf_attribution_status = "skipped"
            return None

        try:
            from agents.paddle_runtime import run_paddle
        except ImportError as e:
            logger.warning(f"[HCAF] paddle_runtime_import_failed: {e}")
            context.hcaf_attribution_status = "failed"
            return None

        routing_timeline, traffic_timeline, routing_context, traffic_context, topology_context = self.build_hcaf_timelines(routing_result, traffic_result)

        # Only skip when BOTH timelines are empty. Traffic-only or routing-only
        # events still provide partial evidence that the LLM report can reason about.
        if not routing_timeline and not traffic_timeline:
            logger.info(f"[HCAF] insufficient_timeline_data: routing={len(routing_timeline)}, traffic={len(traffic_timeline)}; skipping")
            context.hcaf_attribution_status = "skipped"
            return None

        if not routing_timeline:
            logger.info(f"[HCAF] routing timeline empty; continuing with traffic data only ({len(traffic_timeline)} points)")
        elif not traffic_timeline:
            # Note: the log wording "traffic timeline is empty" was once misread as traffic data being empty.
            # It actually means traffic_result['anomalies'] is empty (detector miss),
            # while percent_change / peak_trough_drop_pct can still show the traffic drop.
            pct = traffic_result.get("percent_change") if traffic_result else None
            peak_drop = traffic_result.get("peak_trough_drop_pct") if traffic_result else None
            extra = ""
            if isinstance(pct, (int, float)) or isinstance(peak_drop, (int, float)):
                extra = f" (note: traffic_result exists, percent_change={pct}%, peak_trough_drop={peak_drop}% - anomaly detection produced no anomaly, but the drop data is still usable as context)"
            logger.info(
                f"[HCAF] traffic_timeline(anomalies) empty; continuing with routing data only ({len(routing_timeline)} points){extra}"
            )

        target_as_val = int(context.asn) if str(context.asn).isdigit() else None
        window_start = paddle_parse(context.start_time)
        window_end = paddle_parse(context.end_time)

        # The control plane is measured on the detector's own routing
        # features -- the target's *own* announcements, the channel that
        # falls silent during an outage.  The traffic side is the signed
        # deviation of every observation from the detector's own
        # historical baseline, which is what makes the trough the moment
        # the traffic stopped.
        routing_analysis = (routing_result.get("outage_analysis")
                            or routing_result.get("outage") or {})
        try:
            verdict, control_series, traffic_observations = run_paddle(
                routing_analysis=routing_analysis,
                traffic_timeline=traffic_timeline,
                routing_timeline=routing_timeline,
                routing_context=routing_context,
                traffic_block=traffic_result,
                window_start=window_start,
                window_end=window_end,
            )
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning(f"[HCAF] paddle_call_failed: {e}")
            context.hcaf_attribution_status = "failed"
            return None

        direction_val = verdict.direction if verdict.committed else "unknown"
        logger.info(
            f"[PADDLE] direction={direction_val} reason={verdict.reason} "
            f"vetoes={verdict.vetoes} channel={verdict.channel} "
            f"lag={verdict.lag_seconds} ratio={verdict.exclusivity_ratio}"
        )

        tau_traffic = (verdict.tau_response.isoformat()
                       if verdict.tau_response else None)
        return {
            "direction": direction_val,
            "committed": verdict.committed,
            "reason": verdict.reason,
            "vetoes": dict(verdict.vetoes),
            "tau_routing": verdict.tau_control,
            "tau_traffic": tau_traffic,
            "lag": verdict.lag_seconds,
            "effect": verdict.effect,
            "p_value": None,
            "n_placebos": None,
            "horizon": None,
            "mechanism": verdict.mechanism,
            "tests": verdict.tests,
            "n_buckets": control_series.n_buckets,
            "strength": "strong" if verdict.committed else "none",
            "strength_score": 1.0 if verdict.committed else 0.0,
            "confidence": 1.0 if verdict.committed else 0.0,
            "is_causal": verdict.committed,
            "convergence": 1.0 if verdict.committed else 0.0,
            "routing_causes_traffic": direction_val == "routing_to_traffic",
            "traffic_causes_routing": direction_val == "traffic_to_routing",
            "explanation": paddle_explanation(verdict),
            "limitations": paddle_limitations(verdict),
            "novel_findings": [],
            "confounders": [],
            "evidence_support": {
                "method": "paddle_veto_test",
                "vetoes": dict(verdict.vetoes),
                "reason": verdict.reason,
                "p_value": None,
                "n_placebos": None,
                "lag": verdict.lag_seconds,
                "tau_routing": verdict.tau_control,
                "tau_traffic": tau_traffic,
                "horizon": None,
                "mechanism": verdict.mechanism,
                "channel": verdict.channel,
                "effect": verdict.effect,
                "exclusivity_ratio": verdict.exclusivity_ratio,
                "baseline_displacement": verdict.baseline_displacement,
                "tests": verdict.tests,
            },
            "target_as": target_as_val,
        }

    @staticmethod
    def collect_causal_evidence(routing_result, traffic_result):
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

    async def build_evidence_chain(self, context):
        """Run EvidenceChainBuilder on the traffic/routing/bayesian/causal inputs and stash the chain on the context."""
        try:
            builder = EvidenceChainBuilder()
            agent_judgement = self.extract_agent_judgement(context)
            chain = builder.build(
                traffic_result=context.traffic_result or {},
                routing_result=context.routing_result or {},
                causal_analysis=context.causal_analysis,
                bayesian_result=context.bayesian_result,
                asn=str(context.asn),
                time_range=f"{context.start_time} to {context.end_time}",
                agent_judgement=agent_judgement,
            )
            chain_dict = builder.to_dict(chain)
            logger.info(f"evidence chain built: verdict={chain.verdict}, confidence={chain.confidence:.1%}")
            arb = chain.arbitration or {}
            if arb.get("agent_overrode_rule"):
                logger.info(
                    f"[Arbitration] agent overrode the detector rule: "
                    f"{arb.get('rule_verdict')} -> {arb.get('agent_proposed_verdict')} "
                    f"(confidence {arb.get('agent_confidence'):.2f})"
                )
            # Enumerate the verdict classes this decision rejected, and
            await self.record_rejected_verdicts(context, builder, chain.verdict)
            await self.record_arbitration(context, arb)
            return chain_dict
        except (AttributeError) as e:
            logger.warning(f"evidence chain build failed: {e}")
            return None

    def extract_agent_judgement(self, context) -> dict:
        """Pull the reasoning agent's structured proposal out of the run.

        The reasoning agent classifies the incident and scores its own
        confidence.  Those are the agent's own opinion, so they are what
        the verdict arbitration is allowed to consider — but the
        arbitration still applies a confidence floor and only accepts a
        proposal expressed in the five-class vocabulary.
        """
        reasoning = context.reasoning_result or {}
        if not isinstance(reasoning, dict):
            return {}

        classification = reasoning.get("llm_classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        if classification.get("source") != "llm":
            return {}

        final_classification = reasoning.get("final_classification") or {}
        if isinstance(final_classification, dict):
            integrated = final_classification.get("integrated_findings")
            if isinstance(integrated, dict) and integrated.get("incident_type"):
                classification = {
                    **classification,
                    "incident_type": integrated.get("incident_type"),
                }

        verdict = classification.get("incident_type") or ""
        if not verdict:
            return {}
        return {
            "verdict": verdict,
            "confidence": classification.get("confidence", 0.0),
            "cause": classification.get("cause") or classification.get("incident_type") or "",
            "reasoning": classification.get("reasoning") or "",
            "sub_type": classification.get("sub_type") or "",
            "alternative_types": classification.get("alternative_types") or [],
        }

    async def record_arbitration(self, context, arbitration: dict) -> None:
        """Write the rule/agent arbitration onto the blackboard."""
        if not arbitration:
            return
        bb = context.get_blackboard()
        await bb.write("verdict", "arbitration", arbitration)
        if arbitration.get("agent_overrode_rule"):
            await bb.add_alternative({
                "source": "EvidenceChainBuilder",
                "kind": "rejected_verdict",
                "alternative": arbitration.get("rule_verdict"),
                "reason": (
                    f"detector rule proposed {arbitration.get('rule_verdict')}; "
                    f"reasoning agent proposed "
                    f"{arbitration.get('agent_proposed_verdict')} at confidence "
                    f"{arbitration.get('agent_confidence')}"
                ),
            })

    async def record_rejected_verdicts(self, context, builder, chosen_verdict: str) -> None:
        """Write the rejected verdict classes to the board as alternatives."""
        try:
            rejected = builder.enumerate_rejected_verdicts(
                traffic_result=context.traffic_result or {},
                routing_result=context.routing_result or {},
                causal_analysis=context.causal_analysis,
                bayesian_result=context.bayesian_result,
                chosen_verdict=chosen_verdict,
            )
            if not rejected:
                return
            bb = context.get_blackboard()
            for alternative, reason in rejected:
                await bb.add_alternative({
                    "source": "EvidenceChainBuilder",
                    "alternative": alternative,
                    "summary": f"Competing verdict class rejected: {alternative}",
                    "competes_with": chosen_verdict,
                    "rejected_because": reason,
                    "confidence": 1.0,
                    "derived_from": ["evidence_chain.verdict"],
                })
        except (AttributeError) as exc:  # noqa: BLE001
            logger.warning(f"[Workflow] failed to record rejected verdicts: {exc}")

    # ── Skip-reasoning policy ─────────────────────────────────────────────
    _TIER_ORDER = {"INSUFFICIENT": 0, "C1": 1, "C2": 2, "C3": 3}

    def record_stage_execution(self, context, stage: str, *, ran: bool,
                                detail: str = ""):
        """Record that a coordination stage did or did not run.

        The component ablation is a claim about attribution, and a
        claim that is not checked is not a measurement.  This writes
        the run's own account of which stages executed, so the
        evaluation can compare the arms against it: an arm that
        disabled one stage but also skipped another would show up as
        a mismatch rather than as a larger delta.
        """
        record = context.stage_execution
        if not isinstance(record, dict):  # pragma: no cover - defensive
            return
        entry = record.get(stage) or {}
        entry["ran"] = bool(ran)
        if detail:
            entry["detail"] = str(detail)
        record[stage] = entry

    def should_skip_reasoning(self, context):
        """Whether to short-circuit the reasoning stage.

        The skip policy exists to avoid paying for reasoning when the
        data plainly shows there is nothing to reason about.  It is a
        *cost* optimisation, and it is not part of what any ablation
        arm measures.

        A component ablation disables exactly one stage so that the
        delta against the full agent is attributable to that stage
        alone.  The joint-evidence tier is the gate below, and the tier
        is an *output* of the joint-evidence stage: ablating that stage
        drops the tier to INSUFFICIENT, and using that as grounds to
        skip the reasoning stage would make the measured delta belong
        to two stages rather than one.  Using a stage's own absence as
        evidence against the next stage is never sound.

        So during an ablation run the gate is suspended entirely.  Every
        stage that is not itself ablated runs, which is what makes the
        arms comparable to each other: the "no joint evidence" arm then
        differs from the full agent only in the joint-evidence stage,
        and the "no reasoning" arm only in the reasoning stage.

        The decision is recorded in the validation notes so that a run
        can be audited afterwards rather than the property being taken
        on trust.
        """
        if not self.skip_unnecessary_analysis:
            return False

        if context.anomalies_detected:
            return False

        # Any active ablation suspends the cost gate.  This is broader
        # than the joint-evidence case on purpose: the gate reads the
        # joint tier and the HCAF score, and *any* ablation arm must
        # run the stages it did not disable, whatever the tier happens
        # to be.
        #
        # The campaign switch extends the same treatment to the "full"
        # baseline arm.  The single-variable property belongs to the
        # comparison, not to one arm: if the baseline could skip
        # reasoning while an ablated arm could not, the measured delta
        # would belong to the stage under test *and* to the gate, which
        # is the same confound this gate was the source of in the first
        # place.  Every arm therefore runs every stage it did not
        # disable.
        active = [name for name, off in (self.ablate or {}).items() if off]
        if active or ablation_campaign_active():
            context.validation_notes.append({
                "case": "reasoning_not_skipped",
                "severity": "info",
                "message": (
                    f"Component ablation active ({', '.join(sorted(active)) or 'full baseline'}): "
                    "the skip-reasoning cost gate is suspended so that every "
                    "stage that is not itself ablated still runs. This keeps "
                    "the arm single-variable."
                ),
            })
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

    async def handle_reasoning(self, context):
        from agents.reasoning_agent import run_reasoning_agent
        from agents.hypothesis_manager import HypothesisAgent

        if self.should_skip_reasoning(context):
            skip_reason = context.validation_notes[-1].get("message", "skipped") if context.validation_notes else "no_anomalies_detected"
            context.reasoning_result = {"success": True, "skipped": True, "reason": skip_reason}
            self.record_stage_execution(
                context, "reasoning", ran=False, detail=skip_reason)
            return WorkflowEvent.REASONING_COMPLETE

        try:
            reasoning_start = context.start_time
            reasoning_end = context.end_time

            if self.ablate.get("reasoning"):
                logger.info("[Reasoning] ablated — skipping multi-round reasoning")
                context.reasoning_result = {
                    "success": True,
                    "skipped": True,
                    "reason": "reasoning ablated",
                    "rounds_performed": 0,
                    "reasoning_trace": ["Reasoning stage ablated for component ablation."],
                }
                self.record_stage_execution(
                    context, "reasoning", ran=False,
                    detail="ablated by BGP_TRACER_ABLATE_REASONING")
            else:
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
                self.record_stage_execution(
                    context, "reasoning", ran=True,
                    detail=f"rounds={context.reasoning_result.get('rounds_performed')}"
                           if isinstance(context.reasoning_result, dict) else "ran")

            # ── Shared Blackboard: one board for the whole run ──
            bb = context.get_blackboard()

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

            # ── Hypothesis generation ──
            if self.ablate.get("hypothesis"):
                logger.info("[HypothesisAgent] ablated — skipping hypothesis generation")
                claims = []
                self.record_stage_execution(
                    context, "hypothesis", ran=False,
                    detail="ablated by BGP_TRACER_ABLATE_HYPOTHESIS")
            else:
                hypothesis_agent = HypothesisAgent(bb)
                await hypothesis_agent.start()
                hyp_result = await hypothesis_agent.step()
                claims = await bb.read("diagnosis", "claims", []) or []
                self.record_stage_execution(
                    context, "hypothesis", ran=True,
                    detail=f"claims={len(claims or [])}")

            # Promote the generated hypotheses into the typed claim records
            for claim in claims:
                if not isinstance(claim, dict):
                    claim = getattr(claim, "__dict__", None) or {}
                if not claim:
                    continue
                try:
                    await bb.add_claim({
                        "source": "HypothesisAgent",
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
                except (AttributeError) as exc:  # noqa: BLE001
                    logger.warning(f"[Workflow] failed to promote hypothesis to claim: {exc}")

            # Persist the board onto the context. Without this the local
            board = await bb.read_evidence_board()
            context.evidence_records = board.get("observations", []) or []
            context.diagnosis_claims = claims
            context.verification_records = board.get("verdicts", []) or []
            context.contradictions = board.get("challenges", []) or []
            context.evidence_alternatives = board.get("alternatives", []) or []
            context.evidence_gaps = board.get("gaps", []) or []

            # Rebuild the evidence chain now that the reasoning agent has
            # judged.  The chain was first built in the joint-evidence
            # stage, before any agent had an opinion; this second build
            # lets the agent's structured proposal arbitrate against the
            # detector rule, and records the disagreement either way.
            rebuilt = await self.build_evidence_chain(context)
            if rebuilt:
                context.evidence_chain = rebuilt

            # ── Enhanced mode: LLM debate + online evaluation + reactive decisions ──
            return WorkflowEvent.REASONING_COMPLETE
        except Exception as e:
            logger.error(f"Reasoning failed: {e}")
            raise RetryableError(f"Reasoning error: {e}")

    async def handle_validation(self, context):
        quality_score = self.calculate_quality_score(context)
        context.confidence_score = quality_score
        context.data_quality = self.assess_data_quality(context)

        # ── Record the missing / degraded inputs as first-class records ──
        try:
            await self.record_evidence_gaps(context, quality_score)
        except (AttributeError) as exc:  # noqa: BLE001
            logger.warning(f"[Validation] failed to record evidence gaps: {exc}")

        # Victim traffic is evidence for the final report, so collect it
        bb_for_victim = context.get_blackboard()
        if context.victim_asns:
            await bb_for_victim.write("routing", "victim_asns", context.victim_asns)
            await self.fetch_victim_traffic(context, bb_for_victim)
        if quality_score < 0.5:
            context.validation_notes.append({
                "case": "low_data_quality",
                "severity": "warning",
                "message": "Evidence completeness is low; the report will state data gaps and uncertainty explicitly",
                "details": {"quality_score": quality_score},
            })
        # Inconclusive evidence is still a valid operational outcome. The report
        # must be produced so operators can distinguish it from a pipeline error.
        return WorkflowEvent.VALIDATION_PASSED

    async def record_evidence_gaps(self, context, quality_score: float) -> None:
        """Write the missing / degraded inputs to the board as typed gaps."""
        bb = context.get_blackboard()
        traffic = context.traffic_result or {}
        routing = context.routing_result or {}

        def unavailable(result: dict) -> str:
            if not result:
                return "missing"
            if result.get("data_available") is False:
                return "missing"
            if result.get("success") is False:
                return "degraded"
            return ""

        traffic_state = unavailable(traffic)
        if traffic_state:
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "traffic_data_unavailable",
                "summary": (
                    f"Traffic evidence unavailable ({traffic.get('no_data_reason') or traffic.get('error') or 'no data'})"
                ),
                "severity": traffic_state,
                "impact": (
                    "The traffic side of the correlation is unobserved; a "
                    "routing-only verdict cannot be distinguished from a "
                    "routing-and-traffic verdict."
                ),
                "confidence": 1.0,
                "derived_from": ["traffic.result"],
            })

        routing_state = unavailable(routing)
        if routing_state:
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "routing_data_unavailable",
                "summary": (
                    f"Routing evidence unavailable ({routing.get('no_data_reason') or routing.get('error') or 'no data'})"
                ),
                "severity": routing_state,
                "impact": (
                    "The routing side of the correlation is unobserved; a "
                    "traffic-only anomaly cannot be attributed to a BGP cause."
                ),
                "confidence": 1.0,
                "derived_from": ["routing.result"],
            })

        # A cross-layer mismatch is a gap in the *correlation* itself: one
        # side fired and the other did not, so the pair cannot support a
        # causal reading in either direction.
        traffic_anomalies = bool(
            traffic.get("anomalies_detected")
            or traffic.get("anomaly_count")
            or traffic.get("anomalies")
        )
        routing_anomalies = bool(
            routing.get("origin_hijacked") or routing.get("origin_hijacking")
            or routing.get("forge_hijacked") or routing.get("forge_hijacking")
            or routing.get("route_leaks") or routing.get("anomaly_count")
        )

        # The leak detector saturates on this corpus: it reports a truncated
        # result set for most windows, and a truncated leak count carries no
        # information about *which* prefixes were leaked.  A downstream reader
        # of the board would otherwise take the leak count at face value, so
        # the saturation is recorded as a first-class degraded input.
        if routing.get("leak_results_truncated"):
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "leak_detector_saturated",
                "summary": (
                    "Route-leak detection hit the detector's result limit; the "
                    "reported leak count is a floor, not a total."
                ),
                "severity": "degraded",
                "impact": (
                    "The leak count cannot support a route-leak conclusion on "
                    "its own, because the detector ran out of room before it "
                    "ran out of leaks."
                ),
                "confidence": 1.0,
                "derived_from": ["routing.result"],
            })
        if routing.get("leak_analysis_skipped"):
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "leak_analysis_not_run",
                "summary": "Route-leak detection did not run for this window.",
                "severity": "missing",
                "impact": (
                    "No route-leak evidence exists for this window; the "
                    "absence of a leak finding is not evidence of no leak."
                ),
                "confidence": 1.0,
                "derived_from": ["routing.result"],
            })

        if traffic_anomalies != routing_anomalies:
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "cross_layer_mismatch",
                "summary": (
                    ("Traffic anomalies present without a routing cause"
                     if traffic_anomalies else
                     "Routing anomalies present without a measurable traffic effect")
                ),
                "severity": "degraded",
                "impact": (
                    "One layer of the correlation is silent, so the direction "
                    "of causation is not established by this evidence."
                ),
                "confidence": 0.8,
                "derived_from": ["traffic.result", "routing.result"],
            })

        if quality_score < 0.5:
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "low_evidence_completeness",
                "summary": (
                    f"Evidence completeness score {quality_score:.2f} is below the 0.50 threshold"
                ),
                "severity": "degraded",
                "impact": "The verdict rests on partial evidence and should be treated as provisional.",
                "confidence": 1.0,
                "derived_from": ["validation.quality_score"],
            })

        # A falsification card that found no alternative explanation is not
        # a gap; but a *failed* causal attribution is, because it removes
        # the directional reading of the evidence.
        if getattr(context, "hcaf_attribution_status", "") == "failed":
            await bb.add_gap({
                "source": "WorkflowEngine",
                "kind": "causal_attribution_unavailable",
                "summary": "Causal attribution did not produce a result for this window.",
                "severity": "degraded",
                "impact": "The direction of causation between routing and traffic is not established.",
                "confidence": 1.0,
                "derived_from": ["hcaf_attribution_status"],
            })

    async def fetch_victim_traffic(self, context, bb):
        """Fetch traffic data for victim ASes discovered from routing events.
        Writes results to blackboard under 'routing' section.
        Non-blocking (fire-and-forget from caller)."""
        from agents.traffic_agent import run_traffic_agent
        try:
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
                except (ValueError) as exc:
                    return vas, {"success": False, "data_available": False, "error": str(exc)}

            pairs = await asyncio.gather(*(fetch(vas) for vas in victim_asns))
            results = dict(pairs)
            await bb.write("routing", "victim_traffic_results", results)
            logger.info(f"[workflow] Fetched victim traffic for {len(results)} ASes")
        except (AttributeError) as exc:
            logger.warning(f"[workflow] Victim traffic fetch failed: {exc}")
    
    async def handle_data_enrichment(self, context):
        """Enrich context with additional data (org info, relationships, ThreatIntel, etc.)."""
        from agents.coordination_utils import (
            lookup_org_info,
            query_as_relationships,
            query_as_prefixes
        )
        from tools.tool_implementations import lookup_as_threat_intel

        if self.ablate.get("enrichment"):
            logger.info("[Enrichment] ablated — skipping auxiliary enrichment")
            context.org_info = None
            context.as_relationships = None
            context.as_prefixes = None
            self.record_stage_execution(
                context, "enrichment", ran=False,
                detail="ablated by BGP_TRACER_ABLATE_ENRICHMENT")
            return WorkflowEvent.DATA_COLLECTED
        
        # Load data files from reasoning result AND routing result if available
        asrel_file = None
        prefix2as_file = None
        asorg_file = None
        
        # Try reasoning_result first
        if context.reasoning_result:
            asrel_file = context.reasoning_result.get("as_rel_file")
            prefix2as_file = context.reasoning_result.get("prefix2as_file")
            asorg_file = context.reasoning_result.get("asorg_file")
        
        # If absent, fall back to routing_result (routing_impl.py sets these fields)
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

        def safe_getattr(obj, attr, default=None):
            """Access dict key or object attribute, returning default on failure."""
            if isinstance(obj, dict):
                return obj.get(attr, default)
            return getattr(obj, attr, default) if hasattr(obj, attr) else default

        if rr:
            for ev in (rr.get("origin_hijacked") or hijack_section.get("origin_hijacked") or []):
                if safe_getattr(ev, "hijacker_as"):
                    attacker_asn_for_intel = str(safe_getattr(ev, "hijacker_as") or safe_getattr(ev, "hijacker_asn"))
                    break
            if not attacker_asn_for_intel:
                for ev in (rr.get("origin_hijacking") or hijack_section.get("origin_hijacking") or []):
                    if safe_getattr(ev, "origin_as"):
                        attacker_asn_for_intel = str(safe_getattr(ev, "origin_as"))
                        break
            if attacker_asn_for_intel:
                try:
                    threat_intel_result = await lookup_as_threat_intel(
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
                except (AttributeError) as exc:
                    logger.warning(f"[workflow] Threat intel lookup failed: {exc}")

        # Propagate ThreatIntel to blackboard
        if context.shared_blackboard and threat_intel_result:
            await context.shared_blackboard.write(
                "routing", "threat_intel_result", threat_intel_result
            )

        self.record_stage_execution(
            context, "enrichment", ran=True,
            detail="org/relationships/prefixes resolved")
        return WorkflowEvent.DATA_COLLECTED
    
    async def handle_report_generation(self, context):
        """Generate final report — MultiAgentReportAgent in enhanced mode, original ReportAgent otherwise."""
        from agents.report_agent import ReportAgent
        from utils.logger import logger as log

        # One Blackboard per run, shared by every stage (see
        # ``WorkflowContext.get_blackboard``).
        bb = context.get_blackboard()

        await bb.write("config", "asn", context.asn)
        await bb.write("config", "start_time", context.start_time)
        await bb.write("config", "end_time", context.end_time)

        # Propagate validated joint-analysis artifacts so every report path has
        # access to the same evidence contract.
        await bb.write("validation", "causal_analysis", context.causal_analysis or {})
        await bb.write("validation", "joint_alert", context.joint_alert or context.causal_analysis or {})
        # ── Three-card joint-evidence (C1/C2/C3 tier) ──────────────────────
        await bb.write("validation", "joint_tier", getattr(context, "joint_tier", "") or "")
        await bb.write("validation", "joint_score", getattr(context, "joint_score", 0.0) or 0.0)
        await bb.write("validation", "joint_evidence_cards", getattr(context, "joint_evidence_cards", []) or [])
        await bb.write("validation", "joint_rationale", getattr(context, "joint_rationale", "") or "")
        await bb.write("validation", "hcaf_attribution", context.hcaf_attribution or {})
        await bb.write("validation", "hcaf_attribution_status", context.hcaf_attribution_status or "skipped")
        await bb.write("evidence", "chain", context.evidence_chain or {})
        await bb.write("evidence", "validation_notes", context.validation_notes)

        # Re-sync the typed record lists from the board. The gap records are
        board_snapshot = await bb.read_evidence_board()
        context.evidence_records = board_snapshot.get("observations", []) or []
        context.evidence_alternatives = board_snapshot.get("alternatives", []) or []
        context.evidence_gaps = board_snapshot.get("gaps", []) or []
        context.contradictions = board_snapshot.get("challenges", []) or []
        context.verification_records = board_snapshot.get("verdicts", []) or []

        # The board's typed record surface is the last of the six
        # ablatable stages, so its state is recorded here, where the
        # surface is read back.
        self.record_stage_execution(
            context, "evidence_board",
            ran=not bb.record_surface_off(),
            detail=("typed record surface off" if bb.record_surface_off()
                    else f"observations={len(context.evidence_records)}"))

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
        # Merge (not replace) the typed record lists into the evidence
        await bb.merge_evidence({
            "observations": context.evidence_records or [],
            "claims": context.diagnosis_claims or [],
            "challenges": context.contradictions or [],
            "verdicts": context.verification_records or [],
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
        }, _writer="WorkflowEngine.report")

        # ── Enhanced mode: route to report generation ──
        legacy_html = await self.run_legacy_report(bb, context, ReportAgent, log)
        html = legacy_html or bb._sections.get("report", {}).get("html") or ""

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
            except (AttributeError) as e:
                log.warning(f"Failed to save report: {e}")

        context.final_result = context.final_result or {}
        context.final_result["html"] = html
        context.final_result["report_path"] = context.report_path
        return WorkflowEvent.REPORT_GENERATED

    async def run_legacy_report(self, bb, context, ReportAgent, log):
        """Run the legacy single-agent ReportAgent and return its HTML.
        
        When the LLM-driven path fails (timeout / empty / balance validation)
        AND REPORT_REQUIRE_LLM is NOT set, fall back to the deterministic
        HTML renderer so the user always receives a useful report rather
        than a workflow-level error.  The deterministic fallback uses the
        same structured payload the LLM would have seen — it is not a
        hardcoded prose template, it is data-driven HTML."""
        agent = ReportAgent(bb, enhanced=bool(getattr(context, "enhanced", False)))
        await agent.start()
        result = await agent.step()
        if result is None:
            log.error("ReportAgent returned None")
        elif not result.success:
            error_msg = str(result.error) if result.error is not None else "Unknown error"
            log.error(f"ReportAgent failed: {error_msg}")
        else:
            # Success — fetch the legacy report HTML from the Blackboard
            # so the caller can use it as the final report.
            try:
                legacy_html = await bb.read("report", "html") or ""
            except (ValueError):
                legacy_html = ""
            if legacy_html:
                return legacy_html
            log.warning("[workflow] ReportAgent returned success but no HTML "
                        "on blackboard; will use deterministic fallback.")

        # ── Deterministic fallback (uses real data, not hardcoded prose) ──
        try:
            from agents.report_agent import ReportAgent
            traffic_result = await bb.read("traffic", "result") if bb else None
            routing_result = await bb.read("routing", "result") if bb else None
            reasoning_result = await bb.read("reasoning", "result") if bb else None
            if hasattr(traffic_result, "__await__"):
                traffic_result = await traffic_result
            if hasattr(routing_result, "__await__"):
                routing_result = await routing_result
            if hasattr(reasoning_result, "__await__"):
                reasoning_result = await reasoning_result
            fallback_html = ReportAgent._render_fallback_html(
                None,
                asn=str(getattr(context, "asn", "?")),
                start_time=str(getattr(context, "start_time", "")),
                end_time=str(getattr(context, "end_time", "")),
                traffic_result=traffic_result,
                routing_result=routing_result,
                reasoning_result=reasoning_result,
            )
            if fallback_html:
                log.info("[workflow] Deterministic fallback HTML generated "
                         f"({len(fallback_html)} chars)")
                return fallback_html
        except (AttributeError) as fb_err:
            log.error(f"[workflow] Deterministic fallback also failed: {fb_err!r}")

        # If fallback also fails AND REPORT_REQUIRE_LLM is set, raise so
        # the orchestrator can surface the error properly.
        require_llm = (
            os.environ.get("REPORT_REQUIRE_LLM", "0").strip().lower()
            in ("1", "true", "yes")
        )
        if require_llm:
            raise RetryableError(
                f"Report generation failed and fallback disabled: "
                f"{result.error if result else 'no result'}"
            )
        # Otherwise return empty (orchestrator already saw the fallback attempt)
        return ""

    async def handle_complete(self, context):
        """Handle completion state."""
        return WorkflowEvent.COMPLETE
    
    async def handle_error(self, context):
        """Handle error state."""
        return WorkflowEvent.ERROR
    
# Quality Assessment
    
    def assess_data_quality(self, context):
        """Assess overall data quality."""
        score = self.calculate_quality_score(context)
        
        if score >= 0.8:
            return "High"
        elif score >= 0.5:
            return "Medium"
        else:
            return "Low"
    
    def calculate_quality_score(self, context):
        """Calculate a 0-1 quality score based on available data."""
        score = 0.0
        factors = 0

        # Traffic data quality — only count when data is actually available.
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


# Convenience Functions

async def run_workflow(
    user_input = None,
    asn = None,
    start_time = None,
    end_time = None,
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
    """Run the complete workflow with the given parameters.
    
    Returns:
    WorkflowContext with all results and execution trace"""
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
        enable_mitm=enable_mitm,  # forward the MITM detection switch
        buffer_hours=buffer_hours,  # None -> dataclass default (2.0) if not overridden
        enhanced=enhanced,
        debate_rounds=debate_rounds,
        evaluation_retries=evaluation_retries,
        event_type=event_type,
        as_role=as_role,
        precomputed_routing=precomputed_routing,
        precomputed_traffic=precomputed_traffic,
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


def snapshot_context(context: "WorkflowContext"):
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
    except (ValueError):
        return None


def extract_anomaly_windows(anomalies, buffer_hours = 2):
    """Extract time windows from traffic anomaly timestamps."""
    from datetime import timedelta
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
    except (ValueError):
        return []


def union_anomaly_windows(windows, buffer_hours = 2):
    """Merge multiple anomaly windows into a single unified window that covers all anomalies.
    
    Returns:
    A single {"start": "...", "end": "..."} covering all windows"""
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
    except (KeyError, IndexError):
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
]