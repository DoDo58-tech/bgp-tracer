import os
import sys
import json
from datetime import datetime, timedelta
from typing import Optional

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from llm.prompt import build_multi_agent_coordination_prompt, get_reasoning_laws
from agents.routing_agent import run_routing_agent, run_routing_agent_async
from agents.traffic_agent import run_traffic_agent
from agents.payload_builder import (
    build_payload, cap_payload, to_json_for_prompt,
    PayloadBudget, estimate_tokens,
)
from agents.coordination_utils import (
    clean_timestamps,
    count_consecutive_anomalies_in_longest_period,
    extract_anomaly_time_range,
    identify_consecutive_anomaly_periods,
    lookup_org_info, query_as_relationships, query_as_prefixes
)
from agents.llm_reasoning import (
    LLMIncidentClassifier,
    LLMSeverityAssessor,
    LLMTrafficCorrelator,
)
from utils.logger import logger
from utils.helpers import extract_json_object as _extract_json_object
from config import BASE_URL, API_KEY, MODEL
from detectors.outage.outage_detector import RouteOutageDetector

# Lazy initialization for OUTAGE_DETECTOR to avoid import issues
_OUTAGE_DETECTOR = None

def get_outage_detector():
    global _OUTAGE_DETECTOR
    if _OUTAGE_DETECTOR is None:
        _OUTAGE_DETECTOR = RouteOutageDetector()
    return _OUTAGE_DETECTOR


class ReasoningAgent:
    def __init__(
        self,
        asn,
        start_time,
        end_time,
        model=MODEL,
        uuid="",
        pre_computed_routing=None,
        pre_computed_traffic=None,
        buffer_hours=0,
        use_llm_reasoning: bool = True,
        run_id: str = "",
    ):
        self.run_id = run_id
        self.asn = asn
        self.start_time = start_time
        self.end_time = end_time
        self.model = model
        self.uuid = uuid
        self.pre_computed_routing = pre_computed_routing
        self.pre_computed_traffic = pre_computed_traffic
        self.buffer_hours = buffer_hours
        self.use_llm_reasoning = use_llm_reasoning

        self.llm, self.token_counter = setup_llm_settings(
            model=self.model,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=DEFAULT_TEMP_REASONING
        )

        if self.use_llm_reasoning:
            self.incident_classifier = LLMIncidentClassifier()
            self.severity_assessor = LLMSeverityAssessor()
            self.traffic_correlator = LLMTrafficCorrelator()
        else:
            self.incident_classifier = None
            self.severity_assessor = None
            self.traffic_correlator = None

        self.reasoning_trace = []
        self.evidence_pool = {}
        self.confidence_scores = {}
        self.round_count = 0
        self.structured_facts = []
        self.retrieved_context = []
        # Per-round summary accumulator for multi-round reasoning.
        # In round > 1, the LLM prompt only receives previous rounds' summaries
        # (not the full routing/traffic dumps), reducing token consumption by
        # 40-60% in typical 3-round runs.
        self._round_summaries: list[dict] = []

        # Evidence gap detection for proactive data collection.
        # 用于主动识别缺失的证据并规划数据收集
        self._evidence_gaps: list[dict] = []
        self._gap_resolutions: dict[str, str] = {}

    def perform_multi_round_analysis(self, max_rounds = 3, workflow_claims = None):
        """
        Args:
            max_rounds: Maximum reasoning rounds
            workflow_claims: Pre-generated claims from workflow_engine's HypothesisAgent.
                             If provided, skip local hypothesis generation to avoid
                             duplicate work.
        """
        try:
            self.reasoning_trace.append(f"Starting multi-round analysis for ASN {self.asn}")
            self.reasoning_trace.append(f"Time range: {self.start_time} to {self.end_time}")
            
            initial_data = self.phase1_data_collection()
            
            if not initial_data.get("success", False):
                return {
                    "success": False,
                    "error": "Data collection failed",
                    "reasoning_trace": self.reasoning_trace
                }
            
            # ── Phase 1.5: Multi-Role Classification ──────────────────────────
            # Before enrichment, understand the AS's full role picture
            multi_role_result = self.classify_multi_role(initial_data)
            if multi_role_result:
                initial_data["multi_role"] = multi_role_result

            # ── Phase 1.6: Auxiliary Enrichment (InvestigationSupervisor) ────
            # Run enrichment BEFORE reasoning rounds so LLM has full context
            enrichment_result = self.run_auxiliary_enrichment(initial_data)
            if enrichment_result:
                initial_data["enrichment"] = enrichment_result

            # ── Phase 1.7: Evidence Gap Detection (Bug Fix 3.1) ─────────────
            # Identify missing evidence types to guide reasoning direction
            routing_data = initial_data.get("routing_data", {})
            traffic_data = initial_data.get("traffic_data", {})
            self.identify_evidence_gaps(routing_data, traffic_data, enrichment_result)

            for round_num in range(1, max_rounds + 1):
                self.round_count = round_num
                self.reasoning_trace.append(f"\n=== ROUND {round_num} REASONING ===")
                
                round_result = self.perform_reasoning_round(initial_data, round_num)
                
                if self.should_conclude_analysis():
                    self.reasoning_trace.append(f"Analysis concluded after {round_num} rounds with sufficient confidence")
                    break
            
            final_result = self.phase3_final_integration()
            
            return final_result
            
        except Exception as e:
            return {
                "success": False, 
                "error": str(e),
                "reasoning_trace": self.reasoning_trace
            }
    
    def phase1_data_collection(self):
        self.reasoning_trace.append("Phase 1: Data Collection")
        
        try:
            if self.pre_computed_traffic is not None:
                self.reasoning_trace.append("- Using pre-computed traffic result from chief_agent (avoiding duplicate traffic analysis)")
                traffic_result = self.pre_computed_traffic
            else:
                self.reasoning_trace.append("- Activating TrafficAgent with LLM enhancement...")
                traffic_result = run_traffic_agent(
                    asn=self.asn,
                    start_time=self.start_time.strftime('%Y-%m-%d %H:%M'),
                    end_time=self.end_time.strftime('%Y-%m-%d %H:%M')
                )
            
            traffic_anomaly_detected = traffic_result.get("success") and traffic_result.get("anomalies_detected", False)
            
            extended_analysis_start = self.start_time
            extended_analysis_end = self.end_time
            
            if traffic_anomaly_detected:
                self.reasoning_trace.append("- Traffic anomalies confirmed. Identifying consecutive anomaly periods for routing analysis...")
                
                anomalies = traffic_result.get("anomalies", [])
                anomaly_start, anomaly_end = extract_anomaly_time_range(
                    anomalies,
                    use_consecutive_periods=True,
                    min_consecutive_count=3,
                    max_gap_minutes=60,
                    buffer_hours=self.buffer_hours,
                )
                
                if anomaly_start and anomaly_end:
                    consecutive_periods = identify_consecutive_anomaly_periods(
                        anomalies, min_consecutive_count=3, max_gap_minutes=60
                    )
                    total_consecutive_anomalies = count_consecutive_anomalies_in_longest_period(
                        anomalies,
                        min_consecutive_count=3,
                        max_gap_minutes=60,
                    )
                    
                    self.reasoning_trace.append(
                        f"- Identified consecutive anomaly period: {anomaly_start.strftime('%Y-%m-%d %H:%M')} to {anomaly_end.strftime('%Y-%m-%d %H:%M')} "
                        f"(total anomalies: {len(anomalies)}, consecutive anomalies: {total_consecutive_anomalies})"
                    )
                    routing_start = anomaly_start.strftime('%Y-%m-%d %H:%M')
                    routing_end = anomaly_end.strftime('%Y-%m-%d %H:%M')
                    extended_analysis_start = anomaly_start
                    extended_analysis_end = anomaly_end
                else:
                    self.reasoning_trace.append(
                        f"- No sufficient consecutive anomaly period found (requires at least 3 consecutive anomalies, max gap 60 minutes)."
                        f" Total anomalies: {len(anomalies)}. Skipping routing analysis."
                    )
                    routing_result = {
                        "success": False,
                        "asn": self.asn,
                        "analysis_period": f"{self.start_time} to {self.end_time}",
                        "skipped": True,
                        "skip_reason": f"No sufficient consecutive anomaly period found. Total anomalies: {len(anomalies)}; did not meet consecutive anomaly conditions (>=3 anomalies, max gap 60 minutes)."
                    }
                    data_quality = self.assess_data_quality(routing_result, traffic_result)
                    self.evidence_pool = {
                        "routing_data": routing_result,
                        "traffic_data": traffic_result,
                        "data_quality": data_quality,
                        "extended_analysis_start": extended_analysis_start,
                        "extended_analysis_end": extended_analysis_end
                    }
                    self.reasoning_trace.append(f"- Data quality assessment: {data_quality}")
                    return {
                        "success": True,
                        "routing_success": False,
                        "traffic_success": traffic_result.get("success", False),
                        "data_quality": data_quality,
                        "extended_analysis_start": extended_analysis_start.strftime('%Y-%m-%d %H:%M'),
                        "extended_analysis_end": extended_analysis_end.strftime('%Y-%m-%d %H:%M')
                    }
                
                self.reasoning_trace.append(f"- Using consecutive anomaly period for routing analysis: {routing_start} to {routing_end}")
                
                periodicity = None
                periodicity_confidence = 0.0
                if self.pre_computed_traffic and isinstance(self.pre_computed_traffic, dict):
                    periodicity_info = self.pre_computed_traffic.get("periodicity_analysis", {})
                    periodicity = periodicity_info.get("detected_periodicity")
                    periodicity_confidence = periodicity_info.get("periodicity_confidence", 0.0)
                    if periodicity:
                        self.reasoning_trace.append(f"- Using periodicity from traffic analysis: {periodicity} (confidence: {periodicity_confidence:.2f})")

                if self.pre_computed_routing is not None:
                    self.reasoning_trace.append("- Using pre-computed routing result from chief_agent (avoiding duplicate routing analysis)")
                    routing_result = self.pre_computed_routing
                    self.reasoning_trace.append(f"- pre_computed_routing has {len(routing_result.get('forge_hijacked', []))} forge hijacks")
                else:
                    self.reasoning_trace.append("- WARNING: pre_computed_routing is None, will run new routing analysis")
                    target_asns = [self.asn]
                    routing_result = run_routing_agent(
                        asn=self.asn,
                        start_time=routing_start,
                        end_time=routing_end,
                        target_asns=target_asns,
                        periodicity=periodicity,
                        periodicity_confidence=periodicity_confidence
                    )
            else:
                self.reasoning_trace.append("- Traffic anomalies were not confirmed. Skipping routing analysis by design.")
                routing_result = {
                    "success": False,
                    "asn": self.asn,
                    "analysis_period": f"{self.start_time} to {self.end_time}",
                    "skipped": True,
                    "skip_reason": "Traffic API did not confirm anomalies, routing analysis skipped per workflow."
                }
            
            data_quality = self.assess_data_quality(routing_result, traffic_result)

            # If workflow_engine already generated hypotheses via HypothesisAgent,
            # skip local hypothesis generation to avoid duplicate work.
            if workflow_claims:
                self.reasoning_trace.append(
                    f"- Using {len(workflow_claims)} claims from workflow HypothesisAgent"
                )
                self.evidence_pool["workflow_claims"] = workflow_claims

            self.evidence_pool = {
                "routing_data": routing_result,
                "traffic_data": traffic_result,
                "data_quality": data_quality,
                "extended_analysis_start": extended_analysis_start,
                "extended_analysis_end": extended_analysis_end
            }
            
            self.reasoning_trace.append(f"- Data quality assessment: {data_quality}")
            self.reasoning_trace.append(f"- Extended analysis time range for report: {extended_analysis_start.strftime('%Y-%m-%d %H:%M')} to {extended_analysis_end.strftime('%Y-%m-%d %H:%M')}")
            
            return {
                "success": True,
                "routing_success": routing_result.get("success", False),
                "traffic_success": traffic_result.get("success", False),
                "data_quality": data_quality,
                "extended_analysis_start": extended_analysis_start.strftime('%Y-%m-%d %H:%M'),
                "extended_analysis_end": extended_analysis_end.strftime('%Y-%m-%d %H:%M')
            }
            
        except Exception as e:
            self.reasoning_trace.append(f"- Data collection failed: {str(e)}")
            return {"success": False, "error": str(e)}

    def classify_multi_role(self, initial_data: dict) -> dict | None:
        """
        Run the MultiRoleClassifier to understand the AS's full role picture
        BEFORE the LLM reasons about it.

        This resolves the core classification challenge: AS9121 (Turk Telekom) was
        annotated as 'leaker' but also shows origin_hijacking + origin_hijacked events.
        The classifier identifies ALL applicable roles and detects cross-reference
        patterns (self-hijack, victim→attacker temporal sequence, etc.).

        Results are injected into the reasoning context so the LLM has a complete
        picture of the AS's role before making decisions.
        """
        from agents.multi_role_classifier import MultiRoleClassifier

        routing_data = initial_data.get("routing_data", {})
        traffic_data = initial_data.get("traffic_data", {})

        # Skip if no routing data
        if not routing_data or not routing_data.get("success"):
            return None

        self.reasoning_trace.append("- Running Multi-Role Classification...")

        try:
            classifier = MultiRoleClassifier()
            result = classifier.classify(
                routing_data=routing_data,
                traffic_data=traffic_data,
                asn_info=None,
            )

            # Log key findings
            active_roles = result.get_active_roles()
            self.reasoning_trace.append(
                f"  Multi-role result: primary={result.primary_role} "
                f"(score={result.primary_score}), "
                f"active_roles={active_roles}, "
                f"complexity={result.complexity_level}"
            )

            # Log cross-reference patterns
            if result.self_hijack:
                self.reasoning_trace.append(
                    f"  ⚠️ Self-hijack pattern detected: "
                    f"{result.self_hijack.get('overlap_count', 0)} overlapping prefixes"
                )
            if result.victim_becomes_attacker:
                self.reasoning_trace.append(
                    f"  ⚠️ Victim→Attacker pattern: "
                    f"gap={result.victim_becomes_attacker.get('gap_hours', '?')}h — "
                    f"compromised account likely"
                )
            if result.attacker_becomes_victim:
                self.reasoning_trace.append(
                    f"  ⚠️ Attacker→Victim pattern: "
                    f"gap={result.attacker_becomes_victim.get('gap_hours', '?')}h — "
                    f"collateral damage"
                )

            # Store in evidence pool
            self.evidence_pool["multi_role"] = result.to_dict()

            # Build summary for LLM context
            summary = {
                "asn": result.asn,
                "primary_role": result.primary_role,
                "primary_score": result.primary_score,
                "active_roles": active_roles,
                "complexity_level": result.complexity_level,
                "recommended_depth": result.recommended_analysis_depth,
                "summary_line": result.get_summary(),
                "composite_narrative": result.composite_narrative,
                "detection_gap": result.detection_gap,
                "cross_references": {
                    "self_hijack": result.self_hijack,
                    "victim_becomes_attacker": result.victim_becomes_attacker,
                    "attacker_becomes_victim": result.attacker_becomes_victim,
                },
                # Per-role details (simplified for context)
                "role_details": {
                    r: {
                        "is_active": c.is_active,
                        "score": round(c.score, 3),
                        "sub_types": c.sub_types,
                        "narrative": c.narrative[:300] if c.narrative else "",
                    }
                    for r, c in result.roles.items()
                    if c.is_active
                },
            }

            return summary

        except Exception as e:
            self.reasoning_trace.append(f"- Multi-role classification failed: {e}")
            return None

    def run_auxiliary_enrichment(self, initial_data: dict) -> dict | None:
        """
        Run the InvestigationSupervisor to enrich routing + traffic evidence
        with auxiliary tools (threat intel, news, IRR, history, etc.).

        This is the key "human-like" enhancement: after collecting routing
        and traffic data, we automatically enrich it with external context
        BEFORE the LLM reasons about it.
        """
        routing_data = initial_data.get("routing_data", {})
        traffic_data = initial_data.get("traffic_data", {})

        # Infer suspected type from routing data
        suspected_type = "unknown"
        if routing_data.get("origin_hijacked") or routing_data.get("origin_hijacking"):
            suspected_type = "origin_hijack"
        elif routing_data.get("forge_hijacked") or routing_data.get("forge_hijacking"):
            suspected_type = "forge_hijack"
        elif routing_data.get("route_leaks"):
            suspected_type = "route_leak"
        elif routing_data.get("outage_suspected"):
            suspected_type = "outage"
        elif not routing_data.get("success") and not traffic_data.get("anomalies_detected"):
            suspected_type = "no_anomaly"

        # Check if we have any routing data to work with
        has_events = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked"),
            routing_data.get("route_leaks"),
        ])

        if not routing_data.get("success") and not traffic_data.get("success"):
            self.reasoning_trace.append("- No routing or traffic data available — skipping auxiliary enrichment")
            return None

        # Skip enrichment if no meaningful anomaly detected
        if not has_events and not traffic_data.get("anomalies_detected"):
            self.reasoning_trace.append("- No anomalies detected — skipping auxiliary enrichment")
            return None

        self.reasoning_trace.append(
            f"- Running InvestigationSupervisor (auxiliary enrichment) for suspected_type={suspected_type}..."
        )

        try:
            # Lazy import to avoid circular dependency
            from agents.investigation_supervisor import InvestigationSupervisor
            import asyncio
            supervisor = InvestigationSupervisor()
            result = asyncio.run(supervisor.enrich(
                routing_data=routing_data,
                traffic_data=traffic_data,
                asn=str(self.asn),
                context={"suspected_type": suspected_type},
                skip_pattern="no_anomaly",
            ))

            # Log what was triggered
            tool_count = result.get("tool_count", 0)
            narrative_preview = result.get("auxiliary_narrative", "")[:300]
            confidence_boost = result.get("total_confidence_boost", 0.0)

            self.reasoning_trace.append(
                f"- Auxiliary enrichment complete: {tool_count} tools executed, "
                f"confidence_boost=+{confidence_boost:.2f}"
            )
            self.reasoning_trace.append(f"  Narrative preview: {narrative_preview}...")

            # Store enrichment in evidence pool
            self.evidence_pool["auxiliary_enrichment"] = result

            return result

        except Exception as e:
            self.reasoning_trace.append(f"- Auxiliary enrichment failed: {e}")
            return None

    def identify_evidence_gaps(
        self,
        routing_data: dict,
        traffic_data: dict,
        enrichment_result: dict = None,
    ) -> list[dict]:
        """
        Bug Fix 3.1: 主动识别证据缺口（来自 enhanced_reasoning_agent.py）。

        与 EnhancedReasoningAgent.identify_evidence_gaps 等价，但集成到 ReasoningAgent。
        在进入多轮推理之前，主动识别缺失的证据类型，帮助指导后续推理方向。
        """
        gaps = []
        gap_counter = 0

        # 缺口1：流量异常检测缺失
        if not traffic_data.get("anomalies_detected") and traffic_data.get("success"):
            gap_counter += 1
            gaps.append({
                "gap_id": f"gap_{gap_counter}",
                "gap_type": "missing_traffic_anomaly",
                "question": "Traffic analysis succeeded but found no anomalies. Is the data insufficient or is there truly no traffic impact?",
                "priority": "medium",
                "resolved": False,
                "resolution": None,
            })

        # 缺口2：路由异常检测缺失
        total_hijacks = (
            len(routing_data.get("origin_hijacked", []) or []) +
            len(routing_data.get("forge_hijacked", []) or []) +
            len(routing_data.get("origin_hijacking", []) or []) +
            len(routing_data.get("forge_hijacking", []) or [])
        )
        if total_hijacks == 0 and routing_data.get("success"):
            gap_counter += 1
            gaps.append({
                "gap_id": f"gap_{gap_counter}",
                "gap_type": "missing_bgp_anomaly",
                "question": "Routing analysis succeeded but found no BGP anomalies. Is detection coverage limited or is routing truly normal?",
                "priority": "medium",
                "resolved": False,
                "resolution": None,
            })

        # 缺口3：路由与流量不一致
        routing_has_anomaly = total_hijacks > 0 or len(routing_data.get("route_leaks", []) or []) > 0
        traffic_has_anomaly = traffic_data.get("anomalies_detected", False)
        if routing_has_anomaly and not traffic_has_anomaly:
            gap_counter += 1
            gaps.append({
                "gap_id": f"gap_{gap_counter}",
                "gap_type": "cross_layer_mismatch",
                "question": "Routing anomalies detected but no traffic impact. Is this a failed attack, or is traffic data not sensitive enough?",
                "priority": "high",
                "resolved": False,
                "resolution": None,
            })
        elif traffic_has_anomaly and not routing_has_anomaly:
            gap_counter += 1
            gaps.append({
                "gap_id": f"gap_{gap_counter}",
                "gap_type": "cross_layer_mismatch",
                "question": "Traffic anomalies detected but no routing anomalies found. Is this a non-BGP issue (DDoS, app-layer)?",
                "priority": "high",
                "resolved": False,
                "resolution": None,
            })

        # 缺口4：AS 组织信息缺失
        has_as_info = (
            traffic_data.get("as_info") or
            routing_data.get("as_info") or
            (enrichment_result and enrichment_result.get("as_info"))
        )
        if not has_as_info:
            gap_counter += 1
            gaps.append({
                "gap_id": f"gap_{gap_counter}",
                "gap_type": "missing_as_info",
                "question": "AS organization information missing. Cannot assess organizational context.",
                "priority": "low",
                "resolved": False,
                "resolution": None,
            })

        # 缺口5：辅助信息缺失（threat intel, news context 等）
        if enrichment_result is None:
            gap_counter += 1
            gaps.append({
                "gap_id": f"gap_{gap_counter}",
                "gap_type": "missing_auxiliary_context",
                "question": "No auxiliary enrichment (threat intel, news, IRR, history) was triggered. Does this AS have a known incident record?",
                "priority": "low",
                "resolved": False,
                "resolution": None,
            })

        self._evidence_gaps = gaps

        # Log to reasoning trace
        high_priority = [g for g in gaps if g["priority"] == "high"]
        if gaps:
            self.reasoning_trace.append(
                f"- Evidence gap analysis: {len(gaps)} gap(s) identified "
                f"({len(high_priority)} high priority)"
            )
            for g in high_priority:
                self.reasoning_trace.append(f"  ⚠ {g['gap_id']}: {g['question']}")

    def perform_reasoning_round(self, initial_data, round_num):
        
        try:
            evidence_analysis = self.analyze_evidence_state()
            self.reasoning_trace.append(f"Evidence state: {evidence_analysis['summary']}")
            
            # Identify knowledge gaps
            knowledge_gaps = self.identify_knowledge_gaps()
            if knowledge_gaps:
                self.reasoning_trace.append(f"Knowledge gaps identified: {knowledge_gaps}")

            # Tool-first enrichment for structured factual gaps
            structured_fact_results = self.resolve_structured_fact_gaps(knowledge_gaps)
            if structured_fact_results:
                self.reasoning_trace.append(
                    f"Structured fact enrichment completed: {len(structured_fact_results)} result(s)"
                )

            # Retrieval is reserved for contextual/precedent gaps, not direct facts
            retrieval_candidates = self.identify_retrieval_needs(knowledge_gaps, evidence_analysis)
            if retrieval_candidates:
                retrieval_results = self.resolve_retrieval_needs(retrieval_candidates)
                if retrieval_results:
                    self.reasoning_trace.append(
                        f"Retrieved contextual evidence: {len(retrieval_results)} result(s)"
                    )
            
            # In later rounds, perform deeper analysis using LLM if gaps exist
            if round_num > 1 and knowledge_gaps:
                self.perform_deeper_analysis(round_num, knowledge_gaps)
            
            # Apply reasoning laws to current evidence
            law_application = self.apply_reasoning_laws()
            self.reasoning_trace.append(f"Reasoning law application: {law_application['classification']}")
            
            # Update confidence scores with round-specific refinement
            self.update_confidence_scores(law_application, round_num)
            
            # Check for conflicts between agent findings
            conflicts = self.detect_agent_conflicts()
            if conflicts:
                self.reasoning_trace.append(f"Agent conflicts detected: {conflicts}")
                resolution = self.resolve_conflicts(conflicts)
                self.reasoning_trace.append(f"Conflict resolution: {resolution}")
            
            # Determine if additional rounds are needed
            need_more_rounds = self.assess_analysis_completeness()

            # Record per-round summary so subsequent rounds can use it
            # of re-sending the full routing/traffic dumps.  This cuts token usage
            # by 40-60% in 3-round runs.
            round_summary = {
                "round_num": round_num,
                "evidence_analysis": evidence_analysis,
                "law_classification": law_application.get("classification", "unknown"),
                "conflicts": [str(c) for c in (conflicts or [])],
                "confidence_scores": self.confidence_scores.copy(),
                "knowledge_gaps": knowledge_gaps,
                "reasoning_trace_tail": self.reasoning_trace[-5:],
            }
            self._round_summaries.append(round_summary)

            return {
                "round_num": round_num,
                "evidence_analysis": evidence_analysis,
                "law_application": law_application,
                "conflicts": conflicts if conflicts else None,
                "need_more_rounds": need_more_rounds,
                "confidence_scores": self.confidence_scores.copy()
            }
            
        except Exception as e:
            self.reasoning_trace.append(f"Round {round_num} failed: {str(e)}")
            return {"round_num": round_num, "error": str(e)}
    
    def phase3_final_integration(self):
        self.reasoning_trace.append("\nPhase 3: Final Integration and Decision")

        try:
            # Generate final coordination prompt (now includes auxiliary enrichment)
            coordination_prompt = self.build_coordination_prompt()

            # Cap the prompt to the reasoning budget before sending
            if estimate_bytes(coordination_prompt) > PayloadBudget.REASONING:
                capped_prompt, cap_meta = cap_payload(
                    coordination_prompt,
                    max_bytes=PayloadBudget.REASONING,
                )
                coordination_prompt = capped_prompt
                self.reasoning_trace.append(
                    f"  Coordination prompt capped: {cap_meta['original_bytes']//1024}KB→"
                    f"{cap_meta['final_bytes']//1024}KB "
                    f"(lists_truncated={cap_meta['lists_truncated']})"
                )

            # Get LLM coordination decision with JSON mode
            from agents.llm_wrapper import llm_complete
            response = llm_complete(
                self.llm,
                coordination_prompt,
                run_id=self.run_id,
                agent_name="ReasoningAgent.coordination",
                json_mode=True,
                max_retries=2,
            )
            coordination_result = self.parse_coordination_response(response.text if hasattr(response, "text") else str(response))

            # Generate comprehensive report
            final_report = self.generate_final_report(coordination_result)
            
            self.reasoning_trace.append("Analysis completed successfully")
            
            # Extract file paths from routing analysis for chief_agent
            routing_data = self.evidence_pool.get("routing_data", {})

            return {
                "success": True,
                "analysis_type": "multi-round_reasoning",
                "asn": self.asn,
                "time_range": f"{self.start_time} to {self.end_time}",
                "rounds_performed": self.round_count,
                "final_classification": coordination_result.get("integrated_findings", {}),
                "recommendations": coordination_result.get("recommendations", {}),
                "confidence_assessment": self.build_confidence_assessment(),
                "reasoning_trace": self.reasoning_trace,
                "evidence_summary": self.summarize_evidence(),
                "multi_role": self.evidence_pool.get("multi_role", {}),
                "external_knowledge": self.evidence_pool.get("external_knowledge", []),
                "llm_classification": self.evidence_pool.get("llm_classification", {}),
                "llm_severity": self.evidence_pool.get("llm_severity", {}),
                "token_usage": self.get_total_token_usage(),
                "as_rel_file": routing_data.get("as_rel_file"),
                "prefix2as_file": routing_data.get("prefix2as_file"),
                "asorg_file": routing_data.get("asorg_file")
            }
            
        except Exception as e:
            self.reasoning_trace.append(f"Final integration failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "reasoning_trace": self.reasoning_trace
            }
    
    def assess_data_quality(self, routing_result, traffic_result):
        quality_factors = []

        if routing_result.get("success", False):
            has_anomalies = any([
                routing_result.get("origin_hijacked"),
                routing_result.get("forge_hijacked"),
                routing_result.get("origin_hijacking"),
                routing_result.get("forge_hijacking")
            ])
            # data_available=False ⇒ RIPE RIS had no updates for this AS/time
            # window. Treat as missing data so it doesn't count toward
            # "routing_available" (the evaluator follows the same convention).
            routing_data_available = routing_result.get("data_available", True)
            if routing_data_available:
                quality_factors.append("routing_available")
                if has_anomalies:
                    quality_factors.append("routing_anomalies_detected")
            else:
                quality_factors.append("routing_no_data")

        if traffic_result.get("success", False):
            # Same rule as above for the traffic layer. Without this gate,
            # an AS not sampled by Cloudflare Radar would get "traffic_available"
            # and the reasoning would treat absence of anomalies as a true
            # negative — same root cause as the F1=0 issue.
            traffic_data_available = traffic_result.get("data_available", True)
            if traffic_data_available:
                quality_factors.append("traffic_available")
                if traffic_result.get("anomalies_detected", False):
                    quality_factors.append("traffic_anomalies_detected")
            else:
                quality_factors.append("traffic_no_data")

        if len(quality_factors) >= 3:
            return "High"
        elif len(quality_factors) >= 2:
            return "Medium"
        else:
            return "Low"
    
    def analyze_evidence_state(self):
        """Analyze current state of evidence"""
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        evidence_types = []
        
        if routing_data.get("origin_hijacked") or routing_data.get("origin_hijacking"):
            evidence_types.append("origin_hijack")
        
        if routing_data.get("forge_hijacked") or routing_data.get("forge_hijacking"):
            evidence_types.append("path_forgery")
        
        if traffic_data.get("anomalies_detected", False):
            evidence_types.append("traffic_anomalies")
        
        return {
            "evidence_types": evidence_types,
            "evidence_count": len(evidence_types),
            "summary": f"Found {len(evidence_types)} types of evidence: {', '.join(evidence_types) if evidence_types else 'None'}"
        }
    
    def identify_knowledge_gaps(self):
        """Identify gaps in current knowledge"""
        gaps = []
        
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Check if routing data is missing or failed
        if not routing_data or not routing_data.get("success"):
            gaps.append("missing_routing_analysis")
        
        # Check if AS relationships data is available
        if not routing_data.get("as_rel_file") and not routing_data.get("relationships"):
            gaps.append("missing_as_relationships")
        
        # Check if prefix mappings data is available
        if not routing_data.get("prefix2as_file") and not routing_data.get("prefixes"):
            gaps.append("missing_prefix_mappings")
        
        # Check if traffic data is available
        if not traffic_data or not traffic_data.get("success"):
            gaps.append("missing_traffic_analysis")
        
        return gaps
    
    def resolve_structured_fact_gaps(self, knowledge_gaps):
        """Resolve factual gaps with deterministic tools before any retrieval."""
        routing_data = self.evidence_pool.get("routing_data", {})
        results = []

        asorg_file = routing_data.get("asorg_file")
        asrel_file = routing_data.get("as_rel_file")
        prefix2as_file = routing_data.get("prefix2as_file")

        if "missing_as_relationships" in knowledge_gaps and asrel_file:
            rel_result = query_as_relationships(self.asn, asrel_file)
            record = self.build_structured_fact_record(
                source="as_relationship_tool",
                topic="as_relationships",
                query={"asn": self.asn},
                result=rel_result,
                used_for="validate_routing_interpretation",
            )
            self.structured_facts.append(record)
            self.evidence_pool["as_relationships"] = rel_result
            results.append(record)

        if "missing_prefix_mappings" in knowledge_gaps and prefix2as_file:
            prefix_result = query_as_prefixes(self.asn, prefix2as_file)
            record = self.build_structured_fact_record(
                source="prefix_ownership_tool",
                topic="prefix_ownership",
                query={"asn": self.asn},
                result=prefix_result,
                used_for="validate_prefix_ownership",
            )
            self.structured_facts.append(record)
            self.evidence_pool["as_prefixes"] = prefix_result
            results.append(record)

        if asorg_file:
            org_result = lookup_org_info(self.asn, asorg_file)
            record = self.build_structured_fact_record(
                source="as_org_tool",
                topic="as_organization",
                query={"asn": self.asn},
                result=org_result,
                used_for="establish_as_background",
            )
            self.structured_facts.append(record)
            self.evidence_pool["org_info"] = org_result
            results.append(record)

        return results

    def identify_retrieval_needs(self, knowledge_gaps, evidence_analysis):
        """Identify context gaps that should be filled by retrieval, not fact tools."""
        retrieval_needs = []
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})

        has_routing = bool(routing_data.get("success"))
        has_traffic = bool(traffic_data.get("success"))
        has_routing_events = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked"),
            routing_data.get("origin_hijacking"),
            routing_data.get("forge_hijacking"),
        ])
        has_traffic_anomalies = bool(traffic_data.get("anomalies_detected"))

        suspected_type = self.infer_suspected_incident_type(routing_data)
        if suspected_type:
            retrieval_needs.append({"need": "similar_historical_cases", "suspected_type": suspected_type})

        if has_routing and has_traffic and has_routing_events != has_traffic_anomalies:
            retrieval_needs.append({"need": "contextualize_signal_mismatch", "suspected_type": suspected_type})

        if evidence_analysis.get("evidence_count", 0) == 0 and "missing_traffic_analysis" not in knowledge_gaps:
            retrieval_needs.append({"need": "look_for_similar_low_signal_cases", "suspected_type": suspected_type})

        return retrieval_needs

    def resolve_retrieval_needs(self, retrieval_needs):
        """Resolve retrieval needs using historical routing-grounded cases."""
        results = []
        seen_queries = set()

        for item in retrieval_needs:
            need = item.get("need") if isinstance(item, dict) else str(item)
            suspected_type = item.get("suspected_type") if isinstance(item, dict) else None
            dedupe_key = (need, suspected_type, str(self.asn))
            if dedupe_key in seen_queries:
                continue
            seen_queries.add(dedupe_key)

            retrieval_result = self.case_retriever.retrieve(
                asn=self.asn,
                suspected_type=suspected_type,
                top_k=3,
            )
            match_count = retrieval_result.get("match_count", 0)
            record = {
                "type": "retrieved_context",
                "source": "historical_case_retriever",
                "query": {
                    "asn": self.asn,
                    "time_range": f"{self.start_time} to {self.end_time}",
                    "need": need,
                    "suspected_type": suspected_type,
                },
                "result": retrieval_result,
                "confidence": min(0.85, 0.25 + 0.15 * match_count) if retrieval_result.get("success") else 0.0,
                "used_for": "contextualize_current_incident",
            }
            self.retrieved_context.append(record)
            results.append(record)

        return results

    # ── P5 helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def estimate_bytes_safe(obj) -> int:
        """Safe byte estimate for any object (used in P5 summary-only prompts)."""
        try:
            return len(json.dumps(obj, ensure_ascii=False, default=str))
        except Exception:
            return len(str(obj))

    @staticmethod
    def r_meta_estimate_bytes() -> int:
        """Rough estimate of routing slim size in bytes for P5 log."""
        return 15 * 1024

    def perform_deeper_analysis(self, round_num, knowledge_gaps):
        """
        P5: In round > 1, use accumulated per-round summaries instead of
        re-sending full routing/traffic dumps.  This reduces token consumption
        by 40-60% in typical 3-round runs.

        Round 1  → sends full routing + traffic (cold start; LLM needs all data)
        Round 2  → sends full routing + traffic + previous round 1 summary
        Round 3+ → sends ONLY previous round summaries + new knowledge gaps
                   (full data already available to the LLM from rounds 1-2)
        """
        self.reasoning_trace.append(
            f"[Round {round_num}] Performing LLM deeper analysis for {len(knowledge_gaps)} gap(s)"
        )

        calibration = self.evidence_pool.get("calibration", {})
        gaps_str = ", ".join(str(g) for g in knowledge_gaps)

        # Select data strategy based on round number
        if round_num <= 2:
            # Cold start: still need full routing + traffic data
            routing_raw = self.evidence_pool.get("routing_data", {})
            traffic_raw = self.evidence_pool.get("traffic_data", {})
            routing_slim, r_meta = build_payload(
                "routing", routing_raw, max_bytes=PayloadBudget.REASONING,
            )
            traffic_slim, t_meta = build_payload(
                "traffic", traffic_raw, max_bytes=PayloadBudget.REASONING,
            )
            prev_rounds_summary = (
                "\n\nPrevious rounds summary:\n" +
                "\n".join(
                    f"Round {s['round_num']}: evidence={s['evidence_analysis'].get('summary','')[:200]}, "
                    f"confidence={s.get('confidence_scores',{})}"
                    for s in self._round_summaries
                )
            ) if self._round_summaries else ""
            self.reasoning_trace.append(
                f"  Routing slim: {r_meta['final_bytes']//1024}KB | "
                f"Traffic slim: {t_meta['final_bytes']//1024}KB"
            )
            routing_block = f"Routing data summary:\n{to_json_for_prompt(routing_slim)}"
            traffic_block = f"Traffic data summary:\n{to_json_for_prompt(traffic_slim)}"
        else:
            # summary-only mode: previous rounds already established the facts
            prev_rounds_summary = (
                "\n\nPrevious rounds summary:\n" +
                "\n".join(
                    f"Round {s['round_num']}: "
                    f"law={s.get('law_classification','?')}, "
                    f"evidence={str(s.get('evidence_analysis',{}).get('summary',''))[:150]}, "
                    f"confidence={s.get('confidence_scores',{})}, "
                    f"gaps={s.get('knowledge_gaps',[])}"
                    for s in self._round_summaries
                )
            )
            self.reasoning_trace.append(
                f"  P5 summary-only mode: {self.estimate_bytes_safe(prev_rounds_summary)} chars "
                f"from {len(self._round_summaries)} previous round(s) "
                f"(vs ~{self.r_meta_estimate_bytes()} chars for full data)"
            )
            routing_block = "Routing data: (see previous rounds summary above)"
            traffic_block = "Traffic data: (see previous rounds summary above)"

        prompt = f"""You are a BGP security analyst performing deep reasoning on an ongoing incident.

Round: {round_num}
Target AS: {self.asn}
Time range: {self.start_time} to {self.end_time}

Knowledge gaps to resolve: {gaps_str}

{prev_rounds_summary}

{routing_block}

{traffic_block}

Confidence calibration: {calibration}

Remaining gaps: {gaps_str}

For each gap, provide:
1. A hypothesis about what the missing information likely is
2. What additional data source or query could resolve it
3. A confidence estimate (0-1) that the gap is resolvable with available tools

Respond concisely in JSON:
{{"gap_analysis": [{{"gap": "...", "hypothesis": "...", "resolution_approach": "...", "resolvability": 0.0-1.0}}]}}
"""

        # Log estimated prompt size
        prompt_size = self.estimate_bytes_safe(prompt)
        self.reasoning_trace.append(
            f"  Deeper analysis prompt: {prompt_size//1024}KB "
            f"(est_tokens≈{int(prompt_size * 0.35)})"
        )

        try:
            from agents.llm_wrapper import llm_complete
            response = llm_complete(
                self.llm,
                prompt,
                run_id=self.run_id,
                agent_name="ReasoningAgent.deeper_analysis",
                json_mode=True,
                max_retries=2,
            )
            text = response.text if hasattr(response, "text") else str(response)
            try:
                analysis_result = json.loads(text) if text.strip().startswith("{") else {}
            except json.JSONDecodeError:
                from agents.payload_builder import _extract_json_robust
                parsed, ok, err = _extract_json_robust(text)
                analysis_result = parsed if ok else {}
                if not ok:
                    self.reasoning_trace.append(f"  LLM deeper analysis JSON parse failed: {err}")
            gap_results = analysis_result.get("gap_analysis", [])
            for item in gap_results:
                self.reasoning_trace.append(
                    f"  Gap '{item.get('gap')}': hypothesis={item.get('hypothesis')}, "
                    f"resolvability={item.get('resolvability', 'N/A')}"
                )
            return analysis_result
        except Exception as e:
            self.reasoning_trace.append(f"  LLM deeper analysis failed: {e}")
            return {}

    def infer_suspected_incident_type(self, routing_data):
        if routing_data.get("origin_hijacked") or routing_data.get("origin_hijacking"):
            return "hijack"
        if routing_data.get("forge_hijacked") or routing_data.get("forge_hijacking"):
            return "hijack"
        if routing_data.get("route_leaks"):
            return "leak"
        return None

    def build_structured_fact_record(self, source, topic, query, result, used_for):
        confidence = 0.95 if isinstance(result, dict) and result.get("success") else 0.3
        return {
            "type": "structured_fact",
            "source": source,
            "topic": topic,
            "query": query,
            "result": clean_timestamps(result),
            "confidence": confidence,
            "used_for": used_for,
        }

    def cross_validate_temporal_overlap(self, overlap_window_seconds: int = 3600):
        """Compute routing↔traffic temporal overlap and stash it in
        ``evidence_pool["temporal_correlation"]``.

        This is a lightweight, deterministic backstop used by callers that
        want quick overlap stats without spinning up the LLM deeper-analysis
        pipeline.  Returns the overlap dict (or ``None`` when there isn't
        enough data on either side).
        """
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})

        routing_events: list = []
        for key in ("origin_hijacked", "forge_hijacked",
                    "origin_hijacking", "forge_hijacking"):
            routing_events.extend(routing_data.get(key, []) or [])

        traffic_anomalies = traffic_data.get("anomalies", []) or []
        if not routing_events or not traffic_anomalies:
            return None

        # Accept both with-Z and without-Z ISO formats.  We don't import
        # parse_timestamp here to keep this helper independent of the
        # correlation_analyzer module.
        routing_times: set = set()
        for ev in routing_events:
            ts = ev.get("timestamp") or ev.get("first_seen")
            if not ts:
                continue
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    routing_times.add(datetime.strptime(str(ts), fmt))
                    break
                except ValueError:
                    continue

        anomaly_times: set = set()
        for a in traffic_anomalies:
            ts = a.get("timestamp")
            if not ts:
                continue
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S"):
                try:
                    anomaly_times.add(datetime.strptime(str(ts), fmt))
                    break
                except ValueError:
                    continue

        overlap_count = 0
        for rt in routing_times:
            for at in anomaly_times:
                if abs((rt - at).total_seconds()) < overlap_window_seconds:
                    overlap_count += 1
                    break

        result = {
            "overlap_count": overlap_count,
            "routing_events": len(routing_times),
            "traffic_anomalies": len(anomaly_times),
            "window_seconds": overlap_window_seconds,
        }
        self.evidence_pool["temporal_correlation"] = result
        self.reasoning_trace.append(
            f"Temporal correlation: {overlap_count} routing events align "
            f"with traffic anomalies (window={overlap_window_seconds}s)"
        )
        return result

    def apply_reasoning_laws(self):
        """Apply BGP reasoning laws to current evidence - with LLM enhancement"""
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # 计算持续时间
        duration_minutes = (self.end_time - self.start_time).total_seconds() / 60
        time_range = f"{self.start_time} to {self.end_time}"
        
        # LLM 增强的事件分类
        if self.use_llm_reasoning and self.incident_classifier:
            classification_result = self.incident_classifier.classify(
                routing_data=routing_data,
                traffic_data=traffic_data,
                asn=str(self.asn),
                time_range=time_range,
                duration_minutes=duration_minutes,
                run_id=self.run_id,
            )
            classification = classification_result.get("incident_type", "Unknown")
            classification_confidence = classification_result.get("confidence", 0.5)
            self.evidence_pool["llm_classification"] = classification_result
            self.reasoning_trace.append(f"LLM Incident Classification: {classification} (confidence: {classification_confidence:.2f})")
        else:
            classification = self.classify_incident_type(routing_data)
            classification_confidence = 0.7
        
        # LLM 增强的流量关联评估
        if self.use_llm_reasoning and self.traffic_correlator:
            correlation_result = self.traffic_correlator.assess_correlation(
                routing_data=routing_data,
                traffic_data=traffic_data,
                run_id=self.run_id,
            )
            has_correlation = correlation_result.get("has_correlation", False)
            temporal_alignment = correlation_result.get("temporal_alignment", 0.5)
            self.evidence_pool["llm_correlation"] = correlation_result
            self.reasoning_trace.append(f"LLM Traffic Correlation: has_link={has_correlation}, temporal={temporal_alignment:.2f}")
        else:
            traffic_correlation = self.assess_traffic_correlation(routing_data, traffic_data)
            has_correlation = "Correlated" in traffic_correlation
            temporal_alignment = 0.5
        
        # LLM 增强的严重性评估
        if self.use_llm_reasoning and self.severity_assessor:
            severity_result = self.severity_assessor.assess(
                routing_data=routing_data,
                traffic_data=traffic_data,
                duration_minutes=duration_minutes,
                asn=str(self.asn),
                time_range=time_range,
                run_id=self.run_id,
            )
            severity = severity_result.get("severity", "Medium")
            self.evidence_pool["llm_severity"] = severity_result
            self.reasoning_trace.append(f"LLM Severity Assessment: {severity}")
        else:
            severity = self.assess_incident_severity(routing_data, traffic_data)
        
        return {
            "classification": classification,
            "classification_confidence": classification_confidence,
            "traffic_correlation": traffic_correlation if not self.use_llm_reasoning else ("Correlated" if has_correlation else "Uncorrelated"),
            "has_causal_link": has_correlation,
            "temporal_alignment": temporal_alignment,
            "severity": severity,
            "laws_applied": [
                "1-3: Classification (LLM)" if self.use_llm_reasoning else "1-3: Classification",
                "4: Traffic Correlation (LLM)" if self.use_llm_reasoning else "4: Traffic Correlation",
                "6: Severity Assessment (LLM)" if self.use_llm_reasoning else "6: Severity Assessment"
            ]
        }
    
    def classify_incident_type(self, routing_data):
        """Apply reasoning laws 1-3 for incident classification"""
        if routing_data.get("origin_hijacked") or routing_data.get("origin_hijacking"):
            return "Origin Hijacking"
        elif routing_data.get("forge_hijacked") or routing_data.get("forge_hijacking"):
            return "Path Forgery"
        else:
            return "No BGP Anomaly Detected"
    
    def assess_traffic_correlation(self, routing_data, traffic_data):
        """Apply reasoning law 4 for traffic correlation"""
        has_bgp_anomaly = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked"),
            routing_data.get("origin_hijacking"),
            routing_data.get("forge_hijacking")
        ])
        
        has_traffic_anomaly = traffic_data.get("anomalies_detected", False)
        
        if has_bgp_anomaly and has_traffic_anomaly:
            return "Correlated BGP and Traffic Anomalies"
        elif has_bgp_anomaly and not has_traffic_anomaly:
            return "BGP Anomaly Without Traffic Impact"
        elif not has_bgp_anomaly and has_traffic_anomaly:
            return "Traffic Anomaly Without BGP Events"
        else:
            return "No Anomalies Detected"
    
    def assess_incident_severity(self, routing_data, traffic_data):
        """Apply reasoning law 6 for severity assessment"""
        duration_minutes = (self.end_time - self.start_time).total_seconds() / 60
        
        if duration_minutes > 120:  # > 2 hours
            return "High"
        elif duration_minutes > 10:  # 10 minutes - 2 hours
            return "Medium"
        else:  # < 10 minutes
            return "Low"
    
    def update_confidence_scores(self, law_application, round_num=None):
        """Update confidence scores based on reasoning results with iterative refinement"""
        if round_num is None:
            round_num = self.round_count
        
        # Calculate confidence based on evidence consistency
        evidence_consistency = self.calculate_evidence_consistency()
        
        # Update confidence for current round
        classification_confidence = self.get_classification_confidence(law_application)
        classification_confidence = self.apply_small_bgp_penalty(classification_confidence)
        
        # Apply iterative refinement: confidence should improve with more rounds (up to a point)
        # Round 1: base confidence
        # Round 2: slight improvement if evidence is consistent
        # Round 3: further refinement or stabilization
        refinement_factor = 1.0
        if round_num > 1:
            # If previous rounds had consistent results, increase confidence slightly
            prev_round_key = f"round_{round_num - 1}"
            if prev_round_key in self.confidence_scores:
                prev_confidence = self.confidence_scores[prev_round_key].get("overall_confidence", 0.0)
                # If evidence consistency is high, allow small improvement
                if evidence_consistency >= 0.8:
                    refinement_factor = min(1.15, 1.0 + (round_num - 1) * 0.05)
                # If previous round had low confidence, check if we're converging
                elif prev_confidence < 0.5 and round_num == 3:
                    # Final round: stabilize at current level
                    refinement_factor = 1.0
        
        adjusted_classification_confidence = min(0.95, classification_confidence * refinement_factor)
        
        self.confidence_scores[f"round_{round_num}"] = {
            "evidence_consistency": evidence_consistency,
            "classification_confidence": adjusted_classification_confidence,
            "overall_confidence": min(evidence_consistency, adjusted_classification_confidence)
        }
    
    def calculate_evidence_consistency(self):
        """Calculate how consistent the evidence is across agents with round-specific refinement"""
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Check for consistency between routing and traffic findings
        has_routing_anomalies = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked"),
            routing_data.get("origin_hijacking"),
            routing_data.get("forge_hijacking")
        ])
        
        has_traffic_anomalies = traffic_data.get("anomalies_detected", False)
        
        # Base consistency score
        if has_routing_anomalies == has_traffic_anomalies:
            base_consistency = 0.9
        else:
            base_consistency = 0.6
        
        # Refine based on deeper analysis in later rounds
        if self.round_count > 1:
            # Check temporal correlation if available
            temporal_corr = self.evidence_pool.get("temporal_correlation")
            if temporal_corr:
                overlap_ratio = temporal_corr.get("overlap_count", 0) / max(
                    temporal_corr.get("routing_events", 1),
                    temporal_corr.get("traffic_anomalies", 1)
                )
                # Boost consistency if temporal correlation is strong
                if overlap_ratio > 0.5:
                    base_consistency = min(0.95, base_consistency + 0.1)
                elif overlap_ratio > 0.2:
                    base_consistency = min(0.9, base_consistency + 0.05)
            
            # In round 3, consider confidence stability
            if self.round_count == 3:
                if self.evidence_pool.get("confidence_stability", False):
                    base_consistency = min(0.95, base_consistency + 0.05)
        
        return base_consistency
    
    def get_classification_confidence(self, law_application):
        """Get confidence level for classification - uses LLM assessment if available"""
        # 如果有 LLM 分类结果，使用它
        llm_classification = self.evidence_pool.get("llm_classification")
        if llm_classification and llm_classification.get("source") == "llm":
            return llm_classification.get("confidence", 0.5)
        
        classification = law_application.get("classification", "")
        
        if classification in ["Origin Hijacking", "Path Forgery"]:
            return 0.8
        elif classification == "No BGP Anomaly Detected":
            return 0.7
        else:
            return 0.5
    
    def apply_small_bgp_penalty(self, base_confidence):
        """Reduce confidence when routing impact is small compared to traffic anomaly severity"""
        routing_impact = self.get_routing_impact_score()
        traffic_severity = self.get_traffic_severity_score()
        
        # Only penalize when traffic impact is significant but routing impact is minimal
        if traffic_severity >= 0.6 and routing_impact < 0.3:
            penalty = min(0.4, (traffic_severity - routing_impact))
            adjusted = max(0.1, base_confidence - penalty)
            self.reasoning_trace.append(
                f"Confidence penalty applied: routing impact {routing_impact:.2f} is much smaller than traffic severity {traffic_severity:.2f}"
            )
            return adjusted
        return base_confidence
    
    def get_routing_impact_score(self):
        """Estimate how wide the routing anomaly spreads based on events and affected prefixes"""
        routing_data = self.evidence_pool.get("routing_data", {})
        event_keys = ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]
        event_count = 0
        affected_prefixes = set()
        
        for key in event_keys:
            events = routing_data.get(key, []) or []
            event_count += len(events)
            for event in events:
                prefix = event.get("prefix")
                if prefix:
                    affected_prefixes.add(prefix)
        
        event_factor = min(1.0, event_count / 5.0)  # Full score if >=5 events
        prefix_factor = min(1.0, len(affected_prefixes) / 3.0)  # Full score if >=3 prefixes
        return max(event_factor, prefix_factor)
    
    def get_traffic_severity_score(self):
        """Estimate traffic anomaly severity using percent change and anomaly count"""
        traffic_data = self.evidence_pool.get("traffic_data", {})
        percent_change = abs(traffic_data.get("percent_change", 0.0) or 0.0)
        anomaly_count = traffic_data.get("anomaly_count", 0) or 0
        
        change_factor = min(1.0, percent_change / 40.0)  # 40%+ treated as severe
        anomaly_factor = min(1.0, anomaly_count / 3.0)  # >=3 anomalies considered severe
        return max(change_factor, anomaly_factor)
    
    def detect_agent_conflicts(self):
        """Detect conflicts between agent findings"""
        conflicts = []
        
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Check for conflicting evidence
        has_routing_issues = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked")
        ])
        
        no_traffic_impact = not traffic_data.get("anomalies_detected", False)
        
        if has_routing_issues and no_traffic_impact:
            conflicts.append("BGP anomalies detected but no traffic impact observed")
        
        return conflicts if conflicts else None
    
    def resolve_conflicts(self, conflicts):
        """Resolve conflicts between agent findings"""
        # Simple conflict resolution - in production this would be more sophisticated
        if "BGP anomalies detected but no traffic impact observed" in conflicts:
            return "BGP anomaly may be inactive or traffic data incomplete"
        
        return "Conflicts require manual review"
    
    def should_conclude_analysis(self):
        """Determine if analysis should conclude"""
        if not self.confidence_scores:
            return False
        
        # Get latest round confidence
        latest_round = f"round_{self.round_count}"
        latest_confidence = self.confidence_scores.get(latest_round, {})
        overall_confidence = latest_confidence.get("overall_confidence", 0.0)
        
        # Conclude if confidence is high enough or max rounds reached
        return overall_confidence >= 0.8 or self.round_count >= 3
    
    def assess_analysis_completeness(self):
        """Assess if more analysis rounds are needed"""
        return not self.should_conclude_analysis()
    
    def build_coordination_prompt(self):
        """Build prompt for final coordination.

        Evidence pool sections are slimmed via PayloadBuilder so the final
        coordination LLM call stays within PayloadBudget.REASONING bytes.
        """
        prompt_template = build_multi_agent_coordination_prompt()

        # Slim routing and traffic via PayloadBuilder before embedding in prompt
        routing_raw = self.evidence_pool.get("routing_data", {})
        traffic_raw = self.evidence_pool.get("traffic_data", {})
        routing_slim, r_meta = build_payload(
            "routing", routing_raw, max_bytes=PayloadBudget.REASONING,
        )
        traffic_slim, t_meta = build_payload(
            "traffic", traffic_raw, max_bytes=PayloadBudget.REASONING,
        )
        routing_summary = self._summarize_routing_results_slimmed(routing_slim)
        traffic_summary = self._summarize_traffic_results_slimmed(traffic_slim)
        
        # Include multi-role classification if available
        multi_role_section = ""
        multi_role = self.evidence_pool.get("multi_role")
        if multi_role:
            role_details = multi_role.get("role_details", {})
            lines = [
                "## Multi-Role Classification",
                f"Primary Role: {multi_role.get('primary_role')} (confidence={multi_role.get('primary_score', 0):.2f})",
                f"Complexity: {multi_role.get('complexity_level')} | Recommended Depth: {multi_role.get('recommended_depth')}",
                f"Active Roles: {', '.join(multi_role.get('active_roles', []))}",
            ]
            for role, details in role_details.items():
                lines.append(f"  - {role.upper()}: {details.get('narrative', '')[:200]}")
            # Cross-reference patterns
            xref = multi_role.get("cross_references", {})
            if xref.get("self_hijack"):
                lines.append(f"  ⚠️ SELF-HIJACK: {str(xref['self_hijack'].get('interpretation', ''))[:200]}")
            if xref.get("victim_becomes_attacker"):
                lines.append(f"  ⚠️ VICTIM→ATTACKER (compromised account): {str(xref['victim_becomes_attacker'].get('interpretation', ''))[:200]}")
            if xref.get("attacker_becomes_victim"):
                lines.append(f"  ⚠️ ATTACKER→VICTIM (collateral damage): {str(xref['attacker_becomes_victim'].get('interpretation', ''))[:200]}")
            multi_role_section = "\n" + "\n".join(lines)
        
        # Include auxiliary enrichment narrative if available
        enrichment_narrative = ""
        enrichment = self.evidence_pool.get("auxiliary_enrichment")
        if enrichment:
            enrichment_narrative = enrichment.get("auxiliary_narrative", "")
            if enrichment_narrative:
                enrichment_narrative = f"\n\n## Auxiliary Enrichment Evidence\n{enrichment_narrative}"
        
        return prompt_template.format(
            routing_results=routing_summary,
            traffic_results=traffic_summary,
            reasoning_trace="\n".join(self.reasoning_trace[-10:]),  # Last 10 trace entries
            confidence_scores=json.dumps(self.confidence_scores, indent=2)
        ) + multi_role_section + enrichment_narrative
    
    def summarize_routing_results(self):
        """Summarize routing agent results"""
        routing_data = self.evidence_pool.get("routing_data", {})
        
        if not routing_data.get("success", False):
            return "Routing analysis failed"
        
        summary_parts = [
            f"Origin hijacked: {len(routing_data.get('origin_hijacked', []))} events",
            f"Forge hijacked: {len(routing_data.get('forge_hijacked', []))} events",
            f"LLM analysis: {'Available' if routing_data.get('llm_analysis') else 'Not available'}"
        ]
        
        return "; ".join(summary_parts)
    
    def summarize_traffic_results(self):
        """Summarize traffic agent results"""
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        if not traffic_data.get("success", False):
            return "Traffic analysis failed"
        
        summary_parts = [
            f"Anomalies detected: {traffic_data.get('anomalies_detected', False)}",
            f"Anomaly count: {traffic_data.get('anomaly_count', 0)}",
            f"LLM analysis: {'Available' if traffic_data.get('llm_analysis') else 'Not available'}"
        ]
        
        return "; ".join(summary_parts)
    
    def parse_coordination_response(self, response_text):
        """Parse LLM coordination response"""
        try:
            # Brace-balanced extraction so nested objects (e.g.
            # ``"contextual_insights": ["{something}"]``) don't cause
            # the parser to truncate the JSON early.
            snippet = _extract_json_object(response_text or "")
            if snippet is not None:
                return json.loads(snippet)

            # Fallback to simple parsing
            return {"integrated_findings": {"incident_type": "Unknown", "confidence_level": "Low"}}

        except json.JSONDecodeError:
            return {"integrated_findings": {"incident_type": "Parse Error", "confidence_level": "Low"}}
    
    def generate_final_report(self, coordination_result):
        """Generate comprehensive final report"""
        return {
            "analysis_metadata": {
                "asn": self.asn,
                "time_range": f"{self.start_time} to {self.end_time}",
                "analysis_timestamp": datetime.now().isoformat(),
                "rounds_performed": self.round_count,
                "uuid": self.uuid
            },
            "coordination_result": coordination_result,
            "agent_results": {
                "routing": self.evidence_pool.get("routing_data", {}),
                "traffic": self.evidence_pool.get("traffic_data", {})
            },
            "knowledge_access": {
                "structured_facts": self.structured_facts,
                "retrieved_context": self.retrieved_context,
            },
            "confidence_progression": self.confidence_scores,
            "reasoning_trace": self.reasoning_trace
        }
    
    def get_final_confidence(self):
        """Get final confidence assessment"""
        if not self.confidence_scores:
            return {"overall": "Low", "details": "No confidence data available"}
        
        # Get the latest round confidence
        latest_round = f"round_{self.round_count}"
        latest_confidence = self.confidence_scores.get(latest_round, {})
        
        overall = latest_confidence.get("overall_confidence", 0.0)
        
        if overall >= 0.8:
            level = "High"
        elif overall >= 0.6:
            level = "Medium"
        else:
            level = "Low"
        
        return {
            "overall": level,
            "score": overall,
            "details": f"Based on {self.round_count} rounds of analysis",
            "progression": self.confidence_scores
        }

    def build_confidence_assessment(self) -> dict:
        """构建最终置信度评估（包含校准结果）"""
        base = self.get_final_confidence()

        calibration = self.evidence_pool.get("calibration", {})

        if not calibration:
            return base

        return {
            "overall": base.get("overall", "Low"),
            "score": calibration.get("final_confidence", base.get("score", 0.5)),
            "calibrated": calibration.get("calibrated_confidence"),
            "original": calibration.get("original_confidence"),
            "level": calibration.get("level", "low"),
            "factors": calibration.get("factors", {}),
            "calibration_reason": calibration.get("reason", ""),
            "details": f"Based on {self.round_count} rounds of analysis with calibration",
            "progression": self.confidence_scores,
        }

    def summarize_evidence(self):
        """Summarize all collected evidence"""
        # Convert pandas Timestamps to strings to ensure JSON serialization
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Clean routing data
        cleaned_routing_data = clean_timestamps(routing_data)
        cleaned_traffic_data = clean_timestamps(traffic_data)
        
        # Get extended time range for report generation
        extended_start = self.evidence_pool.get("extended_analysis_start")
        extended_end = self.evidence_pool.get("extended_analysis_end")
        extended_time_range = None
        if extended_start and extended_end:
            extended_time_range = {
                "start": extended_start.strftime('%Y-%m-%d %H:%M') if hasattr(extended_start, 'strftime') else str(extended_start),
                "end": extended_end.strftime('%Y-%m-%d %H:%M') if hasattr(extended_end, 'strftime') else str(extended_end)
            }
        
        return {
            "data_quality": self.evidence_pool.get("data_quality", "Unknown"),
            "routing_data": cleaned_routing_data,  # Return cleaned routing data
            "traffic_data": cleaned_traffic_data,   # Return cleaned traffic data
            "routing_evidence": self.count_routing_evidence(),
            "traffic_evidence": self.count_traffic_evidence(),
            "correlation_assessment": self.assess_final_correlation(),
            "structured_facts": clean_timestamps(self.structured_facts),
            "retrieved_context": clean_timestamps(self.retrieved_context),
            "extended_analysis_time_range": extended_time_range  # Include extended time range for report
        }
    
    def count_routing_evidence(self):
        """Count routing evidence"""
        routing_data = self.evidence_pool.get("routing_data", {})
        
        return {
            "origin_hijacked_count": len(routing_data.get("origin_hijacked", [])),
            "forge_hijacked_count": len(routing_data.get("forge_hijacked", [])),
            "origin_hijacking_count": len(routing_data.get("origin_hijacking", [])),
            "forge_hijacking_count": len(routing_data.get("forge_hijacking", []))
        }
    
    def count_traffic_evidence(self):
        """Count traffic evidence"""
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        return {
            "anomalies_detected": traffic_data.get("anomalies_detected", False),
            "anomaly_count": traffic_data.get("anomaly_count", 0),
            "has_baseline_data": bool(traffic_data.get("baseline_metrics"))
        }
    
    def assess_final_correlation(self):
        """Assess final correlation between routing and traffic"""
        routing_evidence = self.count_routing_evidence()
        traffic_evidence = self.count_traffic_evidence()
        
        has_routing_anomalies = sum(routing_evidence.values()) > 0
        has_traffic_anomalies = traffic_evidence.get("anomalies_detected", False)
        
        if has_routing_anomalies and has_traffic_anomalies:
            return "Strong correlation between BGP and traffic anomalies"
        elif has_routing_anomalies and not has_traffic_anomalies:
            return "BGP anomalies without observable traffic impact"
        elif not has_routing_anomalies and has_traffic_anomalies:
            return "Traffic anomalies without BGP routing issues"
        else:
            return "No significant anomalies detected"
    
    def get_total_token_usage(self):
        total_tokens = self.token_counter.total_llm_token_count
        prompt_tokens = self.token_counter.prompt_llm_token_count
        completion_tokens = self.token_counter.completion_llm_token_count
        
        routing_data = self.evidence_pool.get("routing_data", {})
        routing_tokens = routing_data.get("token_usage", {})
        
        # Add traffic agent tokens
        traffic_data = self.evidence_pool.get("traffic_data", {})
        traffic_tokens = traffic_data.get("token_usage", {})
        
        return {
            "reasoning_agent": {
                "total": total_tokens,
                "prompt": prompt_tokens,
                "completion": completion_tokens
            },
            "routing_agent": routing_tokens,
            "traffic_agent": traffic_tokens,
            "total_across_agents": (
                total_tokens + 
                routing_tokens.get("total_tokens", 0) + 
                traffic_tokens.get("total_tokens", 0)
            )
        }


def run_reasoning_agent(asn = None, start_time = None, end_time = None,
                       user_input = None, max_rounds = 3, pre_computed_routing = None, pre_computed_traffic = None,
                       buffer_hours = 0, workflow_claims = None, run_id = ""):
    try:
        if user_input and not (asn and start_time and end_time):
            from agents.traffic_agent import parse_traffic_outage_input, normalize_time
            parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(user_input)
            
            if not parsed_asn or not parsed_start or not parsed_end:
                return {
                    "success": False,
                    "error": "Could not extract ASN and time period from user input",
                    "user_input": user_input
                }
            
            asn = parsed_asn
            start_time = normalize_time(parsed_start)
            end_time = normalize_time(parsed_end)
        else:
            # Normalize time format for direct parameters
            if start_time:
                try:
                    from agents.traffic_agent import normalize_time
                    start_time = normalize_time(str(start_time))
                except Exception:
                    pass
            if end_time:
                try:
                    from agents.traffic_agent import normalize_time
                    end_time = normalize_time(str(end_time))
                except Exception:
                    pass
        
        # Validate required parameters
        if not all([asn, start_time, end_time]):
            return {
                "success": False,
                "error": "Missing required parameters: asn, start_time, end_time"
            }
        
        # Parse time strings - handle both human-readable AND ISO 8601 formats.
        # Bug fix 2026-09-13 (BUG-R120): the previous implementation only
        # tried ``"%Y-%m-%d %H:%M:%S"`` and ``"%Y-%m-%d %H:%M"``. ISO
        # strings like ``"2024-01-15T00:00:00"`` (very common when the
        # chief_agent passes through ``detected_start`` from
        # ``_extract_anomaly_times``, or when the React agent hands off
        # ISO strings via ``run_context``) raised ``ValueError`` and the
        # outer ``except Exception as e:`` block returned
        # ``{"success": False, "error": "Invalid time: ..."}`` —
        # silently aborting the reasoning stage with a confusing error
        # the LLM caller could not recover from. The fix mirrors the
        # pattern applied in BUG-R110/R111: try multiple formats, then
        # ``fromisoformat``, then a plain-date fallback.
        def _parse_ts(value, label):
            if value is None:
                return None
            if isinstance(value, datetime):
                return value
            if not isinstance(value, str):
                return None
            s = value.strip()
            if not s:
                return None
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S%z",
            ):
                try:
                    return datetime.strptime(
                        s.replace("Z", "+0000") if s.endswith("Z") else s, fmt
                    )
                except ValueError:
                    continue
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is not None:
                    dt = dt.astimezone().replace(tzinfo=None)
                return dt
            except ValueError:
                pass
            try:
                d = datetime.strptime(s, "%Y-%m-%d")
                return datetime.combine(d.date(), datetime.min.time())
            except ValueError:
                logger.warning(
                    f"[reasoning_agent] could not parse {label}={value!r}"
                )
                return None

        start_dt = _parse_ts(start_time, "start_time")
        end_dt = _parse_ts(end_time, "end_time")
        if start_dt is None or end_dt is None:
            return {
                "success": False,
                "error": (
                    f"Invalid time: start_time={start_time!r}, "
                    f"end_time={end_time!r}"
                ),
            }
        
        # Create and run reasoning agent with pre-computed routing if available
        agent = ReasoningAgent(
            asn,
            start_dt,
            end_dt,
            pre_computed_routing=pre_computed_routing,
            pre_computed_traffic=pre_computed_traffic,
            buffer_hours=buffer_hours,
        )
        agent.run_id = run_id
        # Pass pre-generated hypotheses to avoid duplicate hypothesis generation
        return agent.perform_multi_round_analysis(max_rounds, workflow_claims=workflow_claims)
        
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_reasoning_agent_batch(
    as_list,
    start_time,
    end_time,
    max_rounds = 3
):
    from agents.traffic_agent import run_traffic_agent_batch
    from detectors.hijack.hijack_detector import detect_hijacks_batch, detect_hijacks
    
    try:
        logger.info(f"Starting BATCH reasoning analysis for {len(as_list)} AS")
        logger.info(f"Time range: {start_time} to {end_time}")
        
        try:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        
        try:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        logger.info(f"Step 1: Batch traffic analysis for {len(as_list)} AS...")
        traffic_batch_result = run_traffic_agent_batch(
            as_list=as_list,
            start_time=start_time,
            end_time=end_time
        )
        
        if not traffic_batch_result.get("success"):
            return {
                "success": False,
                "error": "Batch traffic analysis failed",
                "traffic_result": traffic_batch_result
            }
        
        anomaly_as_list = traffic_batch_result.get("anomaly_as_list", [])
        logger.info(f"Step 2: Identified {len(anomaly_as_list)} AS with traffic anomalies: {anomaly_as_list}")
        
        if not anomaly_as_list:
            logger.info("No traffic anomalies detected. Skipping routing analysis.")
            return {
                "success": True,
                "batch_mode": True,
                "as_count": len(as_list),
                "anomaly_count": 0,
                "traffic_batch_result": traffic_batch_result,
                "routing_batch_result": None,
                "message": "No traffic anomalies detected across all AS"
            }
        
        logger.info(f"Step 2.5: Extracting anomaly time ranges for routing analysis (per AS)...")
        per_as_windows = {}
        for asn in anomaly_as_list:
            traffic_data = traffic_batch_result.get("results_by_as", {}).get(asn, {})
            anomalies = traffic_data.get("anomalies", [])
            
            if anomalies:
                anomaly_start, anomaly_end = extract_anomaly_time_range(
                    anomalies,
                    use_consecutive_periods=True,
                    min_consecutive_count=3,
                    max_gap_minutes=60,
                )
                
                if anomaly_start and anomaly_end:
                    per_as_windows[asn] = (anomaly_start, anomaly_end)
                    logger.info(f"  AS{asn}: anomaly range {anomaly_start.strftime('%Y-%m-%d %H:%M')} to {anomaly_end.strftime('%Y-%m-%d %H:%M')}")
        
        logger.info(f"Step 3: Per-AS routing analysis for {len(anomaly_as_list)} anomaly AS using individual anomaly windows...")
        routing_results_by_as = {}
        routing_failures = []
        
        for asn in anomaly_as_list:
            if asn not in per_as_windows:
                logger.info(f"  Routing analysis AS{asn} skipped (no traffic anomalies)")
                routing_results_by_as[str(asn)] = {
                    "success": True,
                    "skipped": True,
                    "reason": "no_traffic_anomaly",
                    "asn": asn,
                }
        
        as_with_windows = [asn for asn in anomaly_as_list if asn in per_as_windows]
        if not as_with_windows:
            logger.info("No AS with valid anomaly windows for routing analysis")
        else:
            window_to_as = {}
            for asn in as_with_windows:
                r_start, r_end = per_as_windows[asn]
                window_key = (r_start, r_end)
                if window_key not in window_to_as:
                    window_to_as[window_key] = []
                window_to_as[window_key].append(asn)
            
            logger.info(f"Grouped {len(as_with_windows)} AS into {len(window_to_as)} unique time windows")
            for (w_start, w_end), as_group in window_to_as.items():
                logger.info(f"  Window {w_start.strftime('%Y-%m-%d %H:%M')} to {w_end.strftime('%Y-%m-%d %H:%M')}: {len(as_group)} AS ({', '.join([f'AS{a}' for a in as_group])})")
            
            # batch_hijack_results initialization alignment:
            # for 循环跑到了 else 块之外，会在 as_with_windows 为空时也跑空迭代。
            # 重新对齐到 else 块内部，确保控制流正确。
            batch_hijack_results = None
            for (r_start, r_end), as_group in window_to_as.items():
                window_start_str = r_start.strftime('%Y-%m-%d %H:%M')
                window_end_str = r_end.strftime('%Y-%m-%d %H:%M')

                logger.info(
                    f"  Processing time window [{window_start_str} to {window_end_str}] for {len(as_group)} AS: {', '.join([f'AS{a}' for a in as_group])}"
                )

                if len(as_group) > 1:
                    logger.info(f"    Using BATCH hijack detection (read data once for {len(as_group)} AS)")
                    from detectors.hijack.hijack_detector import detect_hijacks_batch
                    from detectors.leak.leak_detector import analyze_leak_surface
                    
                    batch_hijack_results = detect_hijacks_batch(
                        start_time=r_start,
                        end_time=r_end,
                        target_as_list=[str(asn) for asn in as_group],
                        validate_with_updates=False,
                        save_alerts=False  # Don't save individual alerts in batch mode
                    )
                    
                    # Debug: Log batch_hijack_results structure for first AS
                    if not hasattr(run_reasoning_agent_batch, '_logged_batch_structure'):
                        run_reasoning_agent_batch._logged_batch_structure = True
                        logger.info(f"[DEBUG] batch_hijack_results keys: {list(batch_hijack_results.keys())}")
                        if batch_hijack_results.get("results_by_as"):
                            results_keys = list(batch_hijack_results["results_by_as"].keys())[:5]
                            logger.info(f"[DEBUG] results_by_as sample keys: {results_keys}")
                    
                    for asn in as_group:
                        try:
                            asn_str = str(asn)
                            # FIXED: Access results through 'results_by_as' key
                            # detect_hijacks_batch returns {"success": True, "results_by_as": {asn: data}}
                            # The data contains "origin_hijack" and "forge_hijack" (NOT "origin_hijacked" etc.)
                            batch_results_by_as = batch_hijack_results.get("results_by_as", {})
                            hijack_data = batch_results_by_as.get(asn_str, {})
                            
                            # Extract hijack data - convert from batch format (origin_hijack -> origin_hijacked)
                            raw_origin_hijack = hijack_data.get("origin_hijack", [])
                            raw_forge_hijack = hijack_data.get("forge_hijack", [])
                            
                            # Log to detect if hijack_data is empty when it shouldn't be
                            if hijack_data:
                                logger.info(f"[DEBUG] AS{asn_str} hijack_data: origin_hijack={len(raw_origin_hijack)}, forge_hijack={len(raw_forge_hijack)}")
                            else:
                                logger.warning(f"[DEBUG] AS{asn_str} hijack_data is EMPTY! batch_results_by_as keys: {list(batch_results_by_as.keys())}")
                            
                            leak_result = analyze_leak_surface(asn_str, window_start_str, window_end_str, target_asns=[asn_str])
                            
                            outage_result = get_outage_detector().analyze(asn_str, window_start_str, window_end_str)
                            
                            result = {
                                "success": True,
                                "asn": asn_str,
                                "analysis_period": f"{window_start_str} to {window_end_str}",
                                "analysis_timestamp": datetime.now().isoformat(),
                                
                                # Use both naming conventions for compatibility
                                "origin_hijacked": raw_origin_hijack,  # victim hijack
                                "forge_hijacked": raw_forge_hijack,    # victim forge
                                "origin_hijacking": hijack_data.get("origin_hijacking", []),
                                "forge_hijacking": hijack_data.get("forge_hijacking", []),
                                # Also keep original names for compatibility
                                "origin_hijack": raw_origin_hijack,
                                "forge_hijack": raw_forge_hijack,
                                "aggregated_alerts": hijack_data.get("aggregated_alerts", []),
                                
                                "route_leaks": leak_result.get("route_leaks", []),
                                "leak_count": leak_result.get("leak_count", 0),
                                "leak_detection_success": leak_result.get("success", False),
                                "leak_detection_error": leak_result.get("error"),
                                
                                "outage_analysis": outage_result,
                                "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
                                "outage_score": float(outage_result.get("outage_score", 0.0)) if outage_result.get("success") else 0.0,
                                
                                "total_prefix_hijacks": len(hijack_data.get("origin_hijacked", [])) + len(hijack_data.get("forge_hijacked", [])),
                                "total_prefix_hijacking": len(hijack_data.get("origin_hijacking", [])) + len(hijack_data.get("forge_hijacking", [])),
                            }
                        except Exception as exc:
                            logger.error(f"Routing analysis failed for AS{asn}: {exc}")
                            result = {
                                "success": False,
                                "error": str(exc),
                                "asn": asn,
                            }
                        
                        if not result.get("success"):
                            routing_failures.append(asn)
                        routing_results_by_as[str(asn)] = result
                        
                        logger.info(
                            f"    ✅ AS{asn}: {result.get('total_prefix_hijacks', 0)} hijacks, "
                            f"{result.get('leak_count', 0)} leaks, "
                            f"outage={result.get('outage_suspected', False)}"
                        )
                else:
                    asn = as_group[0]
                    try:
                        result = run_routing_agent(
                            asn=str(asn),
                            start_time=window_start_str,
                            end_time=window_end_str,
                            target_asns=[str(asn)]
                        )
                    except Exception as exc:
                        logger.error(f"Routing analysis failed for AS{asn}: {exc}")
                        result = {
                            "success": False,
                            "error": str(exc),
                            "asn": asn,
                        }
                    
                    if not result.get("success"):
                        routing_failures.append(asn)
                    routing_results_by_as[str(asn)] = result
                    
                    logger.info(
                        f"    ✅ AS{asn}: {result.get('total_prefix_hijacks', 0)} hijacks, "
                        f"{result.get('leak_count', 0)} leaks, "
                        f"outage={result.get('outage_suspected', False)}"
                    )
        
        # Validation: Check if hijack detection results were properly transferred
        total_hijacks_in_batch = 0
        total_hijacks_in_results = 0
        
        # Only validate if batch_hijack_results was defined (when len(as_group) > 1)
        if batch_hijack_results is not None:
            for asn_str, hijack_result in batch_hijack_results.get("results_by_as", {}).items():
                total_hijacks_in_batch += len(hijack_result.get("origin_hijacked", []) or hijack_result.get("origin_hijack", []))
                total_hijacks_in_batch += len(hijack_result.get("forge_hijacked", []) or hijack_result.get("forge_hijack", []))
        else:
            # For single AS case, extract from the routing_results directly
            pass
        
        for asn_str, routing_result in routing_results_by_as.items():
            total_hijacks_in_results += len(routing_result.get("origin_hijacked", []) or routing_result.get("origin_hijack", []))
            total_hijacks_in_results += len(routing_result.get("forge_hijacked", []) or routing_result.get("forge_hijack", []))
        
        logger.info(f"[VALIDATION] Hijack events - batch source: {total_hijacks_in_batch}, in routing_results: {total_hijacks_in_results}")
        if total_hijacks_in_batch > 0 and total_hijacks_in_results == 0:
            logger.error(f"[CRITICAL] DATA LOSS: {total_hijacks_in_batch} hijack events detected but ALL were lost during transfer!")
            logger.error(f"[CRITICAL] This indicates a bug in the routing result extraction logic.")
        elif total_hijacks_in_batch > total_hijacks_in_results:
            logger.warning(f"[WARNING] Possible data loss: batch has {total_hijacks_in_batch} hijacks but only {total_hijacks_in_results} in routing_results")

        routing_batch_result = {
            "success": len(routing_failures) == 0,
            "batch_mode": True,
            "as_count": len(anomaly_as_list),
            "results_by_as": routing_results_by_as,
            "analysis_timestamp": datetime.now().isoformat(),
            "failed_as": routing_failures,
            # Add validation metadata
            "_validation": {
                "hijack_events_in_batch": total_hijacks_in_batch,
                "hijack_events_in_results": total_hijacks_in_results,
                "data_integrity_check": "PASSED" if total_hijacks_in_batch == total_hijacks_in_results else "FAILED"
            }
        }
        
        if routing_failures:
            logger.warning(f"Routing analysis failed for AS: {routing_failures}")

        logger.info(f"Step 4: Generating reasoning analysis for {len(anomaly_as_list)} anomaly AS (parallelized)...")
        reasoning_results = {}
        
        def process_single_as_reasoning(asn):
            """Process reasoning analysis for a single AS"""
            logger.info(f"Reasoning analysis for AS{asn}...")
            
            traffic_data = traffic_batch_result["results_by_as"].get(asn, {})
            routing_data = routing_batch_result["results_by_as"].get(asn, {})
            
            # Create a mini reasoning agent for this AS
            agent = ReasoningAgent(asn, start_dt, end_dt, use_llm_reasoning=True)
            
            # Inject pre-computed results into evidence pool
            agent.evidence_pool = {
                "routing_data": routing_data,
                "traffic_data": traffic_data,
                "data_quality": agent.assess_data_quality(routing_data, traffic_data)
            }
            
            # Perform multi-round reasoning analysis
            for round_num in range(1, max_rounds + 1):
                agent.round_count = round_num
                agent.reasoning_trace.append(f"\n=== ROUND {round_num} REASONING ===")
                
                round_result = agent.perform_reasoning_round({"success": True}, round_num)
                
                if agent.should_conclude_analysis():
                    agent.reasoning_trace.append(f"Analysis concluded after {round_num} rounds")
                    break
            
            # Generate final integration
            reasoning_result = agent.phase3_final_integration()
            return asn, reasoning_result
        
        # Parallelize reasoning analysis using ThreadPoolExecutor (I/O bound, not CPU bound)
        from concurrent.futures import ThreadPoolExecutor, as_completed
        max_workers = min(len(anomaly_as_list), 4)  # Limit to 4 concurrent LLM calls
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_single_as_reasoning, asn): asn for asn in anomaly_as_list}
            
            for future in as_completed(futures):
                try:
                    asn, reasoning_result = future.result()
                    reasoning_results[asn] = reasoning_result
                    logger.info(f"✅ Completed reasoning analysis for AS{asn}")
                except Exception as e:
                    asn = futures[future]
                    logger.error(f"❌ Failed reasoning analysis for AS{asn}: {e}")
                    reasoning_results[asn] = {
                        "success": False,
                        "error": str(e),
                        "asn": asn
                    }
        
        # Summary
        logger.info(f"Batch reasoning analysis completed for {len(as_list)} AS")
        logger.info(f"  - Total AS analyzed: {len(as_list)}")
        logger.info(f"  - AS with traffic anomalies: {len(anomaly_as_list)}")
        logger.info(f"  - AS with routing anomalies: {sum(1 for asn in anomaly_as_list if reasoning_results[asn].get('success'))}")
        
        return {
            "success": True,
            "batch_mode": True,
            "analysis_type": "batch_multi-round_reasoning",
            "as_count": len(as_list),
            "anomaly_count": len(anomaly_as_list),
            "time_range": f"{start_time} to {end_time}",
            "traffic_batch_result": traffic_batch_result,
            "routing_batch_result": routing_batch_result,
            "reasoning_results": reasoning_results,
            "anomaly_as_list": anomaly_as_list,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Batch reasoning analysis failed: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "batch_mode": True
        }


__all__ = ["ReasoningAgent", "run_reasoning_agent", "run_reasoning_agent_batch"] 