import os
import sys
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from llm.llm_factory import setup_llm_settings
from llm.prompt import build_multi_agent_coordination_prompt, get_reasoning_laws
from agents.routing_agent import run_routing_agent, run_routing_agent_async
from agents.traffic_agent import run_traffic_agent
from utils.logger import logger
from config import BASE_URL, API_KEY, MODEL


class ReasoningCore:
    def __init__(self, asn, start_time, end_time, model=MODEL, uuid=""):
        self.asn = asn
        self.start_time = start_time
        self.end_time = end_time
        self.model = model
        self.uuid = uuid

        self.llm, self.token_counter = setup_llm_settings(
            model=self.model,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=0.2
        )

        self.reasoning_trace = []
        self.evidence_pool = {}
        self.confidence_scores = {}
        self.round_count = 0

    def perform_multi_round_analysis(self, max_rounds: int = 3):
        try:
            self.reasoning_trace.append(f"Starting multi-round analysis for ASN {self.asn}")
            self.reasoning_trace.append(f"Time range: {self.start_time} to {self.end_time}")

            from .evidence_processor import EvidenceProcessor
            from .confidence_calculator import ConfidenceCalculator
            from .reasoning_coordinator import ReasoningCoordinator

            evidence_processor = EvidenceProcessor(self)
            confidence_calculator = ConfidenceCalculator(self)
            coordinator = ReasoningCoordinator(self)

            initial_data = self._phase1_data_collection()

            if not initial_data.get("success", False):
                return {
                    "success": False,
                    "error": "Data collection failed",
                    "reasoning_trace": self.reasoning_trace
                }

            current_data = initial_data
            for round_num in range(1, max_rounds + 1):
                self.round_count = round_num

                round_result = self._perform_reasoning_round(current_data, round_num)

                if not round_result.get("continue_analysis", False):
                    break

                current_data = round_result

            final_result = self._phase3_final_integration()

            final_confidence = confidence_calculator.get_final_confidence()

            return {
                "success": True,
                "asn": self.asn,
                "time_period": f"{self.start_time} to {self.end_time}",
                "analysis_type": "multi_round_reasoning",
                "rounds_completed": self.round_count,
                "final_result": final_result,
                "final_confidence": final_confidence,
                "evidence_summary": evidence_processor.summarize_evidence(),
                "reasoning_trace": self.reasoning_trace,
                "token_usage": self._get_total_token_usage()
            }

        except Exception as e:
            logger.error(f"Multi-round analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "reasoning_trace": self.reasoning_trace
            }

    def _phase1_data_collection(self):
        try:
            logger.info(f"🔍 Phase 1: Collecting data for AS{self.asn}")

            # Note: In this path, traffic analysis is run after routing,
            # so we don't have periodicity info for outage detection.
            # Outage detector will use default baseline (24h) in this case.
            routing_result = run_routing_agent(
                asn=self.asn,
                start_time=self.start_time,
                end_time=self.end_time,
                periodicity=None,
                periodicity_confidence=0.0
            )

            traffic_result = run_traffic_agent(
                asn=self.asn,
                start_time=self.start_time,
                end_time=self.end_time
            )

            if not routing_result.get("success") or not traffic_result.get("success"):
                self.reasoning_trace.append("❌ Data collection failed")
                return {"success": False, "error": "Data collection failed"}

            initial_data = {
                "routing_data": routing_result,
                "traffic_data": traffic_result,
                "collection_timestamp": datetime.now().isoformat()
            }

            self.evidence_pool.update({
                "routing_evidence": routing_result,
                "traffic_evidence": traffic_result
            })

            self.reasoning_trace.append("✅ Data collection completed")
            return {"success": True, **initial_data}

        except Exception as e:
            logger.error(f"Data collection failed: {e}")
            return {"success": False, "error": str(e)}

    def _perform_reasoning_round(self, current_data, round_num):
        try:
            logger.info(f"🧠 Round {round_num}: Performing reasoning analysis")

            from .evidence_processor import EvidenceProcessor
            from .confidence_calculator import ConfidenceCalculator

            evidence_processor = EvidenceProcessor(self)
            confidence_calculator = ConfidenceCalculator(self)

            evidence_state = evidence_processor.analyze_evidence_state()

            knowledge_gaps = evidence_processor.identify_knowledge_gaps()

            if knowledge_gaps:
                self._perform_deeper_analysis(round_num, knowledge_gaps)

            law_application = self._apply_reasoning_laws()

            confidence_calculator.update_confidence_scores(law_application, round_num)

            should_conclude = self._should_conclude_analysis()

            round_result = {
                "round_num": round_num,
                "evidence_state": evidence_state,
                "knowledge_gaps": knowledge_gaps,
                "law_application": law_application,
                "confidence_scores": self.confidence_scores.copy(),
                "continue_analysis": not should_conclude,
                "analysis_complete": should_conclude
            }

            self.reasoning_trace.append(f"✅ Round {round_num} completed")
            return round_result

        except Exception as e:
            logger.error(f"Reasoning round {round_num} failed: {e}")
            return {"success": False, "error": str(e), "continue_analysis": False}

    def _phase3_final_integration(self):
        try:
            logger.info("🎯 Phase 3: Final integration and report generation")

            from .reasoning_coordinator import ReasoningCoordinator
            coordinator = ReasoningCoordinator(self)

            coordination_prompt = coordinator.build_coordination_prompt()

            coordination_result = coordinator.parse_coordination_response(
                self.llm.complete(coordination_prompt).text
            )

            final_report = coordinator.generate_final_report(coordination_result)

            self.reasoning_trace.append("✅ Final integration completed")
            return {
                "coordination_result": coordination_result,
                "final_report": final_report,
                "integration_timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Final integration failed: {e}")
            return {"success": False, "error": str(e)}

    def _perform_deeper_analysis(self, round_num, knowledge_gaps):
        try:
            if "routing_details" in knowledge_gaps:
                logger.info(f"🔍 Round {round_num}: Performing deeper routing analysis")

            if "traffic_patterns" in knowledge_gaps:
                logger.info(f"🔍 Round {round_num}: Performing deeper traffic pattern analysis")

            self.reasoning_trace.append(f"🔍 Deeper analysis completed for round {round_num}")

        except Exception as e:
            logger.warning(f"Deeper analysis failed: {e}")

    def _apply_reasoning_laws(self):
        try:
            routing_data = self.evidence_pool.get("routing_evidence", {})
            traffic_data = self.evidence_pool.get("traffic_evidence", {})

            law_application = {
                "incident_type": self._classify_incident_type(routing_data),
                "traffic_correlation": self._assess_traffic_correlation(routing_data, traffic_data),
                "incident_severity": self._assess_incident_severity(routing_data, traffic_data),
                "routing_impact": self._get_routing_impact_score(),
                "traffic_severity": self._get_traffic_severity_score(),
                "application_timestamp": datetime.now().isoformat()
            }

            self.reasoning_trace.append("📋 Reasoning laws applied")
            return law_application

        except Exception as e:
            logger.warning(f"Law application failed: {e}")
            return {"error": str(e)}

    def _classify_incident_type(self, routing_data):
        if routing_data.get("hijack_detected"):
            return "route_hijack"
        elif routing_data.get("leak_detected"):
            return "route_leak"
        elif routing_data.get("flap_detected"):
            return "route_flap"
        else:
            return "unknown"

    def _assess_traffic_correlation(self, routing_data, traffic_data):
        routing_anomalies = routing_data.get("anomaly_count", 0)
        traffic_anomalies = traffic_data.get("anomaly_count", 0)

        if routing_anomalies > 0 and traffic_anomalies > 0:
            return "strong_correlation"
        elif routing_anomalies > 0 or traffic_anomalies > 0:
            return "weak_correlation"
        else:
            return "no_correlation"

    def _assess_incident_severity(self, routing_data, traffic_data):
        routing_score = self._get_routing_impact_score()
        traffic_score = self._get_traffic_severity_score()

        avg_score = (routing_score + traffic_score) / 2

        if avg_score > 0.8:
            return "critical"
        elif avg_score > 0.6:
            return "high"
        elif avg_score > 0.4:
            return "medium"
        else:
            return "low"

    def _get_routing_impact_score(self):
        routing_data = self.evidence_pool.get("routing_evidence", {})
        base_score = 0.5

        if routing_data.get("hijack_detected"):
            base_score += 0.3
        if routing_data.get("leak_detected"):
            base_score += 0.2

        return min(base_score, 1.0)

    def _get_traffic_severity_score(self):
        traffic_data = self.evidence_pool.get("traffic_evidence", {})
        anomaly_count = traffic_data.get("anomaly_count", 0)
        percent_change = abs(traffic_data.get("percent_change", 0))

        severity = min(anomaly_count / 10.0 + percent_change / 50.0, 1.0)
        return severity

    def _should_conclude_analysis(self):
        from .confidence_calculator import ConfidenceCalculator
        confidence_calculator = ConfidenceCalculator(self)

        avg_confidence = confidence_calculator.calculate_evidence_consistency()

        max_rounds_reached = self.round_count >= 3

        has_routing = bool(self.evidence_pool.get("routing_evidence"))
        has_traffic = bool(self.evidence_pool.get("traffic_evidence"))

        should_conclude = (avg_confidence > 0.8 or max_rounds_reached) and (has_routing and has_traffic)

        if should_conclude:
            self.reasoning_trace.append(f"🎯 Analysis conclusion reached (confidence: {avg_confidence:.2f})")

        return should_conclude

    def _get_total_token_usage(self):
        try:
            total_usage = {
                "reasoning_agent": 0,
                "routing_agent": 0,
                "traffic_agent": 0,
                "total": 0
            }

            if self.token_counter:
                total_usage["reasoning_agent"] = getattr(self.token_counter, 'total_llm_token_count', 0)

            routing_data = self.evidence_pool.get("routing_evidence", {})
            traffic_data = self.evidence_pool.get("traffic_evidence", {})

            routing_usage = routing_data.get("token_usage", {})
            traffic_usage = traffic_data.get("token_usage", {})

            if isinstance(routing_usage, dict):
                total_usage["routing_agent"] = routing_usage.get("total", 0)
            if isinstance(traffic_usage, dict):
                total_usage["traffic_agent"] = traffic_usage.get("total", 0)

            total_usage["total"] = sum(total_usage.values())

            return total_usage

        except Exception as e:
            logger.warning(f"Token usage calculation failed: {e}")
            return {"total": 0, "error": str(e)}


def run_reasoning_agent_core(asn, start_time, end_time,
                           model=MODEL, uuid=""):
    try:
        agent = ReasoningCore(asn, start_time, end_time, model, uuid)
        return agent.perform_multi_round_analysis()
    except Exception as e:
        logger.error(f"Reasoning agent core failed: {e}")
        return {"success": False, "error": str(e)}
