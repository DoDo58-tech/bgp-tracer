import os
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utils.logger import logger


class ConfidenceCalculator:
    def __init__(self, reasoning_core):
        self.core = reasoning_core

    def update_confidence_scores(self, law_application, round_num):
        try:
            evidence_consistency = self.calculate_evidence_consistency()
            classification_confidence = self.get_classification_confidence(law_application)
            routing_impact = law_application.get("routing_impact", 0.5)
            traffic_severity = law_application.get("traffic_severity", 0.5)

            small_bgp_penalty = self.apply_small_bgp_penalty(classification_confidence)

            overall_confidence = (
                evidence_consistency * 0.3 +
                classification_confidence * 0.3 +
                routing_impact * 0.2 +
                traffic_severity * 0.2
            ) * (1 - small_bgp_penalty)

            # Update confidence scores
            self.core.confidence_scores.update({
                "evidence_consistency": evidence_consistency,
                "classification_confidence": classification_confidence,
                "routing_impact": routing_impact,
                "traffic_severity": traffic_severity,
                "small_bgp_penalty": small_bgp_penalty,
                "overall_confidence": overall_confidence,
                "last_updated_round": round_num,
                "update_timestamp": datetime.now().isoformat()
            })

            self.core.reasoning_trace.append(".2f")

        except Exception as e:
            logger.warning(f"Confidence score update failed: {e}")

    def calculate_evidence_consistency(self):
        try:
            routing_data = self.core.evidence_pool.get("routing_evidence", {})
            traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

            consistency_factors = []

            if self.check_temporal_consistency(routing_data, traffic_data):
                consistency_factors.append(1.0)
            else:
                consistency_factors.append(0.5)

            correlation_score = self.calculate_anomaly_correlation(routing_data, traffic_data)
            consistency_factors.append(correlation_score)

            quality_score = self.assess_data_quality_consistency(routing_data, traffic_data)
            consistency_factors.append(quality_score)

            if consistency_factors:
                return sum(consistency_factors) / len(consistency_factors)
            else:
                return 0.5

        except Exception as e:
            logger.warning(f"Evidence consistency calculation failed: {e}")
            return 0.5

    def get_final_confidence(self):
        try:
            current_scores = self.core.confidence_scores

            conflicts = self.detect_agent_conflicts()
            if conflicts:
                resolution = self.resolve_conflicts(conflicts)
                current_scores["conflicts_detected"] = conflicts
                current_scores["conflict_resolution"] = resolution

            completeness = self.assess_analysis_completeness()

            final_assessment = {
                "final_confidence_score": current_scores.get("overall_confidence", 0.5),
                "confidence_level": self.get_confidence_level(current_scores.get("overall_confidence", 0.5)),
                "evidence_consistency": current_scores.get("evidence_consistency", 0.5),
                "classification_confidence": current_scores.get("classification_confidence", 0.5),
                "analysis_completeness": completeness,
                "conflicts_resolved": len(conflicts) == 0,
                "assessment_timestamp": datetime.now().isoformat()
            }

            return final_assessment

        except Exception as e:
            logger.warning(f"Final confidence assessment failed: {e}")
            return {"final_confidence_score": 0.5, "error": str(e)}

    def get_classification_confidence(self, law_application):
        try:
            incident_type = law_application.get("incident_type", "unknown")
            traffic_correlation = law_application.get("traffic_correlation", "no_correlation")
            severity = law_application.get("incident_severity", "unknown")

            base_confidence = {
                "route_hijack": 0.8,
                "route_leak": 0.7,
                "route_flap": 0.6,
                "unknown": 0.3
            }.get(incident_type, 0.3)

            correlation_multiplier = {
                "strong_correlation": 1.0,
                "weak_correlation": 0.8,
                "no_correlation": 0.6
            }.get(traffic_correlation, 0.6)

            severity_multiplier = {
                "critical": 1.0,
                "high": 0.9,
                "medium": 0.8,
                "low": 0.7,
                "unknown": 0.5
            }.get(severity, 0.5)

            return base_confidence * correlation_multiplier * severity_multiplier

        except Exception as e:
            logger.warning(f"Classification confidence calculation failed: {e}")
            return 0.5

    def apply_small_bgp_penalty(self, base_confidence):
        try:
            penalty = 0.05
            return penalty

        except Exception as e:
            logger.warning(f"Small BGP penalty calculation failed: {e}")
            return 0.0

    def check_temporal_consistency(self, routing_data, traffic_data):
        routing_start = routing_data.get("start_time")
        routing_end = routing_data.get("end_time")
        traffic_start = traffic_data.get("start_time")
        traffic_end = traffic_data.get("end_time")

        if routing_start and traffic_start and routing_end and traffic_end:
            start_diff = abs((datetime.fromisoformat(routing_start.replace('Z', '+00:00')) -
                            datetime.fromisoformat(traffic_start.replace('Z', '+00:00'))).total_seconds())
            end_diff = abs((datetime.fromisoformat(routing_end.replace('Z', '+00:00')) -
                          datetime.fromisoformat(traffic_end.replace('Z', '+00:00'))).total_seconds())

            return start_diff < 3600 and end_diff < 3600

        return False

    def calculate_anomaly_correlation(self, routing_data, traffic_data):
        routing_anomalies = routing_data.get("anomaly_count", 0)
        traffic_anomalies = traffic_data.get("anomaly_count", 0)

        if routing_anomalies > 0 and traffic_anomalies > 0:
            return 1.0
        elif routing_anomalies > 0 or traffic_anomalies > 0:
            return 0.6
        else:
            return 0.3

    def assess_data_quality_consistency(self, routing_data, traffic_data):
        routing_success = routing_data.get("success", False)
        traffic_success = traffic_data.get("success", False)

        if routing_success and traffic_success:
            return 1.0
        elif routing_success or traffic_success:
            return 0.7
        else:
            return 0.3

    def detect_agent_conflicts(self):
        conflicts = []

        try:
            routing_data = self.core.evidence_pool.get("routing_evidence", {})
            traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

            routing_has_anomalies = routing_data.get("anomalies_detected", False)
            traffic_has_anomalies = traffic_data.get("anomalies_detected", False)

            if routing_has_anomalies != traffic_has_anomalies:
                conflicts.append("inconsistent_anomaly_detection")

            routing_severity = routing_data.get("severity", "unknown")
            traffic_severity = traffic_data.get("severity", "unknown")

            severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 0}
            routing_level = severity_levels.get(routing_severity, 0)
            traffic_level = severity_levels.get(traffic_severity, 0)

            if abs(routing_level - traffic_level) > 2:
                conflicts.append("severity_assessment_discrepancy")

            return conflicts if conflicts else None

        except Exception as e:
            logger.warning(f"Conflict detection failed: {e}")
            return None

    def resolve_conflicts(self, conflicts):
        resolutions = {
            "inconsistent_anomaly_detection": "Investigate further - may indicate different types of events",
            "severity_assessment_discrepancy": "Cross-reference with additional data sources"
        }

        return "; ".join([resolutions.get(conflict, "Manual review required") for conflict in conflicts])

    def assess_analysis_completeness(self):
        try:
            has_routing = bool(self.core.evidence_pool.get("routing_evidence"))
            has_traffic = bool(self.core.evidence_pool.get("traffic_evidence"))

            confidence_score = self.core.confidence_scores.get("overall_confidence", 0)

            rounds_completed = self.core.round_count

            return has_routing and has_traffic and confidence_score > 0.6 and rounds_completed >= 2

        except Exception as e:
            logger.warning(f"Analysis completeness assessment failed: {e}")
            return False

    def get_confidence_level(self, confidence_score):
        if confidence_score >= 0.9:
            return "very_high"
        elif confidence_score >= 0.8:
            return "high"
        elif confidence_score >= 0.7:
            return "moderate"
        elif confidence_score >= 0.6:
            return "low"
        else:
            return "very_low"
