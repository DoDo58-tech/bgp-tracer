import os
import sys
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utils.logger import logger


class EvidenceProcessor:
    def __init__(self, reasoning_core):
        self.core = reasoning_core

    def analyze_evidence_state(self):
        try:
            routing_evidence = self.core.evidence_pool.get("routing_evidence", {})
            traffic_evidence = self.core.evidence_pool.get("traffic_evidence", {})

            state_analysis = {
                "routing_evidence_count": self._count_routing_evidence(),
                "traffic_evidence_count": self._count_traffic_evidence(),
                "evidence_quality": self._assess_evidence_quality(),
                "data_completeness": self._assess_data_completeness(),
                "temporal_alignment": self._check_temporal_alignment(),
                "analysis_timestamp": datetime.now().isoformat()
            }

            self.core.reasoning_trace.append("📊 Evidence state analyzed")
            return state_analysis

        except Exception as e:
            logger.warning(f"Evidence state analysis failed: {e}")
            return {"error": str(e)}

    def identify_knowledge_gaps(self):
        gaps = []

        try:
            routing_data = self.core.evidence_pool.get("routing_evidence", {})
            traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

            if not routing_data.get("detailed_analysis"):
                gaps.append("routing_details")

            if not traffic_data.get("pattern_analysis"):
                gaps.append("traffic_patterns")

            if not self._has_temporal_correlation():
                gaps.append("temporal_correlation")

            if not routing_data.get("geographic_impact"):
                gaps.append("geographic_impact")

            if not routing_data.get("affected_networks"):
                gaps.append("affected_networks")

            if gaps:
                self.core.reasoning_trace.append(f"🔍 Identified knowledge gaps: {', '.join(gaps)}")

            return gaps

        except Exception as e:
            logger.warning(f"Knowledge gap identification failed: {e}")
            return []

    def summarize_evidence(self):
        try:
            routing_summary = self._summarize_routing_results()
            traffic_summary = self._summarize_traffic_results()

            overall_summary = {
                "routing_summary": routing_summary,
                "traffic_summary": traffic_summary,
                "correlation_assessment": self._assess_final_correlation(),
                "evidence_counts": {
                    "routing": self._count_routing_evidence(),
                    "traffic": self._count_traffic_evidence()
                },
                "summary_timestamp": datetime.now().isoformat()
            }

            return overall_summary

        except Exception as e:
            logger.warning(f"Evidence summarization failed: {e}")
            return {"error": str(e)}

    def _assess_evidence_quality(self):
        routing_quality = self._assess_routing_quality()
        traffic_quality = self._assess_traffic_quality()

        overall_quality = {
            "routing_quality": routing_quality,
            "traffic_quality": traffic_quality,
            "overall_score": (routing_quality["score"] + traffic_quality["score"]) / 2,
            "quality_assessment": "good" if (routing_quality["score"] + traffic_quality["score"]) / 2 > 0.7 else "needs_improvement"
        }

        return overall_quality

    def _assess_routing_quality(self):
        routing_data = self.core.evidence_pool.get("routing_evidence", {})

        quality_score = 0.0
        issues = []

        if routing_data.get("success"):
            quality_score += 0.3
        else:
            issues.append("missing_routing_data")

        if routing_data.get("anomalies_detected"):
            quality_score += 0.3
        else:
            issues.append("no_anomalies_detected")

        if routing_data.get("detailed_analysis"):
            quality_score += 0.2
        else:
            issues.append("missing_detailed_analysis")

        if routing_data.get("geographic_impact"):
            quality_score += 0.2
        else:
            issues.append("missing_geographic_data")

        return {
            "score": quality_score,
            "issues": issues,
            "recommendations": self._generate_quality_recommendations(issues, "routing")
        }

    def _assess_traffic_quality(self):
        traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

        quality_score = 0.0
        issues = []

        if traffic_data.get("success"):
            quality_score += 0.3
        else:
            issues.append("missing_traffic_data")

        if traffic_data.get("anomalies_detected"):
            quality_score += 0.3
        else:
            issues.append("no_anomalies_detected")

        if traffic_data.get("period_detection"):
            quality_score += 0.2
        else:
            issues.append("missing_period_detection")

        if traffic_data.get("expanded_boundaries"):
            quality_score += 0.2
        else:
            issues.append("missing_boundary_expansion")

        return {
            "score": quality_score,
            "issues": issues,
            "recommendations": self._generate_quality_recommendations(issues, "traffic")
        }

    def _generate_quality_recommendations(self, issues: List[str], data_type: str) -> List[str]:
        recommendations = []

        for issue in issues:
            if issue == "missing_routing_data":
                recommendations.append("Re-run routing analysis with expanded time window")
            elif issue == "no_anomalies_detected":
                recommendations.append("Adjust anomaly detection thresholds")
            elif issue == "missing_detailed_analysis":
                recommendations.append("Perform deeper routing path analysis")
            elif issue == "missing_geographic_data":
                recommendations.append("Include geographical impact assessment")
            elif issue == "missing_traffic_data":
                recommendations.append("Re-run traffic analysis with different parameters")
            elif issue == "missing_period_detection":
                recommendations.append("Enable automatic period detection")
            elif issue == "missing_boundary_expansion":
                recommendations.append("Enable automatic boundary expansion")

        return recommendations

    def _assess_data_completeness(self):
        completeness_score = 0.0

        routing_data = self.core.evidence_pool.get("routing_evidence", {})
        if routing_data.get("success"):
            routing_complete = sum([
                1 for field in ["anomalies", "paths", "geographic_impact", "affected_networks"]
                if routing_data.get(field) is not None
            ]) / 4.0
            completeness_score += routing_complete * 0.5

        traffic_data = self.core.evidence_pool.get("traffic_evidence", {})
        if traffic_data.get("success"):
            traffic_complete = sum([
                1 for field in ["anomalies", "period_detection", "expanded_boundaries", "current_values"]
                if traffic_data.get(field) is not None
            ]) / 4.0
            completeness_score += traffic_complete * 0.5

        return completeness_score

    def _check_temporal_alignment(self):
        routing_data = self.core.evidence_pool.get("routing_evidence", {})
        traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

        routing_start = routing_data.get("start_time")
        routing_end = routing_data.get("end_time")
        traffic_start = traffic_data.get("start_time")
        traffic_end = traffic_data.get("end_time")

        return (routing_start == traffic_start and routing_end == traffic_end)

    def _has_temporal_correlation(self):
        routing_data = self.core.evidence_pool.get("routing_evidence", {})
        traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

        routing_anomalies = routing_data.get("anomalies", [])
        traffic_anomalies = traffic_data.get("anomalies", [])

        return len(routing_anomalies) > 0 and len(traffic_anomalies) > 0

    def _count_routing_evidence(self):
        routing_data = self.core.evidence_pool.get("routing_evidence", {})

        return {
            "total_anomalies": routing_data.get("anomaly_count", 0),
            "unique_paths": len(routing_data.get("paths", [])),
            "affected_prefixes": len(routing_data.get("affected_prefixes", [])),
            "geographic_locations": len(routing_data.get("geographic_impact", []))
        }

    def _count_traffic_evidence(self):
        traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

        return {
            "total_anomalies": traffic_data.get("anomaly_count", 0),
            "data_points": traffic_data.get("data_points", 0),
            "period_detected": traffic_data.get("period_detection", {}).get("period_name", "unknown"),
            "boundaries_expanded": traffic_data.get("expanded_boundaries") is not None
        }

    def _assess_final_correlation(self):
        routing_count = self._count_routing_evidence()["total_anomalies"]
        traffic_count = self._count_traffic_evidence()["total_anomalies"]

        if routing_count > 0 and traffic_count > 0:
            return "strong_correlation"
        elif routing_count > 0 or traffic_count > 0:
            return "partial_correlation"
        else:
            return "no_correlation"

    def _summarize_routing_results(self):
        routing_data = self.core.evidence_pool.get("routing_evidence", {})

        if not routing_data.get("success"):
            return "Routing analysis failed or incomplete"

        summary_parts = []

        anomaly_count = routing_data.get("anomaly_count", 0)
        summary_parts.append(f"Detected {anomaly_count} routing anomalies")

        incident_type = routing_data.get("incident_type", "unknown")
        summary_parts.append(f"Incident type: {incident_type}")

        geo_impact = routing_data.get("geographic_impact", [])
        if geo_impact:
            summary_parts.append(f"Affected {len(geo_impact)} geographic regions")

        return ". ".join(summary_parts)

    def _summarize_traffic_results(self):
        traffic_data = self.core.evidence_pool.get("traffic_evidence", {})

        if not traffic_data.get("success"):
            return "Traffic analysis failed or incomplete"

        summary_parts = []

        anomaly_count = traffic_data.get("anomaly_count", 0)
        summary_parts.append(f"Detected {anomaly_count} traffic anomalies")

        percent_change = traffic_data.get("percent_change", 0)
        try:
            summary_parts.append(f"Traffic changed by {percent_change:.1f}% compared to baseline")
        except Exception:
            summary_parts.append(f"Traffic change: {percent_change}")

        period_info = traffic_data.get("period_detection", {})
        if period_info.get("period_name"):
            summary_parts.append(f"Traffic pattern: {period_info['period_name']} cycle")

        if traffic_data.get("expanded_boundaries"):
            summary_parts.append("Anomaly boundaries automatically expanded")

        return ". ".join(summary_parts)
