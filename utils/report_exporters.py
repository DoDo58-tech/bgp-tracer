"""
Report export functions for BGP security analysis.

This module handles saving and exporting BGP security analysis reports
in various formats including HTML, JSON, and PDF.
"""

import os
import json
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from .logger import logger


def save_html_report(asn: str, time_range: str, html_content: str,
                    output_dir: Optional[str] = None) -> str:
    """
    Save HTML report to file.

    Args:
        asn: AS number
        time_range: Analysis time range
        html_content: Complete HTML report content
        output_dir: Output directory (optional)

    Returns:
        Path to saved HTML file
    """
    try:
        if output_dir is None:
            output_dir = Path(__file__).resolve().parent.parent / "results" / "html"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        filename = f"bgp_security_report_AS{asn_clean}_{timestamp}.html"
        file_path = output_dir / filename

        # Write HTML content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report saved to: {file_path}")
        return str(file_path)

    except Exception as e:
        logger.error(f"Error saving HTML report: {e}")
        raise


def save_json_report(analysis_data: Dict[str, Any], asn: str,
                    output_dir: Optional[str] = None) -> str:
    """
    Save analysis data as JSON report.

    Args:
        analysis_data: Complete analysis results
        asn: AS number
        output_dir: Output directory (optional)

    Returns:
        Path to saved JSON file
    """
    try:
        # Always use json directory for JSON reports, ignore passed output_dir
        output_dir = Path(__file__).resolve().parent.parent / "results" / "json"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        filename = f"bgp_analysis_AS{asn_clean}_{timestamp}.json"
        file_path = output_dir / filename

        # Prepare data for JSON serialization
        json_data = make_json_serializable(analysis_data)

        # Write JSON content
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON report saved to: {file_path}")
        return str(file_path)

    except Exception as e:
        logger.error(f"Error saving JSON report: {e}")
        raise


def generate_comprehensive_report(llm, routing_analysis: Dict[str, Any],
                                traffic_analysis: Dict[str, Any],
                                law_analysis: Optional[Dict[str, Any]],
                                reasoning_analysis: Dict[str, Any],
                                start_time: str, output_dir: Optional[str] = None,
                                org_name: Optional[str] = None, asn: Optional[str] = None,
                                fallback_report_func=None, user_input_time_range: Optional[str] = None,
                                no_anomalies: bool = False) -> Dict[str, Any]:
    """
    Generate comprehensive BGP security analysis report.

    This is the main entry point for report generation, coordinating
    all rendering and export functions.

    Args:
        llm: LLM instance for analysis
        routing_analysis: Routing analysis results
        traffic_analysis: Traffic analysis results
        law_analysis: Reasoning law analysis results
        reasoning_analysis: Complete reasoning analysis
        start_time: Analysis start time
        output_dir: Output directory
        org_name: Organization name
        asn: AS number
        fallback_report_func: Fallback report generation function

    Returns:
        Report generation results
    """
    try:
        from .report_renderers import (
            render_traffic_analysis_section,
            render_routing_analysis_section,
            render_anomaly_details_section,
            render_root_cause_analysis,
            render_recommendations_section,
            render_technical_details_section,
            render_summary_html
        )

        # Extract basic information
        target_as = asn or (reasoning_analysis.get("asn") if isinstance(reasoning_analysis, dict) else "Unknown")
        # If routing_analysis is batch_mode (results_by_as), resolve to target AS so report shows detected anomalies
        if isinstance(routing_analysis, dict) and routing_analysis.get("batch_mode") and routing_analysis.get("results_by_as"):
            _resolved = routing_analysis.get("results_by_as", {}).get(str(target_as), {})
            if isinstance(_resolved, dict) and ("origin_hijacked" in _resolved or "forge_hijacked" in _resolved):
                routing_analysis = _resolved

        # Determine time range: prefer explicit user_input_time_range, then reasoning/routing/traffic analysis fields
        if user_input_time_range:
            time_range = user_input_time_range
        else:
            time_range = None
            # Try common fields
            if isinstance(reasoning_analysis, dict):
                time_range = reasoning_analysis.get("time_range") or reasoning_analysis.get("analysis_period")
            if not time_range and isinstance(routing_analysis, dict):
                time_range = routing_analysis.get("analysis_period")
            if not time_range and isinstance(traffic_analysis, dict):
                time_range = traffic_analysis.get("analysis_period")
            if not time_range:
                time_range = f"{start_time} to Unknown"

        # Determine primary classification
        primary_class = _determine_primary_classification(reasoning_analysis)

        # Count total events
        total_events = _count_total_events(routing_analysis, traffic_analysis)

        # Determine detected anomaly time range from traffic_analysis if available
        detected_range = "Unknown"
        detected_start = None
        detected_end = None
        if traffic_analysis and traffic_analysis.get("detected_start") and traffic_analysis.get("detected_end"):
            detected_start = traffic_analysis.get("detected_start")
            detected_end = traffic_analysis.get("detected_end")
            detected_range = f"{detected_start} to {detected_end}"

        # Generate executive summary (include detected range and counts)
        exec_summary = _generate_executive_summary(
            reasoning_analysis, primary_class,
            time_range=time_range, detected_range=detected_range,
            routing_analysis=routing_analysis, traffic_analysis=traffic_analysis
        )

        # Render individual sections
        traffic_section = render_traffic_analysis_section(
            traffic_analysis,
            traffic_analysis.get("plot_path")
        )

        routing_section = render_routing_analysis_section(routing_analysis)

        all_anomalies = _get_anomalies(routing_analysis, traffic_analysis)
        anomaly_section = render_anomaly_details_section(all_anomalies)

        # Synthesize root cause and recommendations if reasoning analysis does not provide them
        root_cause_data = {}
        reasoning_trace_text = ""
        
        if isinstance(reasoning_analysis, dict):
            # Extract reasoning trace for report
            reasoning_trace_list = reasoning_analysis.get("reasoning_trace", [])
            if reasoning_trace_list:
                reasoning_trace_text = "\n".join(f"- {item}" for item in reasoning_trace_list)
            
            root_cause_data = reasoning_analysis.get("root_cause_analysis", {}) or {}
            
            # Also check final_classification for incident type
            if not root_cause_data:
                final_class = reasoning_analysis.get("final_classification", {})
                if isinstance(final_class, dict):
                    integrated = final_class.get("integrated_findings", {})
                    if integrated:
                        root_cause_data = {
                            "primary_cause": integrated.get("incident_type", "Unknown"),
                            "confidence": integrated.get("confidence_level", "medium"),
                            "contributing_factors": [],
                            "technical_details": str(integrated)
                        }
            # Build a simple deterministic root cause summary based on routing/traffic results
            primary_cause = "Unknown"
            if routing_analysis and isinstance(routing_analysis, dict):
                hijacks = routing_analysis.get("total_prefix_hijacks", 0)
                leaks = routing_analysis.get("leak_count", 0)
                if isinstance(hijacks, (int, float)) and hijacks > 0:
                    primary_cause = "Prefix Hijack(s) detected"
                elif isinstance(leaks, (int, float)) and leaks > 0:
                    primary_cause = "Route Leak(s) detected"
            if primary_cause == "Unknown" and traffic_analysis and isinstance(traffic_analysis, dict):
                anomaly_count = traffic_analysis.get("anomaly_count", 0)
                if isinstance(anomaly_count, (int, float)) and anomaly_count > 0:
                    primary_cause = "Traffic Anomaly detected"

            root_cause_data = {
                "primary_cause": primary_cause,
                "confidence": "medium",
                "contributing_factors": [],
                "technical_details": ""
            }

        root_cause_section = render_root_cause_analysis(root_cause_data)

        recommendations = []
        if isinstance(reasoning_analysis, dict):
            recommendations = reasoning_analysis.get("recommendations", []) or []
        if not recommendations:
            # Generate fallback recommendations
            if root_cause_data.get("primary_cause", "").lower().find("hijack") != -1:
                recommendations = [
                    "Investigate advertising AS and validate origin prefixes with RPKI/ROA.",
                    "Contact upstream providers to filter suspicious announcements."
                ]
            elif root_cause_data.get("primary_cause", "").lower().find("leak") != -1:
                recommendations = [
                    "Review BGP export policies and filter unintended announcements.",
                    "Coordinate with neighboring ASes to mitigate leak."
                ]
            elif root_cause_data.get("primary_cause", "").lower().find("traffic") != -1:
                recommendations = [
                    "Validate traffic baselines and investigate potential DDoS sources.",
                    "Apply traffic engineering or rate-limiting as needed."
                ]
            else:
                recommendations = ["No specific recommendations available"]
        recommendations_section = render_recommendations_section(recommendations)

        technical_details = _prepare_technical_details(reasoning_analysis)
        
        # Add reasoning trace to technical details if available
        if isinstance(reasoning_analysis, dict):
            reasoning_trace_list = reasoning_analysis.get("reasoning_trace", [])
            if reasoning_trace_list:
                technical_details["reasoning_trace"] = "\n".join(f"- {item}" for item in reasoning_trace_list)
            
            # Add confidence assessment
            confidence = reasoning_analysis.get("confidence_assessment", {})
            if confidence:
                technical_details["confidence_assessment"] = str(confidence)
        
        technical_section = render_technical_details_section(technical_details)

        # Render complete HTML report
        html_content = render_summary_html(
            target_as=target_as,
            time_range=time_range,
            detected_time_range=detected_range,
            primary_classification=primary_class,
            total_events=total_events,
            exec_summary=exec_summary,
            traffic_section=traffic_section,
            routing_section=routing_section,
            anomaly_section=anomaly_section,
            root_cause_section=root_cause_section,
            recommendations_section=recommendations_section,
            technical_section=technical_section,
            routing_analysis_data=routing_analysis,
            no_anomalies=no_anomalies
        )

        # Save HTML report
        html_path = save_html_report(target_as, time_range, html_content, output_dir)

        # Save JSON report
        json_path = save_json_report(reasoning_analysis, target_as, output_dir)

        result = {
            "success": True,
            "html_report_path": html_path,
            "json_report_path": json_path,
            "target_as": target_as,
            "analysis_timestamp": datetime.now().isoformat(),
            "report_sections": {
                "executive_summary": exec_summary,
                "traffic_analysis": bool(traffic_section),
                "routing_analysis": bool(routing_section),
                "anomaly_details": len(all_anomalies),
                "root_cause_analysis": bool(root_cause_section),
                "recommendations": len(recommendations),
                "technical_details": bool(technical_section)
            }
        }

        logger.info(f"Comprehensive report generated for AS{target_as}")
        return result

    except Exception as e:
        logger.error(f"Error generating comprehensive report: {e}")

        # Try fallback if available
        if fallback_report_func:
            try:
                logger.info("Attempting fallback report generation")
                return fallback_report_func(
                    routing_analysis, traffic_analysis, law_analysis,
                    reasoning_analysis, start_time, output_dir, org_name, asn
                )
            except Exception as fallback_e:
                logger.error(f"Fallback report generation also failed: {fallback_e}")

        return {
            "success": False,
            "error": str(e),
            "target_as": asn,
            "analysis_timestamp": datetime.now().isoformat()
        }


def generate_batch_html_report(batch_result: Dict[str, Any], start_time: str,
                              end_time: str, output_dir: Optional[str] = None) -> str:
    """
    Generate HTML report for batch AS analysis.

    Args:
        batch_result: Batch analysis results
        start_time: Analysis start time
        end_time: Analysis end time
        output_dir: Output directory

    Returns:
        Path to generated HTML report
    """
    try:
        from .report_templates import BATCH_ANALYSIS_HTML_TEMPLATE, AS_SECTION_TEMPLATE

        # Extract batch information
        analysis_period = f"{start_time} to {end_time}"
        total_as = batch_result.get("as_count", 0)
        anomalous_as_count = batch_result.get("anomaly_count", 0)
        results_by_as = batch_result.get("results_by_as", {})

        # Calculate summary statistics
        total_routing_anomalies = sum(
            len(result.get("routing_anomalies", []))
            for result in results_by_as.values()
        )
        total_traffic_anomalies = sum(
            len(result.get("traffic_anomalies", []))
            for result in results_by_as.values()
        )

        high_severity_as = sum(
            1 for result in results_by_as.values()
            if _assess_as_severity(result) == "high"
        )

        # Determine status indicators
        routing_status = "critical" if total_routing_anomalies > 10 else "warning" if total_routing_anomalies > 0 else "normal"
        traffic_status = "critical" if total_traffic_anomalies > 10 else "warning" if total_traffic_anomalies > 0 else "normal"
        severity_status = "critical" if high_severity_as > 3 else "warning" if high_severity_as > 0 else "normal"

        # Generate per-AS sections
        per_as_sections = []
        for asn, result in results_by_as.items():
            section_html = _generate_as_section_html(asn, result, AS_SECTION_TEMPLATE)
            per_as_sections.append(section_html)

        # Generate recommendations
        recommendations = _generate_batch_recommendations(
            total_routing_anomalies, total_traffic_anomalies, high_severity_as
        )

        # Render complete batch report
        html = BATCH_ANALYSIS_HTML_TEMPLATE
        html = html.replace("{{ANALYSIS_PERIOD}}", analysis_period)
        html = html.replace("{{TOTAL_AS}}", str(total_as))
        html = html.replace("{{ANOMALOUS_AS_COUNT}}", str(anomalous_as_count))
        html = html.replace("{{REPORT_TIMESTAMP}}", datetime.now().isoformat())
        html = html.replace("{{TOTAL_ROUTING_ANOMALIES}}", str(total_routing_anomalies))
        html = html.replace("{{TOTAL_TRAFFIC_ANOMALIES}}", str(total_traffic_anomalies))
        html = html.replace("{{HIGH_SEVERITY_AS}}", str(high_severity_as))
        html = html.replace("{{ROUTING_STATUS}}", routing_status.title())
        html = html.replace("{{TRAFFIC_STATUS}}", traffic_status.title())
        html = html.replace("{{SEVERITY_STATUS}}", severity_status.title())
        html = html.replace("{{PER_AS_SECTIONS}}", "\n".join(per_as_sections))
        html = html.replace("{{RECOMMENDATIONS}}", "\n".join(f"<li>{rec}</li>" for rec in recommendations))

        # Save report
        if output_dir is None:
            output_dir = Path(__file__).resolve().parent.parent / "results" / "html"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"batch_bgp_analysis_{timestamp}.html"
        file_path = output_dir / filename

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)

        logger.info(f"Batch HTML report saved to: {file_path}")
        return str(file_path)

    except Exception as e:
        logger.error(f"Error generating batch HTML report: {e}")
        return ""


def make_json_serializable(data: Any) -> Any:
    """
    Convert data to JSON-serializable format.

    Args:
        data: Data to make serializable

    Returns:
        JSON-serializable version of data
    """
    try:
        if isinstance(data, dict):
            return {key: make_json_serializable(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [make_json_serializable(item) for item in data]
        elif isinstance(data, (int, float, str, bool)) or data is None:
            return data
        elif hasattr(data, 'isoformat'):  # datetime objects
            return data.isoformat()
        elif hasattr(data, '__array__'):  # numpy arrays
            return data.tolist()
        else:
            return str(data)
    except Exception:
        return str(data)


# Helper functions

def _determine_primary_classification(reasoning_analysis: Dict[str, Any]) -> str:
    """Determine primary incident classification."""
    try:
        # Check for explicit classification in final_classification
        final_class = reasoning_analysis.get("final_classification", {})
        if isinstance(final_class, dict):
            integrated = final_class.get("integrated_findings", {})
            if "incident_type" in integrated:
                return integrated["incident_type"]
        
        # Check for explicit classification at top level
        if "incident_type" in reasoning_analysis:
            return reasoning_analysis["incident_type"]

        # Infer from analysis results
        if reasoning_analysis.get("hijack_detected"):
            return "Route Hijack"
        elif reasoning_analysis.get("leak_detected"):
            return "Route Leak"
        elif reasoning_analysis.get("traffic_anomaly_detected"):
            return "Traffic Anomaly"
        else:
            return "Normal Operation"
    except Exception:
        return "Unknown"


def _count_total_events(routing_analysis: Dict[str, Any], traffic_analysis: Dict[str, Any]) -> int:
    """Count total number of events across all analyses."""
    try:
        routing_events = len(routing_analysis.get("anomalies", []))
        traffic_events = len(traffic_analysis.get("anomalies", []))
        return routing_events + traffic_events
    except Exception:
        return 0


def _generate_executive_summary(reasoning_analysis: Dict[str, Any], primary_class: str, time_range: Optional[str] = None, detected_range: Optional[str] = None, routing_analysis: Optional[Dict[str, Any]] = None, traffic_analysis: Optional[Dict[str, Any]] = None) -> str:
    """Generate executive summary for the report including detected time range and key counts."""
    try:
        # Basic header sentence
        time_range_display = time_range or "Unknown"
        detected_display = detected_range or "Unknown"
        header = f"During the analysis period ({time_range_display}),"

        # Traffic anomalies summary
        anomalous_as_count = 0
        total_traffic_anomalies = 0
        if isinstance(traffic_analysis, dict):
            # If batch-style traffic_analysis, it may contain per-as results; otherwise use single AS fields
            if "results_by_as" in traffic_analysis:
                results = traffic_analysis.get("results_by_as", {})
                anomalous_as_count = sum(1 for r in results.values() if r.get("anomaly_count", 0) > 0)
                total_traffic_anomalies = sum(r.get("anomaly_count", 0) for r in results.values())
            else:
                anomalous_as_count = 1 if traffic_analysis.get("anomaly_count", 0) > 0 else 0
                total_traffic_anomalies = traffic_analysis.get("anomaly_count", 0)

        # Routing anomalies summary
        total_routing_alerts = 0
        if isinstance(routing_analysis, dict):
            # Sum known routing event lists
            for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "mitm_alerts", "route_leaks"]:
                items = routing_analysis.get(key, [])
                total_routing_alerts += len(items) if isinstance(items, list) else 0

        # Build summary sentences
        parts = []
        parts.append(header)
        parts.append(f"{anomalous_as_count} out of analyzed AS exhibited traffic anomalies ({total_traffic_anomalies} total anomaly points detected) during the detected anomaly time range ({detected_display}).")

        if total_routing_alerts > 0:
            parts.append(f"Routing security analysis detected {total_routing_alerts} routing alerts across the analyzed AS, including origin hijacks, path forgery (MITM), and route leaks.")
        else:
            parts.append("Routing security analysis did not detect significant routing alerts during the analysis period.")

        # Correlation sentence
        correlation = ""
        try:
            if anomalous_as_count > 0 and total_routing_alerts > 0:
                correlation = "Correlation Analysis: Some AS showed both traffic anomalies and routing security issues, suggesting that the traffic disruptions may be routing-related (e.g., hijacking or path manipulation)."
            elif anomalous_as_count > 0:
                correlation = "Correlation Analysis: Traffic anomalies were observed but without matching routing alerts; investigate other causes (DDoS, network issues)."
            elif total_routing_alerts > 0:
                correlation = "Correlation Analysis: Routing alerts were detected without clear traffic impact; these may represent routing incidents that did not affect traffic volume significantly."
            else:
                correlation = "Correlation Analysis: No significant correlation between traffic and routing alerts was observed."
        except Exception:
            correlation = ""

        parts.append(correlation)

        # Include any top-level key findings or confidence if present
        if isinstance(reasoning_analysis, dict):
            if "confidence_score" in reasoning_analysis:
                try:
                    conf = float(reasoning_analysis.get("confidence_score", 0.0))
                    parts.append(f"Analysis confidence: {conf:.1%}.")
                except Exception:
                    pass
            if "key_findings" in reasoning_analysis:
                findings = reasoning_analysis.get("key_findings") or []
                if findings:
                    parts.append("Key findings include: " + "; ".join(findings[:3]))

        return " ".join(p for p in parts if p)
    except Exception:
        return "Analysis completed. See detailed sections below for comprehensive findings."


def _get_anomalies(routing_analysis, traffic_analysis):
    """Collect all anomalies from routing and traffic analyses."""
    try:
        all_anomalies = []

        # Add routing anomalies
        # Extract structured routing anomalies from routing analysis results
        if routing_analysis:
            # Prefix hijacks and hijacking announcements
            for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
                items = routing_analysis.get(key, [])
                for it in items:
                    an = {}
                    an["timestamp"] = it.get("timestamp") or it.get("first_seen") or routing_analysis.get("analysis_timestamp")
                    an["type"] = "hijack"
                    an["subtype"] = key
                    an["severity"] = it.get("severity", "high") if isinstance(it, dict) else "high"
                    an["description"] = it.get("description", "Prefix hijack or suspicious origin change") if isinstance(it, dict) else str(it)
                    an["confidence"] = it.get("confidence", "medium") if isinstance(it, dict) else "medium"
                    an["source"] = "routing"
                    all_anomalies.append(an)

            # Route leaks
            leaks = routing_analysis.get("route_leaks", [])
            for leak in leaks:
                an = {}
                an["timestamp"] = leak.get("timestamp") or routing_analysis.get("analysis_timestamp")
                an["type"] = "route_leak"
                an["severity"] = leak.get("severity", "medium") if isinstance(leak, dict) else "medium"
                an["description"] = leak.get("description", "Route leak detected") if isinstance(leak, dict) else str(leak)
                an["confidence"] = leak.get("confidence", "medium") if isinstance(leak, dict) else "medium"
                an["source"] = "routing"
                all_anomalies.append(an)

            # Outage events
            outage = routing_analysis.get("outage_analysis", {})
            if outage and outage.get("is_outage_suspected"):
                an = {
                    "timestamp": outage.get("timestamp") or routing_analysis.get("analysis_timestamp"),
                    "type": "outage",
                    "severity": "high",
                    "description": outage.get("note", "Outage suspected based on BGP signals"),
                    "confidence": outage.get("confidence", "medium"),
                    "source": "routing"
                }
                all_anomalies.append(an)

        # Add traffic anomalies
        if traffic_analysis.get("anomalies"):
            for anomaly in traffic_analysis["anomalies"]:
                anomaly_copy = anomaly.copy()
                anomaly_copy["source"] = "traffic"
                all_anomalies.append(anomaly_copy)

        # Sort by timestamp if available
        all_anomalies.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return all_anomalies

    except Exception:
        return []


def _prepare_technical_details(reasoning_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare technical details for the report."""
    try:
        technical = {
            "analysis_method": reasoning_analysis.get("analysis_method", "Unknown"),
            "llm_model": reasoning_analysis.get("llm_model", "Unknown"),
            "processing_time": reasoning_analysis.get("elapsed_seconds", 0),
            "data_sources": reasoning_analysis.get("data_sources", []),
            "algorithm_versions": reasoning_analysis.get("algorithm_versions", {})
        }

        return technical

    except Exception:
        return {"error": "Failed to prepare technical details"}


def _generate_as_section_html(asn: str, result: Dict[str, Any], template: str) -> str:
    """Generate HTML section for individual AS in batch report."""
    try:
        routing_anomalies = len(result.get("routing_anomalies", []))
        traffic_anomalies = len(result.get("traffic_anomalies", []))
        total_events = routing_anomalies + traffic_anomalies

        # Determine status
        routing_status = "critical" if routing_anomalies > 5 else "warning" if routing_anomalies > 0 else "normal"
        traffic_status = "critical" if traffic_anomalies > 5 else "warning" if traffic_anomalies > 0 else "normal"
        events_status = "critical" if total_events > 10 else "warning" if total_events > 0 else "normal"

        # Generate key findings
        key_findings = []
        if routing_anomalies > 0:
            key_findings.append(f"{routing_anomalies} routing anomalies detected")
        if traffic_anomalies > 0:
            key_findings.append(f"{traffic_anomalies} traffic anomalies detected")
        if not key_findings:
            key_findings.append("No anomalies detected")

        html = template
        html = html.replace("{{ASN}}", str(asn))
        html = html.replace("{{AS_NAME}}", result.get("as_name", ""))
        html = html.replace("{{ROUTING_ANOMALIES}}", str(routing_anomalies))
        html = html.replace("{{TRAFFIC_ANOMALIES}}", str(traffic_anomalies))
        html = html.replace("{{TOTAL_EVENTS}}", str(total_events))
        html = html.replace("{{ROUTING_STATUS}}", routing_status.title())
        html = html.replace("{{TRAFFIC_STATUS}}", traffic_status.title())
        html = html.replace("{{EVENTS_STATUS}}", events_status.title())
        html = html.replace("{{TRAFFIC_CHART}}", "")  # Placeholder for future chart embedding
        html = html.replace("{{KEY_FINDINGS}}", "\n".join(f"<li>{finding}</li>" for finding in key_findings))

        return html

    except Exception as e:
        logger.error(f"Error generating AS section HTML: {e}")
        return f"<div>Error generating section for AS{asn}: {str(e)}</div>"


def _generate_batch_recommendations(routing_anomalies: int, traffic_anomalies: int, high_severity_as: int) -> List[str]:
    """Generate recommendations for batch analysis."""
    recommendations = []

    if routing_anomalies > 10 or high_severity_as > 2:
        recommendations.append("URGENT: Multiple ASes showing routing security issues - implement network-wide BGP security measures")

    if traffic_anomalies > 20:
        recommendations.append("Widespread traffic anomalies detected - investigate potential DDoS campaigns or network congestion")

    if routing_anomalies > 0:
        recommendations.append("Review BGP routing policies and filtering rules across affected ASes")

    if high_severity_as > 0:
        recommendations.append(f"Prioritize investigation of {high_severity_as} AS(es) with high-severity issues")

    recommendations.append("Implement continuous BGP monitoring and automated alerting")
    recommendations.append("Consider deploying RPKI and BGP Origin Validation")

    return recommendations


def _assess_as_severity(result: Dict[str, Any]) -> str:
    """Assess severity level for an individual AS."""
    try:
        routing_anomalies = len(result.get("routing_anomalies", []))
        traffic_anomalies = len(result.get("traffic_anomalies", []))

        total_anomalies = routing_anomalies + traffic_anomalies

        if total_anomalies > 15 or routing_anomalies > 8:
            return "high"
        elif total_anomalies > 5 or routing_anomalies > 2:
            return "medium"
        else:
            return "low"

    except Exception:
        return "unknown"
