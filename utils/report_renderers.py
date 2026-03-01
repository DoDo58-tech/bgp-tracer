"""
Report rendering functions for BGP security analysis.

This module contains functions for rendering different sections of
BGP security reports, including traffic analysis, routing analysis,
and anomaly details.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from .logger import logger
from .report_templates import (
    get_css_class_for_severity,
    get_css_class_for_confidence,
    get_status_indicator_class
)


def render_traffic_analysis_section(traffic_data: Dict[str, Any], chart_path: Optional[str] = None) -> str:
    """
    Render the traffic analysis section of the report.

    Args:
        traffic_data: Traffic analysis results
        chart_path: Path to traffic chart image

    Returns:
        HTML string for traffic analysis section
    """
    try:
        if not traffic_data or not traffic_data.get("success"):
            return "<p>No traffic analysis data available</p>"

        current_avg = traffic_data.get("current_avg", 0)
        historical_avg = traffic_data.get("historical_avg", 0)
        percent_change = traffic_data.get("percent_change", 0)
        anomaly_count = traffic_data.get("anomaly_count", 0)
        detected_start = traffic_data.get("detected_start")
        detected_end = traffic_data.get("detected_end")

        # Determine status indicators
        if abs(percent_change) > 50:
            traffic_status = "critical" if percent_change < -50 else "warning"
        elif abs(percent_change) > 25:
            traffic_status = "warning"
        else:
            traffic_status = "normal"

        change_status = "anomalous" if abs(percent_change) > 20 else "normal"
        anomaly_status = "critical" if anomaly_count > 10 else "warning" if anomaly_count > 5 else "normal"

        html_parts = []

        # Chart embedding if available
        if chart_path and os.path.exists(chart_path):
            try:
                import base64
                with open(chart_path, 'rb') as f:
                    chart_data = base64.b64encode(f.read()).decode('utf-8')
                # Inline image with responsive sizing so it fits inside the HTML card
                img_html = (
                    f'<div class="chart-container">'
                    f'<img src="data:image/png;base64,{chart_data}" alt="Traffic Analysis Chart" '
                    f'style="max-width:100%;height:auto;display:block;margin:0 auto;max-height:700px;" />'
                    f'</div>'
                )
                html_parts.append(img_html)
            except Exception as e:
                logger.warning(f"Failed to embed chart: {e}")
                html_parts.append('<p>Traffic chart could not be embedded</p>')
        else:
            # No chart: present a concise textual summary, and only show table if anomalies exist
            if anomaly_count and anomaly_count > 0:
                det_range = f"{detected_start} to {detected_end}" if detected_start and detected_end else "Detected time range not available"
                html_parts.append(f"<p><strong>Detected anomaly time range:</strong> {det_range}</p>")
                html_parts.append(f"<p><strong>Total anomaly points detected:</strong> {anomaly_count}</p>")
            else:
                html_parts.append("<p>No traffic chart available</p>")

        # Only include a compact metrics table when meaningful (chart present or anomalies detected)
        if (chart_path and os.path.exists(chart_path)) or (anomaly_count and anomaly_count > 0):
            html_parts.append(f"""
            <table class="data-table">
              <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
              <tr><td>Current Average Traffic</td><td>{current_avg:.4f}</td><td><span class="status-indicator {get_status_indicator_class(traffic_status)}"></span>{traffic_status.title()}</td></tr>
              <tr><td>Historical Average Traffic</td><td>{historical_avg:.4f}</td><td><span class="status-indicator status-normal"></span>Baseline</td></tr>
              <tr><td>Traffic Change</td><td>{percent_change:+.2f}%</td><td><span class="status-indicator {get_status_indicator_class(change_status)}"></span>{change_status.title()}</td></tr>
              <tr><td>Total Anomalies Detected</td><td>{anomaly_count}</td><td><span class="status-indicator {get_status_indicator_class(anomaly_status)}"></span>{anomaly_status.title()}</td></tr>
            </table>
            """)

        html = "\n".join(html_parts)

        return html

    except Exception as e:
        logger.error(f"Error rendering traffic analysis section: {e}")
        return f"<p>Error rendering traffic analysis: {str(e)}</p>"


def render_routing_analysis_section(routing_data: Dict[str, Any]) -> str:
    """
    Render the routing analysis section of the report.

    Args:
        routing_data: Routing analysis results

    Returns:
        HTML string for routing analysis section
    """
    try:
        if not routing_data:
            return "<p>No routing analysis data available</p>"

        # Build a concise summary table with available metrics
        summary_rows = []
        metrics = [
            ("Total Prefix Hijacks", routing_data.get("total_prefix_hijacks", 0)),
            ("Total MITM Alerts", routing_data.get("total_mitm_alerts", 0)),
            ("Route Leak Count", routing_data.get("leak_count", routing_data.get("route_leaks_count", 0))),
            ("Outage Suspected", "Yes" if routing_data.get("outage_suspected") else "No"),
            ("Outage Score", routing_data.get("outage_score", 0))
        ]
        for name, val in metrics:
            summary_rows.append(f"<tr><td>{name}</td><td>{val}</td></tr>")

        html = f"<table class='data-table'><tr><th>Metric</th><th>Value</th></tr>{''.join(summary_rows)}</table>"

        # Prepare aggregated alert groups for dropdown: hijacks, leaks, outages
        hijack_items = []
        leak_items = []
        outage_items = []

        # Collect hijack-related lists
        for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "mitm_alerts"]:
            items = routing_data.get(key, []) or []
            for it in items:
                hijack_items.append((key, it))

        # Route leaks
        for it in routing_data.get("route_leaks", []) or []:
            leak_items.append(it)

        # Outage analysis
        outage_analysis = routing_data.get("outage_analysis", {}) or {}
        if outage_analysis and outage_analysis.get("is_outage_suspected"):
            outage_items.append(outage_analysis)

        # Aggregation helper for hijacks/leaks: aggregate by prefix and origin AS where possible
        def aggregate_by_prefix(items_list):
            agg = {}
            for key, it in items_list:
                if isinstance(it, dict):
                    prefixes = it.get("affected_prefixes") or ([it.get("prefix")] if it.get("prefix") else [])
                    origin_as = it.get("asn") or it.get("origin_as") or "Unknown"
                    desc = it.get("description", "") or it.get("note", "")
                else:
                    prefixes = [str(it)]
                    origin_as = routing_data.get("asn", "Unknown")
                    desc = str(it)
                for pfx in prefixes:
                    k = (pfx, origin_as)
                    if k not in agg:
                        agg[k] = {"count": 0, "examples": [], "descriptions": set()}
                    agg[k]["count"] += 1
                    if len(agg[k]["examples"]) < 3:
                        agg[k]["examples"].append(desc or str(it))
                    if desc:
                        agg[k]["descriptions"].add(desc)
            return agg

        hijack_agg = aggregate_by_prefix(hijack_items)

        # Build dropdown using <details> for accessibility
        html += "<h4>Routing Alerts</h4>"
        html += "<details><summary>Show routing alerts (click to expand)</summary>"

        # Hijacks section
        html += f"<h5>Hijacks / MITM ({sum(v['count'] for v in hijack_agg.values())})</h5>"
        if hijack_agg:
            html += "<div style='background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;'>"
            for (pfx, asn), info in sorted(hijack_agg.items(), key=lambda x: x[1]["count"], reverse=True):
                samples = "; ".join(info["examples"][:2])  # Limit to first 2 examples
                html += f"<p><strong>Hijack Alert</strong> · Prefix: {pfx} · Origin AS: {asn} · Occurrences: {info['count']} · Details: {samples}"
                if len(info["examples"]) > 2:
                    html += f" (and {len(info['examples']) - 2} more)"
                html += "</p>"
            html += "</div>"
        else:
            html += "<p>No hijack or MITM alerts detected.</p>"

        # Route leaks section
        html += f"<h5>Route Leaks ({len(leak_items)})</h5>"
        if leak_items:
            html += "<div style='background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;'>"
            for leak in leak_items:
                if isinstance(leak, dict):
                    ts = leak.get("timestamp") or leak.get("first_seen") or routing_data.get("analysis_timestamp", "")
                    prefixes = ", ".join(leak.get("affected_prefixes", [])) if leak.get("affected_prefixes") else leak.get("prefix", "")
                    asn = leak.get("asn") or leak.get("origin_as") or ""
                    desc = leak.get("description", "")
                    prob = leak.get("leak_probability", "")
                    html += f"<p><strong>Route Leak</strong> · Timestamp: {ts} · Prefixes: {prefixes} · AS: {asn}"
                    if prob:
                        html += f" · Probability: {prob}"
                    if desc:
                        html += f" · Details: {desc}"
                    html += "</p>"
                else:
                    html += f"<p><strong>Route Leak</strong> · Details: {str(leak)}</p>"
            html += "</div>"
        else:
            html += "<p>No route leak alerts detected.</p>"

        # Outages section
        html += f"<h5>Outages ({len(outage_items)})</h5>"
        if outage_items:
            html += "<div style='background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;'>"
            for out in outage_items:
                # Extract detailed outage information
                outage_score = out.get("outage_score", 0)
                analysis_period = out.get("analysis_period", "")
                indicators = out.get("indicators", [])
                anomalies = out.get("anomalies", [])

                html += f"<p><strong>Route Outage</strong> · Score: {outage_score:.2f}/1.0"

                if analysis_period:
                    html += f" · Period: {analysis_period}"

                if indicators:
                    indicator_str = ", ".join(indicators)
                    html += f" · Indicators: {indicator_str}"

                # Add detailed anomaly information
                if anomalies:
                    anomaly_details = []
                    for anomaly in anomalies[:5]:  # Limit to 5 anomalies
                        feature = anomaly.get("feature", "unknown")
                        z_score = anomaly.get("z_score", 0)
                        value = anomaly.get("value", 0)
                        baseline = anomaly.get("baseline", 0)
                        anomaly_details.append(f"{feature}: {value:.2f} vs baseline={baseline:.2f}, z_score={z_score:.2f}")

                    if anomaly_details:
                        html += f" · Anomaly Details: {'; '.join(anomaly_details)}"

                # Group anomalies by feature for summary
                if anomalies:
                    feature_summary = {}
                    for anomaly in anomalies:
                        feature = anomaly.get("feature", "unknown")
                        if feature not in feature_summary:
                            feature_summary[feature] = {"count": 0, "max_z": 0}
                        feature_summary[feature]["count"] += 1
                        z_score = abs(anomaly.get("z_score", 0))
                        if z_score > feature_summary[feature]["max_z"]:
                            feature_summary[feature]["max_z"] = z_score

                    feature_list = ", ".join([f"{k}({v['count']} times, max_z={v['max_z']:.2f})" for k, v in feature_summary.items()])
                    html += f" · Anomaly Features: {feature_list}"

                html += "</p>"
            html += "</div>"
        else:
            html += "<p>No outage events recorded.</p>"

        html += "</details>"

        return html

    except Exception as e:
        logger.error(f"Error rendering routing analysis section: {e}")
        return f"<p>Error rendering routing analysis: {str(e)}</p>"


def render_anomaly_details_section(anomalies: List[Dict[str, Any]]) -> str:
    """
    Render the anomaly details section of the report.

    Args:
        anomalies: List of detected anomalies

    Returns:
        HTML string for anomaly details section
    """
    try:
        if not anomalies:
            return "<p>No anomalies detected</p>"

        anomaly_rows = []

        for anomaly in anomalies[:20]:  # Limit to first 20 anomalies
            timestamp = anomaly.get("timestamp", "Unknown")
            anomaly_type = anomaly.get("type", "unknown")
            severity = anomaly.get("severity", "low")
            description = anomaly.get("description", "No description available")
            confidence = anomaly.get("confidence", "low")

            anomaly_rows.append(f"""
            <tr class="{get_css_class_for_confidence(confidence)}">
              <td>{timestamp}</td>
              <td>{anomaly_type.replace('_', ' ').title()}</td>
              <td><span class="{get_css_class_for_severity(severity)}">{severity.title()}</span></td>
              <td>{description}</td>
              <td>{confidence.title()}</td>
            </tr>
            """)

        html = f"""
        <table class="data-table">
          <tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Description</th><th>Confidence</th></tr>
          {"".join(anomaly_rows)}
        </table>
        """

        if len(anomalies) > 20:
            html += f"<p>... and {len(anomalies) - 20} more anomalies</p>"

        return html

    except Exception as e:
        logger.error(f"Error rendering anomaly details section: {e}")
        return f"<p>Error rendering anomaly details: {str(e)}</p>"


def render_root_cause_analysis(root_cause_data: Dict[str, Any]) -> str:
    """
    Render the root cause analysis section.

    Args:
        root_cause_data: Root cause analysis results

    Returns:
        HTML string for root cause analysis section
    """
    try:
        if not root_cause_data:
            return "<p>No root cause analysis available</p>"

        html = "<div>"

        # Primary cause
        primary_cause = root_cause_data.get("primary_cause", "Unknown")
        confidence = root_cause_data.get("confidence", "low")

        html += f"""
        <h4>Primary Root Cause</h4>
        <p class="{get_css_class_for_confidence(confidence)}">
          <strong>{primary_cause}</strong> (Confidence: {confidence.title()})
        </p>
        """

        # Contributing factors
        factors = root_cause_data.get("contributing_factors", [])
        if factors:
            html += "<h4>Contributing Factors</h4><ul>"
            for factor in factors:
                html += f"<li>{factor}</li>"
            html += "</ul>"

        # Technical details
        technical_details = root_cause_data.get("technical_details", "")
        if technical_details:
            html += f"""
            <h4>Technical Details</h4>
            <div class="code-snippet">{technical_details}</div>
            """

        html += "</div>"
        return html

    except Exception as e:
        logger.error(f"Error rendering root cause analysis: {e}")
        return f"<p>Error rendering root cause analysis: {str(e)}</p>"


def render_recommendations_section(recommendations: List[str]) -> str:
    """
    Render the recommendations section.

    Args:
        recommendations: List of recommendations

    Returns:
        HTML string for recommendations section
    """
    try:
        if not recommendations:
            return "<p>No specific recommendations available</p>"

        html = "<ul>"
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        html += "</ul>"

        return html

    except Exception as e:
        logger.error(f"Error rendering recommendations: {e}")
        return f"<p>Error rendering recommendations: {str(e)}</p>"


def render_technical_details_section(technical_data: Dict[str, Any]) -> str:
    """
    Render the technical details section.

    Args:
        technical_data: Technical analysis details

    Returns:
        HTML string for technical details section
    """
    try:
        if not technical_data:
            return "<p>No technical details available</p>"

        html = "<div>"

        # Implementation / technical details (avoid duplicating top-level metadata)
        html += "<h4>Implementation Details</h4>"
        html += "<table class='data-table'>"

        # Only include keys that are truly technical
        keys_to_show = ["analysis_method", "llm_model", "processing_time", "data_sources", "algorithm_versions"]
        for key in keys_to_show:
            if key in technical_data:
                value = technical_data.get(key)
                html += f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>"

        html += "</table>"

        # Raw data (collapsible) - render JSON safely
        if "raw_data" in technical_data:
            try:
                raw_json = json.dumps(technical_data["raw_data"], indent=2, ensure_ascii=False)
            except Exception:
                raw_json = str(technical_data["raw_data"])

            html += f"""
            <h4>Raw Analysis Data</h4>
            <div class="expandable-section" onclick="toggleVisibility(this)">
              Click to show/hide raw analysis data
              <div class="expandable-content">
                <pre>{raw_json}</pre>
              </div>
            </div>
            """

        html += "</div>"
        return html

    except Exception as e:
        logger.error(f"Error rendering technical details: {e}")
        return f"<p>Error rendering technical details: {str(e)}</p>"


def render_summary_html(target_as: str, time_range: str, detected_time_range: str, primary_classification: str,
                       total_events: int, exec_summary: str, traffic_section: str,
                       routing_section: str, anomaly_section: str, root_cause_section: str,
                       recommendations_section: str, technical_section: str,
                       routing_analysis_data: Dict[str, Any] = None, no_anomalies: bool = False) -> str:
    """
    Render the complete HTML report by combining all sections.

    Args:
        target_as: Target AS number
        time_range: Analysis time range
        primary_classification: Primary incident classification
        total_events: Total number of events
        exec_summary: Executive summary text
        traffic_section: Traffic analysis HTML
        routing_section: Routing analysis HTML
        anomaly_section: Anomaly details HTML
        root_cause_section: Root cause analysis HTML
        recommendations_section: Recommendations HTML
        technical_section: Technical details HTML
        routing_analysis_data: Raw routing analysis data for summary stats

    Returns:
        Complete HTML report string
    """
    try:
        # If no anomalies detected, use simplified template but still embed traffic chart if available
        if no_anomalies:
            from .report_templates import NO_ANOMALIES_HTML_TEMPLATE

            html = NO_ANOMALIES_HTML_TEMPLATE
            html = html.replace("{{TARGET_AS}}", str(target_as))
            html = html.replace("{{TIME_RANGE}}", time_range)
            html = html.replace("{{EXEC_SUMMARY}}", exec_summary)

            # If a traffic_section was provided (may include an embedded chart), append it as a card
            try:
                if traffic_section and str(traffic_section).strip():
                    insert_block = (
                        "\n\n"
                        "    <div class=\"card\">\n"
                        "      <h2>Traffic Analysis</h2>\n"
                        f"      {traffic_section}\n"
                        "    </div>\n"
                    )
                    html = html.replace("</body>", insert_block + "</body>")
            except Exception as e:
                logger.warning(f"Failed to append traffic section to no-anomalies template: {e}")

            return html

        from .report_templates import BGP_SECURITY_HTML_TEMPLATE

        # Calculate routing summary stats
        routing_status = "No routing anomalies detected"
        hijack_origin_count = 0
        hijack_forge_count = 0
        hijack_origin_attacker_count = 0
        hijack_forge_attacker_count = 0
        leak_count = 0
        leak_success = "No"
        outage_score = "N/A"
        outage_status = "NORMAL"
        outage_color = "#1a9850"

        if routing_analysis_data:
            # Hijack counts
            hijack_origin_count = len(routing_analysis_data.get("origin_hijacked", []))
            hijack_forge_count = len(routing_analysis_data.get("forge_hijacked", []))
            hijack_origin_attacker_count = len(routing_analysis_data.get("origin_hijacking", []))
            hijack_forge_attacker_count = len(routing_analysis_data.get("forge_hijacking", []))

            # Leak counts
            leak_count = len(routing_analysis_data.get("route_leaks", []))
            leak_success = "Yes" if leak_count > 0 else "No"

            # Outage info
            outage_analysis = routing_analysis_data.get("outage_analysis", {})
            if outage_analysis.get("success"):
                outage_score_val = outage_analysis.get("outage_score", 0)
                outage_score = f"{outage_score_val:.2f}/1.0"
                if outage_analysis.get("is_outage_suspected"):
                    outage_status = "🚨 SUSPECTED"
                    outage_color = "#d73027"
                else:
                    outage_status = "✅ NORMAL"
                    outage_color = "#1a9850"

            # Overall routing status
            total_routing_anomalies = (hijack_origin_count + hijack_forge_count +
                                     hijack_origin_attacker_count + hijack_forge_attacker_count +
                                     leak_count + (1 if outage_analysis.get("is_outage_suspected") else 0))
            if total_routing_anomalies > 0:
                routing_status = f"Routing anomalies detected ({total_routing_anomalies} total)"
            else:
                routing_status = "No routing anomalies detected"

        # Replace template variables
        html = BGP_SECURITY_HTML_TEMPLATE
        html = html.replace("{{TARGET_AS}}", str(target_as))
        html = html.replace("{{TIME_RANGE}}", time_range)
        html = html.replace("{{DETECTED_TIME_RANGE}}", detected_time_range or "Unknown")
        html = html.replace("{{PRIMARY_CLASS}}", primary_classification)
        html = html.replace("{{TOTAL_EVENTS}}", str(total_events))
        html = html.replace("{{REPORT_TIMESTAMP}}", datetime.now().isoformat())
        html = html.replace("{{EXEC_SUMMARY}}", exec_summary)
        html = html.replace("{{TRAFFIC_ANALYSIS}}", traffic_section)
        html = html.replace("{{ROUTING_ANALYSIS}}", routing_section)
        html = html.replace("{{ANOMALY_DETAILS}}", anomaly_section)
        html = html.replace("{{ROOT_CAUSE_ANALYSIS}}", root_cause_section)
        html = html.replace("{{RECOMMENDATIONS}}", recommendations_section)
        html = html.replace("{{TECHNICAL_DETAILS}}", technical_section)

        # Routing summary stats
        html = html.replace("{{ROUTING_STATUS}}", routing_status)
        html = html.replace("{{HIJACK_ORIGIN_COUNT}}", str(hijack_origin_count))
        html = html.replace("{{HIJACK_FORGE_COUNT}}", str(hijack_forge_count))
        html = html.replace("{{HIJACK_ORIGIN_ATTACKER_COUNT}}", str(hijack_origin_attacker_count))
        html = html.replace("{{HIJACK_FORGE_ATTACKER_COUNT}}", str(hijack_forge_attacker_count))
        html = html.replace("{{LEAK_COUNT}}", str(leak_count))
        html = html.replace("{{LEAK_SUCCESS}}", leak_success)
        html = html.replace("{{OUTAGE_SCORE}}", outage_score)
        html = html.replace("{{OUTAGE_STATUS}}", outage_status)
        html = html.replace("{{OUTAGE_COLOR}}", outage_color)

        # Generate routing alerts dropdown
        routing_alerts_html = _build_routing_alerts_dropdown(routing_analysis_data or {})
        html = html.replace("{{ROUTING_ALERTS}}", routing_alerts_html)

        return html

    except Exception as e:
        logger.error(f"Error rendering summary HTML: {e}")
        return f"<html><body><h1>Report Generation Error</h1><p>{str(e)}</p></body></html>"


def _build_routing_alerts_dropdown(routing_data: Dict[str, Any]) -> str:
    """Build routing alerts dropdown aggregating hijack, leak, and outage alerts."""
    alerts = routing_data.get("aggregated_alerts") or []
    leak_events = routing_data.get("route_leaks", []) or []
    outage_analysis = routing_data.get("outage_analysis", {})

    all_alerts = []

    # Add hijack alerts
    for alert in alerts:
        prefix = str(alert.get("prefixes", alert.get("prefix", 'unknown')))
        a_type = str(alert.get("type", "unknown"))
        victim = str(alert.get("victim_as", "unknown"))
        hijackers = alert.get("hijackers", alert.get("hijacker_as"))
        if isinstance(hijackers, (list, set, tuple)):
            hijackers = ", ".join(str(h) for h in hijackers if h)
        hijackers = str(hijackers or "unknown")
        first_seen = str(alert.get("first_seen", "unknown"))
        last_seen = str(alert.get("last_seen", "unknown"))
        all_alerts.append(
            f"<li><strong>{a_type}</strong> · Prefix: {prefix} · Victim: {victim} · "
            f"Hijacker(s): {hijackers} · Window: {first_seen} → {last_seen} · Count: {alert.get('count', 1)}</li>"
        )

    # Add leak alerts (aggregated)
    if leak_events:
        # Group leaks by prefix for aggregation
        leak_by_prefix = {}
        for leak in leak_events:
            prefix = leak.get("prefix", "unknown")
            if prefix not in leak_by_prefix:
                leak_by_prefix[prefix] = {
                    "count": 0,
                    "min_prob": 1.0,
                    "first_seen": leak.get("timestamp", "unknown"),
                    "last_seen": leak.get("timestamp", "unknown"),
                    "as_paths": set()
                }
            leak_by_prefix[prefix]["count"] += 1
            prob = leak.get("leak_probability", 1.0)
            if prob < leak_by_prefix[prefix]["min_prob"]:
                leak_by_prefix[prefix]["min_prob"] = prob
            ts = leak.get("timestamp", "")
            if ts < leak_by_prefix[prefix]["first_seen"]:
                leak_by_prefix[prefix]["first_seen"] = ts
            if ts > leak_by_prefix[prefix]["last_seen"]:
                leak_by_prefix[prefix]["last_seen"] = ts
            as_path = leak.get("as-path", "")
            if as_path:
                leak_by_prefix[prefix]["as_paths"].add(as_path[:50])  # Truncate long paths

        for prefix, leak_info in leak_by_prefix.items():
            first_seen = str(leak_info["first_seen"])
            last_seen = str(leak_info["last_seen"])
            min_prob = f"{leak_info['min_prob']:.3f}"
            path_sample = ", ".join(list(leak_info["as_paths"])[:3])
            if len(leak_info["as_paths"]) > 3:
                path_sample += f" (and {len(leak_info['as_paths']) - 3} more)"
            all_alerts.append(
                f"<li><strong>Route Leak</strong> · Prefix: {prefix} · "
                f"Count: {leak_info['count']} · Min Probability: {min_prob} · "
                f"Window: {first_seen} → {last_seen} · "
                f"Sample AS_PATHs: {path_sample if path_sample else 'N/A'}</li>"
            )

    # Add outage alerts
    if outage_analysis.get("success") and outage_analysis.get("is_outage_suspected"):
        outage_score = outage_analysis.get("outage_score", 0)
        indicators = outage_analysis.get("indicators", [])
        anomalies = outage_analysis.get("anomalies", []) or []
        analysis_period = str(outage_analysis.get("analysis_period", "unknown"))

        # Group anomalies by feature
        feature_summary = {}
        for anomaly in anomalies:
            feature = anomaly.get("feature", "unknown")
            if feature not in feature_summary:
                feature_summary[feature] = {
                    "count": 0,
                    "max_z": 0
                }
            feature_summary[feature]["count"] += 1
            z_score = abs(anomaly.get("z_score", 0))
            if z_score > feature_summary[feature]["max_z"]:
                feature_summary[feature]["max_z"] = z_score

        feature_list = ", ".join([f"{k}({v['count']} times, max_z={v['max_z']:.2f})" for k, v in feature_summary.items()])
        indicator_list = ", ".join(indicators) if indicators else "None"

        all_alerts.append(
            f"<li><strong>Route Outage</strong> · Score: {outage_score:.2f}/1.0 · "
            f"Period: {analysis_period} · "
            f"Indicators: {indicator_list} · "
            f"Anomaly Features: {feature_list if feature_list else 'None'}</li>"
        )

    if not all_alerts:
        return "<p>No routing alerts detected for this AS.</p>"

    total_count = len(alerts) + len(leak_events) + (1 if (outage_analysis.get("success") and outage_analysis.get("is_outage_suspected")) else 0)
    return f"<details><summary>Show {total_count} routing alerts</summary><ul>{''.join(all_alerts)}</ul></details>"
