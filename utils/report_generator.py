"""HTML report generator for BGP security analysis"""

import os
import json
import base64
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from .helpers import parse_llm_json
from .logger import logger

# HTML template for report generation
HTML_TEMPLATE = """<html>
  <head>
    <meta charset="utf-8" />
    <title>BGP Security RCA Report</title>
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; font-size: 16px; }
      h2 { margin: 0.2em 0 0.4em 0; font-size: 24px; }
      h3 { margin: 0.8em 0 0.4em 0; font-size: 20px; }
      table { border-collapse: collapse; width: 100%; margin: 0.6em 0; }
      th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; }
      th { background: #fafafa; }
      code { background: #f6f8fa; padding: 2px 4px; border-radius: 4px; font-size: 14px; }
      ul { margin: 0.4em 0 0.4em 1.2em; }
      .chart-container { margin: 1em 0; text-align: center; }
      .traffic-chart { max-width: 100%; height: auto; border: 1px solid #ddd; }
      .data-table { font-size: 14px; margin: 0.5em 0; }
      .anomaly { color: #d73027; font-weight: bold; }
      .normal { color: #1a9850; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  </head>
  <body>
    <h2>BGP Security Root Cause Analysis Report</h2>
    <h3>Metadata</h3>
    <table>
      <tr><th>Target AS</th><td>{{TARGET_AS}}</td></tr>
      <tr><th>Time Range</th><td>{{TIME_RANGE}}</td></tr>
      <tr><th>Primary Classification</th><td>{{PRIMARY_CLASS}}</td></tr>
      <tr><th>Total Events</th><td>{{TOTAL_EVENTS}}</td></tr>
    </table>

    <h3>Executive Summary</h3>
    <p>{{EXEC_SUMMARY}}</p>

    <h3>Traffic Analysis</h3>
    <div class="chart-container">
      <canvas id="trafficChart" width="800" height="400"></canvas>
    </div>
    <table class="data-table">
      <thead><tr><th>Timestamp</th><th>Current Value</th><th>Historical Mean</th><th>Status</th><th>Z-Score</th></tr></thead>
      <tbody>{{TRAFFIC_DATA_ROWS}}</tbody>
    </table>
    
    <script>
    {{TRAFFIC_CHART_SCRIPT}}
    </script>

    <h3>Root Cause Analysis</h3>
    <p>{{RCA_TEXT}}</p>

    <h3>Observed AS_PATHs</h3>
    <ul>{{AS_PATH_ITEMS}}</ul>

    <h3>Organizations</h3>
    <table>
      <thead><tr><th>ASN</th><th>Organization</th><th>Country</th><th>Role</th></tr></thead>
      <tbody>{{ORG_ROWS}}</tbody>
    </table>

    <h3>Impact Assessment</h3>
    <p>{{IMPACT_ASSESSMENT}}</p>

    <h3>Recommendations</h3>
    <ul>{{RECOMMENDATIONS}}</ul>

    <h3>Confidence and Limitations</h3>
    <p>{{CONFIDENCE_TEXT}}</p>

  </body>
</html>"""

def save_html_report(asn: str, 
                    start_time: str, 
                    end_time: str,
                    analysis_result: Dict[str, Any],
                    model: str,
                    output_dir: Optional[Path] = None) -> Optional[str]:
    """Generate and save HTML report for BGP security analysis"""
    
    try:
        # Create output directory
        if output_dir is None:
            output_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "results"
        html_dir = output_dir / "html"
        html_dir.mkdir(exist_ok=True, parents=True)
        
        # Generate report filename
        report_file = html_dir / f"report_AS{asn}_{start_time.replace(' ', '-')}T{end_time.replace(' ', '-')}.html"
        
        # Get analysis results from chief expert
        chief_analysis = analysis_result.get("chief_expert_analysis", {})
        ar = {
            "target_as": chief_analysis.get("target_as", "unknown"),
            "time_range": chief_analysis.get("time_range", "unknown"),
            "analysis_timestamp": chief_analysis.get("analysis_timestamp", ""),
            "expert_analysis": chief_analysis.get("coordination_summary", "No analysis available"),
            "primary_classification": "BGP Security Analysis",
            "total_events": 0,  # Will be updated from reasoning trace
            "root_cause_analysis": "Detailed analysis available in coordination summary",
            "impact_assessment": "Risk assessment completed",
            "recommendations": "Recommendations provided in analysis",
            "confidence_level": "Analysis completed with multi-expert coordination"
        }
        
        # Extract event counts from reasoning trace
        reasoning_trace = analysis_result.get("reasoning_trace", [])
        routing_events = 0
        traffic_anomalies = 0
        
        for step in reasoning_trace:
            if step.get("tool_name") == "invoke_routing_expert":
                # Extract from observation
                obs = step.get("observation", "{}")
                if "origin_hijack_count" in obs:
                    try:
                        import json
                        obs_data = json.loads(obs)
                        if "raw_output" in obs_data:
                            raw_output = obs_data["raw_output"]
                            if "origin_hijack_count" in raw_output:
                                routing_events += int(raw_output.split("origin_hijack_count")[1].split(",")[0].strip(": '\""))
                    except:
                        pass
            elif step.get("tool_name") == "invoke_traffic_expert":
                # Extract anomaly count
                obs = step.get("observation", "{}")
                if "anomaly_count" in obs:
                    try:
                        import json
                        obs_data = json.loads(obs)
                        if "raw_output" in obs_data:
                            raw_output = obs_data["raw_output"]
                            if "anomaly_count" in raw_output:
                                traffic_anomalies = int(raw_output.split("anomaly_count")[1].split(",")[0].strip(": '\""))
                    except:
                        pass
        
        ar["total_events"] = routing_events + traffic_anomalies
        
        # Replace placeholders in template
        report_html = HTML_TEMPLATE.replace("{{TARGET_AS}}", f"AS{ar.get('target_as', 'unknown')}")
        report_html = report_html.replace("{{TIME_RANGE}}", ar.get("time_range", "unknown"))
        report_html = report_html.replace("{{PRIMARY_CLASS}}", ar.get("primary_classification", "Unknown"))
        report_html = report_html.replace("{{TOTAL_EVENTS}}", str(ar.get("total_events", 0)))
        report_html = report_html.replace("{{EXEC_SUMMARY}}", ar.get("expert_analysis", "No analysis available"))
        report_html = report_html.replace("{{RCA_TEXT}}", ar.get("root_cause_analysis", "No RCA available"))
        report_html = report_html.replace("{{IMPACT_ASSESSMENT}}", ar.get("impact_assessment", "No impact assessment available"))
        report_html = report_html.replace("{{RECOMMENDATIONS}}", ar.get("recommendations", "No recommendations available"))
        report_html = report_html.replace("{{CONFIDENCE_TEXT}}", ar.get("confidence_level", "No confidence assessment available"))
        
        # Add metadata
        report_html = report_html.replace("<head>", f"""<head>
    <meta name="generator" content="bgp_tracer agent" />
    <meta name="model" content="{model}" />
    <meta name="tokens" content="{analysis_result.get('token_count', 0)}" />
    <meta name="time-range" content="{ar.get('time_range', 'unknown')}" />
    <meta name="target-as" content="AS{ar.get('target_as', 'unknown')}" />
    <meta name="analysis-timestamp" content="{ar.get('analysis_timestamp', '')}" />""")
        
        # Save report
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_html)
            
        return str(report_file)
        
    except Exception as e:
        print(f"Failed to save HTML report: {e}")
        return None


def render_summary_html(
    summary_payload: Dict[str, Any],
    routing_analysis: Dict[str, Any],
    traffic_analysis: Dict[str, Any],
    law_analysis: Dict[str, Any],
    reasoning_analysis: Dict[str, Any],
    org_name: str,
    asn: str,
    start_time: str,
) -> str:
    """Render HTML template using structured summary data."""
    
    def safe_text(value: Any, default: str = "") -> str:
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            try:
                value = json.dumps(value, ensure_ascii=False)
            except Exception:
                value = str(value)
        return html.escape(str(value))
    
    def render_list(items: List[str]) -> str:
        """Render list items; return empty string if there is no content."""
        if not items:
            return ""
        return "".join(f"<li>{safe_text(item)}</li>" for item in items)
    
    def inline_chart() -> str:
        plot_path = (traffic_analysis or {}).get("plot_path")
        extended_time_range = None
        
        if not plot_path and reasoning_analysis:
            try:
                source = reasoning_analysis
                if isinstance(source, str):
                    source = json.loads(source)
                ev = (source or {}).get("evidence_summary", {})
                plot_path_candidate = (ev.get("traffic_data", {}) or {}).get("plot_path")
                if plot_path_candidate:
                    plot_path = plot_path_candidate
                # Extract extended time range from evidence summary (reasoning agent)
                extended_time_range = (ev or {}).get("extended_analysis_time_range")
            except Exception:
                plot_path = None
        
        # If traffic agent provided an explicit extended_analysis_period, prefer it
        if not extended_time_range and (traffic_analysis or {}).get("extended_analysis_period"):
            eap = traffic_analysis.get("extended_analysis_period") or {}
            start = eap.get("start_time") or eap.get("start")
            end = eap.get("end_time") or eap.get("end")
            if start and end:
                extended_time_range = {"start": start, "end": end}
        
        # If no plot path but we have extended time range, try to regenerate traffic chart with extended range
        if not plot_path and extended_time_range and reasoning_analysis:
            try:
                from tools.traffic_detector import CloudflareRadarAPI
                source = reasoning_analysis
                if isinstance(source, str):
                    source = json.loads(source)
                
                asn_from_reasoning = source.get("asn") or asn
                extended_start = extended_time_range.get("start")
                extended_end = extended_time_range.get("end")
                
                if asn_from_reasoning and extended_start and extended_end:
                    logger.info(f"Regenerating traffic chart for extended time range: {extended_start} to {extended_end}")
                    api = CloudflareRadarAPI()
                    traffic_result = api.detect_anomalies(
                        asn=asn_from_reasoning,
                        start_time=extended_start,
                        end_time=extended_end,
                        plot_result=True
                    )
                    if traffic_result.get("success") and traffic_result.get("plot_path"):
                        plot_path = traffic_result.get("plot_path")
                        logger.info(f"Successfully regenerated traffic chart: {plot_path}")
            except Exception as e:
                logger.warning(f"Failed to regenerate traffic chart with extended range: {e}")
        
        if plot_path and os.path.exists(plot_path):
            with open(plot_path, "rb") as img:
                b64 = base64.b64encode(img.read()).decode("utf-8")
            time_range_note = ""
            if extended_time_range:
                time_range_note = (
                    "<p style='font-size:12px;color:#666;margin-top:8px;'>"
                    f"Traffic window: start_time-1day to end_time+6h "
                    f"({safe_text(extended_time_range.get('start'))} "
                    f"~ {safe_text(extended_time_range.get('end'))})"
                    "</p>"
                )
            return f'<img src="data:image/png;base64,{b64}" alt="Traffic Analysis Chart" style="max-width:100%;height:auto;border:1px solid #ddd;border-radius:6px;" />{time_range_note}'
        if (traffic_analysis or {}).get("timestamps"):
            return "<p>Traffic chart not available in this run.</p>"
        return "<p>No traffic visualization.</p>"
    
    def routing_evidence_table() -> str:
        """Generate comprehensive routing evidence table with all three detection types"""
        routing_data = routing_analysis or {}
        
        # Build HTML with three sections: Hijack, Leak, Outage
        html_sections = []
        
        # ============ SECTION 1: HIJACK DETECTION ============
        hijack_events = []
        for bucket in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
            for event in routing_data.get(bucket, []) or []:
                hijack_events.append((bucket, event))
        
        if hijack_events:
            hijack_rows = []
            for bucket, event in hijack_events[:50]:
                ts = safe_text(event.get("timestamp") or event.get("first_seen") or "")
                prefix = safe_text(event.get("prefix") or event.get("parent_prefix") or "")
                hijacker = safe_text(event.get("hijacker_as") or event.get("most_suspicious_hijacker") or "unknown")
                victim = safe_text(event.get("victim_as") or event.get("expected_origin") or "unknown")
                detail_parts = []
                if event.get("fake_connection"):
                    detail_parts.append(f"Fake connection: {safe_text(event.get('fake_connection'))}")
                if event.get("as-path"):
                    detail_parts.append(f"AS_PATH: {safe_text(event.get('as-path'))}")
                if event.get("reason"):
                    detail_parts.append(safe_text(event.get("reason")))
                detail = "<br>".join(detail_parts) or "N/A"
                hijack_rows.append(
                    f"<tr><td>{safe_text(bucket)}</td><td>{ts}</td><td>{prefix}</td>"
                    f"<td>Hijacker: {hijacker}<br>Victim: {victim}</td><td>{detail}</td></tr>"
                )
            
            hijack_table = f"""
            <h4 style="color: #d73027; margin-top: 20px;">🚨 Hijack Detection ({len(hijack_events)} events)</h4>
        <table class="data-table">
            <thead><tr><th>Type</th><th>Timestamp</th><th>Prefix</th><th>Actors</th><th>Evidence</th></tr></thead>
                <tbody>{"".join(hijack_rows)}</tbody>
        </table>
            """
            html_sections.append(hijack_table)
        
        # ============ SECTION 2: LEAK DETECTION ============
        route_leaks = routing_data.get("route_leaks", []) or []
        if route_leaks:
            leak_rows = []
            for leak in route_leaks[:50]:
                ts = safe_text(leak.get("timestamp") or "")
                prefix = safe_text(leak.get("prefix") or "")
                origin_as = safe_text(leak.get("origin-as") or leak.get("origin_as") or "")
                as_path = safe_text(leak.get("as-path") or leak.get("as_path") or "")
                leak_prob = safe_text(f"{leak.get('leak_probability', 0):.2f}")
                detection_method = safe_text(leak.get("detection_method", "PathProb"))
                
                leak_rows.append(
                    f"<tr><td>{ts}</td><td>{prefix}</td><td>{origin_as}</td>"
                    f"<td>Probability: {leak_prob}<br>Method: {detection_method}</td>"
                    f"<td>{as_path}</td></tr>"
                )
            
            leak_table = f"""
            <h4 style="color: #fc8d59; margin-top: 20px;">⚠️ Route Leak Detection ({len(route_leaks)} events)</h4>
            <table class="data-table">
                <thead><tr><th>Timestamp</th><th>Prefix</th><th>Origin AS</th><th>Leak Info</th><th>AS_PATH</th></tr></thead>
                <tbody>{"".join(leak_rows)}</tbody>
            </table>
            """
            html_sections.append(leak_table)
        
        # ============ SECTION 3: OUTAGE DETECTION ============
        outage_analysis = routing_data.get("outage_analysis", {}) or {}
        if outage_analysis.get("success"):
            outage_score = outage_analysis.get("outage_score", 0)
            is_outage = outage_analysis.get("is_outage_suspected", False)
            indicators = outage_analysis.get("indicators", [])
            event_features = outage_analysis.get("event_features", {})
            baseline_features = outage_analysis.get("baseline_features", {})
            anomalies = outage_analysis.get("anomalies", []) or []
            
            # Color based on outage score
            score_color = "#d73027" if is_outage else "#1a9850"
            score_label = "🚨 OUTAGE SUSPECTED" if is_outage else "✅ No Outage"
            
            # Build indicator list
            indicator_items = "".join([f"<li>{safe_text(ind)}</li>" for ind in indicators])
            
            # Build feature comparison
            feature_rows = []
            for key in ["announcement_count", "withdrawal_count", "flapping_prefix_count", "unique_prefix_count"]:
                event_val = event_features.get(key, 0)
                baseline_val = baseline_features.get(key, 0)
                ratio = (event_val / baseline_val * 100) if baseline_val > 0 else 0
                feature_rows.append(
                    f"<tr><td>{safe_text(key)}</td><td>{event_val}</td><td>{baseline_val}</td><td>{ratio:.1f}%</td></tr>"
                )
            
            # Build anomaly analysis table
            anomaly_rows = []
            anomaly_summary = {}
            if anomalies:
                # Group anomalies by feature for summary
                for anomaly in anomalies:
                    feature = anomaly.get("feature", "unknown")
                    if feature not in anomaly_summary:
                        anomaly_summary[feature] = {
                            "count": 0,
                            "max_z_score": 0,
                            "anomaly_type": anomaly.get("anomaly_type", "unknown"),
                            "max_value": None,
                            "baseline_mean": None
                        }
                    anomaly_summary[feature]["count"] += 1
                    z_score = abs(anomaly.get("z_score", 0))
                    if z_score > anomaly_summary[feature]["max_z_score"]:
                        anomaly_summary[feature]["max_z_score"] = z_score
                        anomaly_summary[feature]["max_value"] = anomaly.get("value")
                        anomaly_summary[feature]["baseline_mean"] = anomaly.get("baseline_mean")
                
                # Show detailed anomalies (limit to first 20 for readability)
                for anomaly in anomalies[:20]:
                    timestamp = safe_text(anomaly.get("timestamp", ""))
                    feature = safe_text(anomaly.get("feature", "unknown"))
                    value = anomaly.get("value", anomaly.get("event_value", ""))
                    baseline_mean = anomaly.get("baseline_mean", "")
                    z_score = anomaly.get("z_score", 0)
                    anomaly_type = safe_text(anomaly.get("anomaly_type", "unknown"))
                    severity = safe_text(anomaly.get("severity", "unknown"))
                    
                    # Format z-score
                    z_display = f"{z_score:.2f}" if isinstance(z_score, (int, float)) else str(z_score)
                    value_display = f"{value:.2f}" if isinstance(value, (int, float)) else str(value)
                    mean_display = f"{baseline_mean:.2f}" if isinstance(baseline_mean, (int, float)) else str(baseline_mean)
                    
                    anomaly_rows.append(
                        f"<tr><td>{timestamp}</td><td>{feature}</td><td>{value_display}</td>"
                        f"<td>{mean_display}</td><td>{z_display}</td><td>{anomaly_type}</td><td>{severity}</td></tr>"
                    )
                
                if len(anomalies) > 20:
                    anomaly_rows.append(
                        f"<tr><td colspan='7' style='text-align: center; color: #666;'>"
                        f"... and {len(anomalies) - 20} more anomalies (total: {len(anomalies)})</td></tr>"
                    )
            
            # Build feature summary for clear explanation
            feature_summary_html = ""
            if anomaly_summary:
                summary_items = []
                for feature, summary in anomaly_summary.items():
                    feature_name = safe_text(feature)
                    count = summary["count"]
                    max_z = summary["max_z_score"]
                    max_val = summary.get("max_value", "N/A")
                    baseline = summary.get("baseline_mean", "N/A")
                    anomaly_type = safe_text(summary.get("anomaly_type", "unknown"))
                    
                    # Format values
                    max_val_display = f"{max_val:.2f}" if isinstance(max_val, (int, float)) else str(max_val)
                    baseline_display = f"{baseline:.2f}" if isinstance(baseline, (int, float)) else str(baseline)
                    
                    summary_items.append(
                        f"<li><strong>{feature_name}</strong>: "
                        f"Detected {count} anomalies, max Z-Score={max_z:.2f}. "
                        f"Anomaly value={max_val_display}, baseline mean={baseline_display}, anomaly type={anomaly_type}</li>"
                    )
                
                feature_summary_html = f"""
                <h5>Anomaly Feature Summary:</h5>
                <ul style="margin-left: 20px;">{"".join(summary_items)}</ul>
                """
            
            anomaly_table_html = ""
            if anomaly_rows:
                # Get anomaly time window from outage_analysis
                anomaly_time_window = safe_text(outage_analysis.get('anomaly_time_window', outage_analysis.get('analysis_period', 'unknown')))
                
                anomaly_table_html = f"""
                <h5>Feature Anomaly Analysis ({len(anomalies)} anomalies detected in period [{anomaly_time_window}]):</h5>
                {feature_summary_html}
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Feature</th>
                            <th>Event Value</th>
                            <th>Baseline Mean</th>
                            <th>Z-Score</th>
                            <th>Anomaly Type</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>{"".join(anomaly_rows)}</tbody>
                </table>
                """
            else:
                # No anomalies detected or anomalies list is empty
                anomaly_table_html = """
                <h5>Feature Anomaly Analysis:</h5>
                <p style="color: #1a9850;">✅ No significant feature anomalies detected in the time series analysis.</p>
                """
            
            # Get anomaly time window (should be the traffic anomaly period)
            anomaly_time_window = safe_text(outage_analysis.get('anomaly_time_window', outage_analysis.get('analysis_period', '')))
            baseline_period = safe_text(outage_analysis.get('baseline_period', 'N/A'))
            unique_features = outage_analysis.get('unique_features_with_anomalies', [])
            
            outage_table = f"""
            <h4 style="color: {score_color}; margin-top: 20px;">📊 Outage Detection</h4>
            <div style="background: #f0f0f0; padding: 12px; border-radius: 6px; margin-bottom: 12px;">
                <p><strong>Status:</strong> <span style="color: {score_color}; font-weight: bold;">{score_label}</span></p>
                <p><strong>Outage Score:</strong> {outage_score:.2f}/1.0</p>
                <p><strong>Score Calculation:</strong> The outage score is calculated based on multiple indicators: announcement drop (0.3 weight), withdrawal surge (0.25 weight), flapping spike (0.2 weight), prefix disappearance (0.15 weight), timeseries anomalies (0.2 weight), and message drop (0.1 weight). Scores are summed and capped at 1.0. A score ≥0.25 indicates suspected outage.</p>
                <p><strong>Anomaly Time Window:</strong> <span style="color: #d73027; font-weight: bold;">{anomaly_time_window}</span> (traffic anomaly period)</p>
                <p><strong>Baseline Period:</strong> {baseline_period}</p>
                <p><strong>Features with Anomalies:</strong> {', '.join([safe_text(f) for f in unique_features]) if unique_features else 'None'}</p>
            </div>
            
            <h5>Outage Indicators:</h5>
            <ul>{indicator_items if indicator_items else "<li>No indicators detected</li>"}</ul>
            
            <h5>Feature Comparison (Event vs Baseline):</h5>
            <table class="data-table">
                <thead><tr><th>Feature</th><th>Event Value</th><th>Baseline Value</th><th>Ratio %</th></tr></thead>
                <tbody>{"".join(feature_rows)}</tbody>
            </table>
            
            {anomaly_table_html}
            """
            html_sections.append(outage_table)
        
        # Build comprehensive summary section combining all three detection types
        summary_section = ""
        hijack_count = len(hijack_events) if hijack_events else 0
        leak_count = len(route_leaks) if route_leaks else 0
        outage_detected = outage_analysis.get("is_outage_suspected", False) if outage_analysis.get("success") else False
        
        if hijack_count > 0 or leak_count > 0 or outage_detected:
            summary_items = []
            if hijack_count > 0:
                summary_items.append(f"<li><strong>Hijack Detection</strong>: Found {hijack_count} hijack events</li>")
            if leak_count > 0:
                summary_items.append(f"<li><strong>Leak Detection</strong>: Found {leak_count} route leak events</li>")
            if outage_detected:
                outage_score = outage_analysis.get("outage_score", 0)
                summary_text = f"<li><strong>Outage Detection</strong>: Suspected outage (score={outage_score:.2f})"
                if anomaly_summary:
                    feature_list = ", ".join([f"{k}({v['count']} times)" for k, v in anomaly_summary.items()])
                    summary_text += f", anomaly features: {feature_list}</li>"
                else:
                    summary_text += "</li>"
                summary_items.append(summary_text)
            
            summary_section = f"""
            <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 12px; margin-bottom: 16px;">
                <h4 style="margin-top: 0;">📋 Routing Analysis Summary</h4>
                <ul style="margin-left: 20px;">{"".join(summary_items)}</ul>
            </div>
            """
        
        # Combine all sections
        if html_sections:
            return f"""
            <div style="border: 1px solid #ddd; border-radius: 8px; padding: 16px; background: #fafafa;">
                <h3>🔍 Routing Security Analysis - Detailed Evidence</h3>
                {summary_section}
                {"".join(html_sections)}
            </div>
            """
        else:
            return "<p>No routing anomalies recorded.</p>"
    
    def _build_executive_summary(exec_summary, traffic_section, routing_section, routing_analysis, traffic_analysis):
        """Build Executive Summary with clear anomaly detection and traffic-routing correlation"""
        summary_parts = []
        
        # Get traffic anomaly info
        traffic_anomaly_count = (traffic_analysis or {}).get("anomaly_count", 0)
        traffic_status = traffic_section.get("status", "")
        
        # Get routing anomaly info
        ra = routing_analysis or {}
        hij_victim = len(ra.get("origin_hijacked", []) or []) + len(ra.get("forge_hijacked", []) or [])
        hij_attacker = len(ra.get("origin_hijacking", []) or []) + len(ra.get("forge_hijacking", []) or [])
        leak_cnt = len(ra.get("route_leaks", []) or [])
        outage_analysis = ra.get("outage_analysis", {}) or {}
        outage_detected = outage_analysis.get("is_outage_suspected", False) if outage_analysis.get("success") else False
        outage_score = outage_analysis.get("outage_score", 0) if outage_analysis.get("success") else 0
        
        routing_anomaly_count = hij_victim + hij_attacker + leak_cnt + (1 if outage_detected else 0)
        
        # Build summary based on detected anomalies
        if traffic_anomaly_count > 0:
            summary_parts.append(f"<p><strong>Traffic Anomalies Detected:</strong> {traffic_anomaly_count} anomaly point(s) detected during the analysis period.</p>")
        else:
            summary_parts.append("<p><strong>Traffic Status:</strong> No significant traffic anomalies detected.</p>")
        
        if routing_anomaly_count > 0:
            routing_details = []
            if hij_victim > 0 or hij_attacker > 0:
                routing_details.append(f"{hij_victim + hij_attacker} hijack event(s)")
            if leak_cnt > 0:
                routing_details.append(f"{leak_cnt} route leak(s)")
            if outage_detected:
                routing_details.append(f"outage suspected (score={outage_score:.2f})")
            
            summary_parts.append(f"<p><strong>Routing Anomalies Detected:</strong> {', '.join(routing_details)}.</p>")
            
            # Correlation analysis
            if traffic_anomaly_count > 0 and routing_anomaly_count > 0:
                summary_parts.append("<p><strong>Correlation:</strong> Both traffic anomalies and routing security issues were detected. "
                                    "<strong>The traffic disruptions are likely routing-related</strong> (e.g., hijacking, route leaks, or path manipulation).</p>")
            elif traffic_anomaly_count > 0:
                summary_parts.append("<p><strong>Correlation:</strong> Traffic anomalies were detected, but no corresponding routing security issues were found. "
                                    "<strong>The traffic disruptions are likely not routing-related</strong> (e.g., application-layer issues, DDoS, or infrastructure failures).</p>")
        else:
            summary_parts.append("<p><strong>Routing Status:</strong> No routing anomalies detected.</p>")
            if traffic_anomaly_count > 0:
                summary_parts.append("<p><strong>Correlation:</strong> Traffic anomalies detected without routing issues. "
                                    "<strong>The disruptions are likely not routing-related</strong>.</p>")
        
        # Add LLM-generated overview if available
        llm_overview = exec_summary.get("overview")
        if llm_overview:
            summary_parts.insert(0, f"<p>{safe_text(llm_overview)}</p>")
        
        # Add key findings
        key_findings = exec_summary.get("key_findings", [])
        if key_findings:
            findings_html = render_list(key_findings)
            summary_parts.append(f"<h3>Key Findings</h3><ul>{findings_html}</ul>")
        
        return "".join(summary_parts) if summary_parts else "<p>No summary available.</p>"
    
    def _build_impact_assessment_card(business_impact_html, technical_impact_html, severity_html):
        """Build Impact Assessment card only if there's content"""
        if not (business_impact_html or technical_impact_html or severity_html):
            return ""
        return f"""
            <div class="card">
                <h2>Impact Assessment</h2>
                {business_impact_html}
                {technical_impact_html}
                {severity_html}
            </div>
        """
    
    summary_payload = summary_payload or {}
    exec_summary = summary_payload.get("executive_summary", {}) or {}
    traffic_section = summary_payload.get("traffic_analysis", {}) or {}
    routing_section = summary_payload.get("routing_analysis", {}) or {}
    root_cause = summary_payload.get("root_cause", {}) or {}
    impact = summary_payload.get("impact_assessment", {}) or {}
    recs = summary_payload.get("recommendations", {}) or {}
    technical = summary_payload.get("technical_details", {}) or {}

    # If LLM summary forgot to mention real anomalies, patch status fields using raw analysis.
    if not traffic_section.get("status"):
        anomaly_count = (traffic_analysis or {}).get("anomaly_count", 0)
        outage_anomaly_count = (traffic_analysis or {}).get("outage_period_anomaly_count", 0)
        if anomaly_count > 0:
            traffic_section["status"] = "Traffic anomalies detected"
        else:
            traffic_section["status"] = "No significant traffic anomalies"
        details = traffic_section.setdefault("details", [])
        details.append(
            f"Detector found {anomaly_count} anomalies in the extended window; "
            f"{outage_anomaly_count} fall inside the reported outage period."
        )

    if not routing_section.get("status"):
        ra = routing_analysis or {}
        hij_victim = len(ra.get("origin_hijacked", []) or []) + len(ra.get("forge_hijacked", []) or [])
        hij_attacker = len(ra.get("origin_hijacking", []) or []) + len(ra.get("forge_hijacking", []) or [])
        leak_cnt = len(ra.get("route_leaks", []) or [])
        outage_flag = ra.get("outage_suspected") or (ra.get("outage_analysis") or {}).get("is_outage_suspected")

        if hij_victim or hij_attacker or leak_cnt or outage_flag:
            routing_section["status"] = "Routing anomalies detected"
        else:
            routing_section["status"] = "No routing anomalies detected"

        alerts = routing_section.setdefault("alerts", [])
        if hij_victim or hij_attacker:
            alerts.append(
                f"Hijack detector reported {hij_victim} victim-side and {hij_attacker} attacker-side events."
            )
        if leak_cnt:
            alerts.append(f"Route leak detector reported {leak_cnt} suspicious leaked paths.")
        oa = ra.get("outage_analysis") or {}
        if oa.get("success"):
            alerts.append(
                f"Outage detector score={oa.get('outage_score', 0):.2f}, "
                f"indicators={', '.join(oa.get('indicators', [])) or 'none'}."
            )
    
    routing_table_html = routing_evidence_table()
    
    # Safely format outage score for the summary card (routing_analysis-level).
    # If not available, leave it empty instead of forcing 'N/A'.
    raw_outage_score = (routing_analysis or {}).get("outage_score")
    outage_score_card = ""
    if raw_outage_score is not None:
        try:
            outage_score_card = f"{float(raw_outage_score):.2f}/1.0"
        except Exception:
            outage_score_card = safe_text(raw_outage_score)

    # Pre-build optional section snippets so that missing LLM fields don't show 'N/A'.
    business_impact = impact.get("business_impact")
    technical_impact = impact.get("technical_impact")
    severity = impact.get("severity")
    business_impact_html = (
        f"<p><strong>Business Impact:</strong> {safe_text(business_impact)}</p>"
        if business_impact else ""
    )
    technical_impact_html = (
        f"<p><strong>Technical Impact:</strong> {safe_text(technical_impact)}</p>"
        if technical_impact else ""
    )
    severity_html = (
        f"<p><strong>Severity:</strong> {safe_text(severity)}</p>"
        if severity else ""
    )

    root_assessment = root_cause.get("assessment")
    root_assessment_html = safe_text(root_assessment) if root_assessment else ""
    root_evidence_html = render_list(root_cause.get("evidence") or [])

    rec_immediate_html = render_list(recs.get("immediate_actions") or [])
    rec_long_term_html = render_list(recs.get("long_term") or [])

    tech_conf = technical.get("confidence")
    tech_quality = technical.get("data_quality")
    tech_conf_html = (
        f"<p><strong>Confidence:</strong> {safe_text(tech_conf)}</p>"
        if tech_conf else ""
    )
    tech_quality_html = (
        f"<p><strong>Data Quality:</strong> {safe_text(tech_quality)}</p>"
        if tech_quality else ""
    )
    tech_limits_html = render_list(technical.get("limitations") or [])

    # Build optional section blocks so that if LLM didn't provide content, the
    # corresponding card can be omitted entirely instead of showing empty shells.
    root_block = ""
    if root_assessment_html or root_evidence_html:
        root_block = f"""
        <div class="card">
            <h2>Root Cause</h2>
            <p>{root_assessment_html}</p>
            {f"<ul>{root_evidence_html}</ul>" if root_evidence_html else ""}
        </div>
        """

    rec_block = ""
    if rec_immediate_html or rec_long_term_html:
        rec_block = f"""
        <div class="card">
            <h2>Recommendations</h2>
            <h3>Immediate</h3>
            {f"<ul>{rec_immediate_html}</ul>" if rec_immediate_html else ""}
            <h3>Long-term</h3>
            {f"<ul>{rec_long_term_html}</ul>" if rec_long_term_html else ""}
        </div>
        """

    tech_block = ""
    if tech_conf_html or tech_quality_html or tech_limits_html:
        tech_block = f"""
        <div class="card">
            <h2>Technical Details</h2>
            {tech_conf_html}
            {tech_quality_html}
            <h3>Limitations</h3>
            {f"<ul>{tech_limits_html}</ul>" if tech_limits_html else ""}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Fault Analysis Report - AS{safe_text(asn)}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f5f6f8; color: #1f2933; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 32px; }}
        .card {{ background: #fff; border-radius: 12px; box-shadow: 0 10px 25px rgba(15,23,42,.08); padding: 28px; margin-bottom: 24px; }}
        h1, h2 {{ margin-top: 0; }}
        .grid {{ display: grid; gap: 20px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }}
        ul {{ padding-left: 20px; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.82rem; background: #eef2ff; color: #4338ca; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Network Fault Analysis Report</h1>
            <p class="badge">AS{safe_text(asn)} · {safe_text(org_name or "Unknown Organization")}</p>
            <p><strong>Analysis Window:</strong> {safe_text(start_time)}</p>
        </div>
        <div class="grid">
            <div class="card">
                <h2>Executive Summary</h2>
                {_build_executive_summary(exec_summary, traffic_section, routing_section, routing_analysis, traffic_analysis)}
            </div>
            {_build_impact_assessment_card(business_impact_html, technical_impact_html, severity_html)}
        </div>
        <div class="card">
            <h2>Traffic Analysis</h2>
            <p><strong>Status:</strong> {safe_text(traffic_section.get("status"))}</p>
            <div style="text-align:center;margin:16px 0;">{inline_chart()}</div>
            <h3>Details</h3>
            <ul>{render_list(traffic_section.get("details"))}</ul>
            <h3>Insights</h3>
            <ul>{render_list(traffic_section.get("insights"))}</ul>
        </div>
        <div class="card">
            <h2>Routing Security Analysis</h2>
            <p><strong>Status:</strong> {safe_text(routing_section.get("status"))}</p>
            
            <!-- Detection Type Summary -->
            <div style="display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin: 20px 0;">
                <!-- Hijack Detection Summary -->
                <div style="background: #fff3cd; border-left: 4px solid #d73027; padding: 12px; border-radius: 4px;">
                    <h4 style="margin-top: 0; color: #d73027;">🚨 Hijack Detection</h4>
                    <p style="margin: 8px 0;"><strong>Origin Hijacked:</strong> {len(routing_analysis.get("origin_hijacked", []) or [])}</p>
                    <p style="margin: 8px 0;"><strong>Forge Hijacked:</strong> {len(routing_analysis.get("forge_hijacked", []) or [])}</p>
                    <p style="margin: 8px 0;"><strong>Origin Hijacking:</strong> {len(routing_analysis.get("origin_hijacking", []) or [])}</p>
                    <p style="margin: 8px 0;"><strong>Forge Hijacking:</strong> {len(routing_analysis.get("forge_hijacking", []) or [])}</p>
                </div>
                
                <!-- Route Leak Detection Summary -->
                <div style="background: #ffe8d6; border-left: 4px solid #fc8d59; padding: 12px; border-radius: 4px;">
                    <h4 style="margin-top: 0; color: #fc8d59;">⚠️ Route Leak Detection</h4>
                    <p style="margin: 8px 0;"><strong>Leaks Detected:</strong> {len(routing_analysis.get("route_leaks", []) or [])}</p>
                    <p style="margin: 8px 0;"><strong>Detection Success:</strong> {safe_text("Yes" if routing_analysis.get("leak_detection_success") else "No")}</p>
                    {f'<p style="margin: 8px 0; color: #d73027;"><strong>Error:</strong> {safe_text(routing_analysis.get("leak_detection_error"))}</p>' if routing_analysis.get("leak_detection_error") else ""}
                </div>
                
                <!-- Outage Detection Summary -->
                <div style="background: #e8f4f8; border-left: 4px solid #1a9850; padding: 12px; border-radius: 4px;">
                    <h4 style="margin-top: 0; color: #1a9850;">📊 Outage Detection</h4>
                    <p style="margin: 8px 0;"><strong>Outage Score:</strong> {outage_score_card}</p>
                    <p style="margin: 8px 0;"><strong>Status:</strong> <span style="color: {'#d73027' if routing_analysis.get('outage_suspected') else '#1a9850'}; font-weight: bold;">{'🚨 SUSPECTED' if routing_analysis.get('outage_suspected') else '✅ NORMAL'}</span></p>
                </div>
            </div>
            
            <h3>Alerts</h3>
            <ul>{render_list(routing_section.get("alerts"))}</ul>
            <h3>Notable Prefixes</h3>
            <ul>{render_list(routing_section.get("notable_prefixes"))}</ul>
            <h3>Detailed Evidence</h3>
            {routing_table_html}
        </div>
        <div class="card">
            <h2>Root Cause</h2>
            <p>{root_assessment_html}</p>
            {f"<ul>{root_evidence_html}</ul>" if root_evidence_html else ""}
        </div>
        {root_block}
        {rec_block}
        {tech_block}
    </div>
</body>
</html>"""


BATCH_HTML_TEMPLATE = """<html>
  <head>
    <meta charset="utf-8" />
    <title>Batch BGP Security Analysis Report</title>
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; font-size: 16px; }
      h2 { margin: 0.2em 0 0.4em 0; font-size: 24px; }
      h3 { margin: 0.8em 0 0.4em 0; font-size: 20px; }
      table { border-collapse: collapse; width: 100%; margin: 0.6em 0; }
      th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
      th { background: #fafafa; font-weight: bold; }
      tr:nth-child(even) { background: #f9f9f9; }
      .anomaly { color: #d73027; font-weight: bold; }
      .normal { color: #1a9850; }
      .summary-box { background: #f6f8fa; padding: 16px; border-radius: 8px; margin: 16px 0; }
      .executive-summary { background: #fff3cd; padding: 20px; border-left: 5px solid #ffc107; border-radius: 8px; margin: 20px 0; }
      .as-section { margin: 24px 0; padding: 16px; border: 1px solid #ddd; border-radius: 8px; }
      .traffic-grid { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }
      .traffic-thumb { flex: 1 1 240px; max-width: 260px; border: 1px solid #ddd; border-radius: 8px; padding: 8px; background: #fff; box-shadow: 0 4px 10px rgba(0,0,0,0.04); }
      .traffic-thumb img { width: 100%; height: auto; border-radius: 4px; }
      .traffic-thumb-title { font-weight: 600; margin-bottom: 6px; font-size: 14px; text-align: center; }
      details { margin: 10px 0; background: #fafafa; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px 14px; }
      details summary { cursor: pointer; font-weight: 600; }
    </style>
  </head>
  <body>
    <h2>Batch BGP Security Analysis Report</h2>
    
    <div class="summary-box">
      <h3>Summary</h3>
      <table>
        <tr><th>Time Range</th><td>{{TIME_RANGE}}</td></tr>
        <tr><th>Total AS Analyzed</th><td>{{TOTAL_AS_COUNT}}</td></tr>
        <tr><th>AS with Anomalies</th><td>{{ANOMALY_AS_COUNT}}</td></tr>
        <tr><th>Analysis Timestamp</th><td>{{ANALYSIS_TIMESTAMP}}</td></tr>
      </table>
    </div>

    <div class="executive-summary">
      <h3>Executive Summary</h3>
      {{EXECUTIVE_SUMMARY}}
    </div>

    <h3>AS Analysis Results</h3>
    {{AS_RESULTS_TABLE}}

    <h3>Traffic Visualization Gallery</h3>
    <p><em>Traffic charts show baseline mean (orange dashed line), baseline ±3σ range (light blue shaded area), and current traffic (blue line). Red dots indicate detected anomalies. Analysis window: {{TIME_RANGE}} (extended to start_time-1day ~ end_time+6h for detection).</em></p>
    {{TRAFFIC_GALLERY}}

    <h3>Routing Security Analysis</h3>
    {{ROUTING_SECTION}}

    <h3>Detailed Results by AS</h3>
    {{AS_DETAILS}}
  </body>
</html>"""


def generate_batch_html_report(
    batch_result: Dict[str, Any],
    start_time: str,
    end_time: str,
    output_dir: Optional[Path] = None
) -> Optional[str]:
    """Generate and save batch HTML report for multiple AS analysis"""
    
    try:
        # Create output directory
        if output_dir is None:
            output_dir = Path(__file__).parent.parent / "results"
        html_dir = output_dir / "html"
        html_dir.mkdir(exist_ok=True, parents=True)
        
        # Generate report filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = html_dir / f"comprehensive_analysis_batch_{timestamp}.html"
        
        # Extract data from batch result
        payload = batch_result.get("batch_result", batch_result) or {}
        traffic_batch = payload.get("traffic_batch_result", {})
        routing_batch = payload.get("routing_batch_result", {})
        reasoning_results = payload.get("reasoning_results", {})
        anomaly_as_list = payload.get("anomaly_as_list", [])
        traffic_results_by_as = (traffic_batch or {}).get("results_by_as", {})
        routing_results_by_as = (routing_batch or {}).get("results_by_as", {})
        
        as_list = sorted(
            set(traffic_results_by_as.keys()) | set(routing_results_by_as.keys())
        )
        if not as_list:
            as_list = payload.get("as_list") or []
        total_as_count = traffic_batch.get("as_count") or len(as_list)
        if not total_as_count:
            total_as_count = len(as_list)
        
        anomaly_count = len(anomaly_as_list)
        
        # Generate traffic gallery thumbnails
        traffic_gallery_items = []
        for asn in as_list:
            plot_path = (traffic_results_by_as.get(asn, {}) or {}).get("plot_path")
            if plot_path and os.path.exists(plot_path):
                try:
                    with open(plot_path, "rb") as img:
                        encoded = base64.b64encode(img.read()).decode("utf-8")
                    traffic_gallery_items.append(
                        f'<div class="traffic-thumb"><div class="traffic-thumb-title">AS{asn}</div>'
                        f'<img src="data:image/png;base64,{encoded}" alt="Traffic chart for AS{asn}"></div>'
                    )
                except Exception:
                    continue
        traffic_gallery_html = (
            '<p>No traffic charts available for this batch.</p>'
            if not traffic_gallery_items else f'<div class="traffic-grid">{"".join(traffic_gallery_items)}</div>'
        )
        
        def build_reasoning_summary(reasoning_result: Dict[str, Any], for_table: bool = False) -> str:
            """Build reasoning summary, optionally as plain text for table display"""
            if not reasoning_result:
                return "No reasoning analysis available." if for_table else "<p>No reasoning analysis available.</p>"
            
            parts = []
            
            # Format final classification
            final_class = reasoning_result.get("final_classification")
            if final_class:
                if isinstance(final_class, dict):
                    class_items = "; ".join(f"{k}: {v}" for k, v in final_class.items() if v)
                    class_text = f"Classification: {class_items}" if class_items else "Classification: Unknown"
                else:
                    class_text = f"Classification: {final_class}"
                if for_table:
                    parts.append(class_text)
                else:
                    parts.append(f"<strong>Classification:</strong> {html.escape(str(final_class) if not isinstance(final_class, dict) else class_items)}")
            
            # Format confidence assessment
            confidence = reasoning_result.get("confidence_assessment")
            if confidence:
                if isinstance(confidence, dict):
                    # Extract key information from confidence dict
                    overall = confidence.get("overall", confidence.get("score"))
                    score = confidence.get("score")
                    details = confidence.get("details", "")
                    if overall:
                        conf_text = f"Confidence: {overall}"
                        if score is not None:
                            conf_text += f" (score: {score:.2f})"
                        if details and not for_table:
                            conf_text += f" - {details}"
                    else:
                        conf_text = f"Confidence: {html.escape(str(confidence))}"
                else:
                    conf_text = f"Confidence: {confidence}"
                
                if for_table:
                    parts.append(conf_text)
                else:
                    parts.append(f"<strong>Confidence:</strong> {html.escape(conf_text.replace('Confidence: ', ''))}")
            
            # Format recommendations
            recommendations = reasoning_result.get("recommendations")
            if recommendations:
                if isinstance(recommendations, dict):
                    rec_items = "; ".join(f"{k}: {v}" for k, v in recommendations.items() if v)
                    rec_text = f"Recommendations: {rec_items}" if rec_items else "Recommendations: None"
                else:
                    rec_text = f"Recommendations: {recommendations}"
                
                if for_table:
                    parts.append(rec_text)
                else:
                    parts.append(f"<strong>Recommendations:</strong> {html.escape(rec_text.replace('Recommendations: ', ''))}")
            
            if not parts:
                return "No reasoning analysis available." if for_table else "<p>No reasoning analysis available.</p>"
            
            if for_table:
                return " | ".join(parts)
            else:
                return "<p>" + "<br>".join(parts) + "</p>"

        def build_alert_dropdown(routing_data: Dict[str, Any]) -> str:
            alerts = routing_data.get("aggregated_alerts") or []
            leak_events = routing_data.get("route_leaks", []) or []
            outage_analysis = routing_data.get("outage_analysis", {})
            
            all_alerts = []
            
            # Add hijack alerts
            for alert in alerts:
                prefix = html.escape(str(alert.get("prefixes", alert.get("prefix", 'unknown'))))
                a_type = html.escape(str(alert.get("type", "unknown")))
                victim = html.escape(str(alert.get("victim_as", "unknown")))
                hijackers = alert.get("hijackers", alert.get("hijacker_as"))
                if isinstance(hijackers, (list, set, tuple)):
                    hijackers = ", ".join(str(h) for h in hijackers if h)
                hijackers = html.escape(str(hijackers or "unknown"))
                first_seen = html.escape(str(alert.get("first_seen", "unknown")))
                last_seen = html.escape(str(alert.get("last_seen", "unknown")))
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
                    prefix_escaped = html.escape(str(prefix))
                    first_seen = html.escape(str(leak_info["first_seen"]))
                    last_seen = html.escape(str(leak_info["last_seen"]))
                    min_prob = f"{leak_info['min_prob']:.3f}"
                    path_sample = ", ".join(list(leak_info["as_paths"])[:3])
                    if len(leak_info["as_paths"]) > 3:
                        path_sample += f" (and {len(leak_info['as_paths']) - 3} more)"
                    all_alerts.append(
                        f"<li><strong>Route Leak</strong> · Prefix: {prefix_escaped} · "
                        f"Count: {leak_info['count']} · Min Probability: {min_prob} · "
                        f"Window: {first_seen} → {last_seen} · "
                        f"Sample AS_PATHs: {html.escape(path_sample) if path_sample else 'N/A'}</li>"
                    )
            
            # Add outage alerts
            if outage_analysis.get("success") and outage_analysis.get("is_outage_suspected"):
                outage_score = outage_analysis.get("outage_score", 0)
                indicators = outage_analysis.get("indicators", [])
                anomalies = outage_analysis.get("anomalies", []) or []
                analysis_period = html.escape(str(outage_analysis.get("analysis_period", "unknown")))
                
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
                    f"Indicators: {html.escape(indicator_list)} · "
                    f"Anomaly Features: {html.escape(feature_list) if feature_list else 'None'}</li>"
                )
            
            if not all_alerts:
                return "<p>No routing alerts detected for this AS.</p>"
            
            total_count = len(alerts) + len(leak_events) + (1 if (outage_analysis.get("success") and outage_analysis.get("is_outage_suspected")) else 0)
            return f"<details><summary>Show {total_count} routing alerts</summary><ul>{''.join(all_alerts)}</ul></details>"

        def build_traffic_insights(traffic_data: Dict[str, Any]) -> str:
            if not traffic_data:
                return "<p>No traffic data collected.</p>"
            insights = []
            percent_change = traffic_data.get("percent_change")
            if percent_change is not None:
                insights.append(f"Avg traffic change: {percent_change:.2f}% vs baseline.")
            anomaly_count = traffic_data.get("anomaly_count", 0)
            insights.append(f"Detected anomalies: {anomaly_count}.")
            anomalies = traffic_data.get("anomalies", []) or []
            if anomalies:
                sample = []
                for anomaly in anomalies[:3]:
                    ts = html.escape(str(anomaly.get("timestamp", "unknown")))
                    z_score = anomaly.get("z_score")
                    if isinstance(z_score, (int, float)):
                        z_display = f"{z_score:.2f}"
                    else:
                        z_display = str(z_score)
                    sample.append(f"<li>{ts} · z-score={html.escape(z_display)}</li>")
                insights.append("<strong>Sample anomalies:</strong><ul>" + "".join(sample) + "</ul>")
            return "<p>" + " ".join(insights) + "</p>"

        def build_routing_section(routing_by_as: Dict[str, Any]) -> str:
            if not routing_by_as:
                return "<p>No routing analysis results available for this batch.</p>"
            totals = {
                "origin_hijacked": sum(len(v.get("origin_hijacked", [])) for v in routing_by_as.values()),
                "forge_hijacked": sum(len(v.get("forge_hijacked", [])) for v in routing_by_as.values()),
                "origin_hijacking": sum(len(v.get("origin_hijacking", [])) for v in routing_by_as.values()),
                "forge_hijacking": sum(len(v.get("forge_hijacking", [])) for v in routing_by_as.values()),
                "route_leaks": sum(len(v.get("route_leaks", [])) for v in routing_by_as.values()),
                "outage_suspected": sum(1 for v in routing_by_as.values() if (v.get("outage_analysis", {}).get("success") and v.get("outage_analysis", {}).get("is_outage_suspected"))),
            }
            summary_table = f"""
            <table>
              <tr><th>Origin Hijacks (Victim)</th><td>{totals['origin_hijacked']}</td></tr>
              <tr><th>Forge Hijacks (Victim)</th><td>{totals['forge_hijacked']}</td></tr>
              <tr><th>Origin Hijacking (Attacker)</th><td>{totals['origin_hijacking']}</td></tr>
              <tr><th>Forge Hijacking (Attacker)</th><td>{totals['forge_hijacking']}</td></tr>
              <tr><th>Route Leak Events</th><td>{totals['route_leaks']}</td></tr>
              <tr><th>Route Outage Suspected</th><td>{totals['outage_suspected']} AS</td></tr>
            </table>
            """
            per_as_details = []
            for asn, data in routing_by_as.items():
                alert_dropdown = build_alert_dropdown(data)
                per_as_details.append(
                    f"<details><summary>AS{asn}: {len(data.get('aggregated_alerts', []))} aggregated alerts</summary>"
                    f"{alert_dropdown}</details>"
                )
            return summary_table + "".join(per_as_details)
        
        # Generate AS results table
        table_rows = []
        table_rows.append("<table><thead><tr><th>AS Number</th><th>Status</th><th>Traffic Anomalies</th><th>Hijack Alerts</th><th>Leak Events</th><th>Outage Events</th><th>Summary</th></tr></thead><tbody>")
        
        for asn in as_list:
            is_anomaly = asn in anomaly_as_list if anomaly_count else False
            status = '<span class="anomaly">Anomaly Detected</span>' if is_anomaly else '<span class="normal">Normal</span>'
            
            # Get traffic data
            traffic_data = traffic_results_by_as.get(asn, {})
            traffic_anomalies = traffic_data.get("anomaly_count", 0)
            
            # Get routing data
            routing_data = routing_results_by_as.get(asn, {})
            hijack_alerts = 0
            leak_events = 0
            outage_events = 0
            if routing_data:
                hijack_alerts = (
                    len(routing_data.get("origin_hijacked", [])) +
                    len(routing_data.get("forge_hijacked", [])) +
                    len(routing_data.get("origin_hijacking", [])) +
                    len(routing_data.get("forge_hijacking", []))
                )
                # Count leak events
                leak_events = len(routing_data.get("route_leaks", []))
                # Count outage events (if outage is suspected)
                outage_analysis = routing_data.get("outage_analysis", {})
                if outage_analysis.get("success") and outage_analysis.get("is_outage_suspected"):
                    outage_events = 1  # Outage is a binary event, but we can count anomaly features
                    # Count anomaly features as outage indicators
                    anomalies = outage_analysis.get("anomalies", [])
                    if anomalies:
                        outage_events = len(anomalies)  # Use anomaly count as outage event count
            
            # Get reasoning summary (plain text for table)
            reasoning_result = reasoning_results.get(asn, {})
            summary_preview = build_reasoning_summary(reasoning_result, for_table=True)
            # Truncate if too long
            if len(summary_preview) > 200:
                summary_preview = summary_preview[:197] + "..."
            summary_preview = html.escape(summary_preview)
            
            table_rows.append(f"<tr><td>AS{asn}</td><td>{status}</td><td>{traffic_anomalies}</td><td>{hijack_alerts}</td><td>{leak_events}</td><td>{outage_events}</td><td>{summary_preview}</td></tr>")
        
        table_rows.append("</tbody></table>")
        as_results_table = "\n".join(table_rows)
        
        # Generate detailed AS sections
        as_details = []
        detail_as_list = as_list or anomaly_as_list
        for asn in detail_as_list:
            traffic_data = traffic_results_by_as.get(asn, {})
            routing_data = routing_results_by_as.get(asn, {})
            reasoning_result = reasoning_results.get(asn)
            reasoning_html = build_reasoning_summary(reasoning_result)
            alert_dropdown = build_alert_dropdown(routing_data)
            traffic_insights = build_traffic_insights(traffic_data)
            
            # Get leak and outage counts
            leak_count = len(routing_data.get('route_leaks', []))
            outage_analysis = routing_data.get('outage_analysis', {})
            outage_suspected = "Yes" if (outage_analysis.get("success") and outage_analysis.get("is_outage_suspected")) else "No"
            outage_score = outage_analysis.get("outage_score", 0) if outage_analysis.get("success") else 0
            
            detail_html = f"""
            <div class="as-section">
              <h4>AS{asn} - Detailed Analysis</h4>
              <table>
                <tr><th>Traffic Anomalies</th><td>{traffic_data.get('anomaly_count', 0)}</td></tr>
                <tr><th>Origin Hijacks (Victim)</th><td>{len(routing_data.get('origin_hijacked', []))}</td></tr>
                <tr><th>Forge Hijacks (Victim)</th><td>{len(routing_data.get('forge_hijacked', []))}</td></tr>
                <tr><th>Origin Hijacking (Attacker)</th><td>{len(routing_data.get('origin_hijacking', []))}</td></tr>
                <tr><th>Forge Hijacking (Attacker)</th><td>{len(routing_data.get('forge_hijacking', []))}</td></tr>
                <tr><th>Route Leak Events</th><td>{leak_count}</td></tr>
                <tr><th>Route Outage Suspected</th><td>{outage_suspected} {f'(Score: {outage_score:.2f})' if outage_score > 0 else ''}</td></tr>
              </table>
              <h5>Reasoning Analysis</h5>
              {reasoning_html}
              <h5>Routing Alerts</h5>
              {alert_dropdown}
              <h5>Traffic Insights</h5>
              {traffic_insights}
            </div>
            """
            as_details.append(detail_html)
        
        as_details_html = "\n".join(as_details) if as_details else "<p>No detailed analysis available.</p>"
        routing_section_html = build_routing_section(routing_results_by_as)
        
        # Build Executive Summary
        def build_executive_summary() -> str:
            total_traffic_anomalies = sum(
                (traffic_results_by_as.get(asn, {}) or {}).get("anomaly_count", 0)
                for asn in as_list
            )
            total_routing_alerts = sum(
                len((routing_results_by_as.get(asn, {}) or {}).get("origin_hijacked", [])) +
                len((routing_results_by_as.get(asn, {}) or {}).get("forge_hijacked", [])) +
                len((routing_results_by_as.get(asn, {}) or {}).get("origin_hijacking", [])) +
                len((routing_results_by_as.get(asn, {}) or {}).get("forge_hijacking", []))
                for asn in as_list
            )
            anomaly_as_with_routing = [
                asn for asn in anomaly_as_list
                if routing_results_by_as.get(asn, {}) and (
                    len(routing_results_by_as[asn].get("origin_hijacked", [])) > 0 or
                    len(routing_results_by_as[asn].get("forge_hijacked", [])) > 0 or
                    len(routing_results_by_as[asn].get("origin_hijacking", [])) > 0 or
                    len(routing_results_by_as[asn].get("forge_hijacking", [])) > 0
                )
            ]
            correlation_count = len(anomaly_as_with_routing)
            summary_parts = []
            summary_parts.append(
                f"<p><strong>During the analysis period ({start_time} to {end_time}), "
                f"{anomaly_count} out of {total_as_count} analyzed AS exhibited traffic anomalies "
                f"({total_traffic_anomalies} total anomaly points detected).</strong></p>"
            )
            if total_routing_alerts > 0:
                summary_parts.append(
                    f"<p><strong>Routing security analysis detected {total_routing_alerts} routing alerts "
                    f"across the analyzed AS, including origin hijacks, path forgery (MITM), and hijacking activities.</strong></p>"
                )
                if correlation_count > 0:
                    summary_parts.append(
                        f"<p><strong>Correlation Analysis:</strong> {correlation_count} AS ({', '.join(f'AS{asn}' for asn in anomaly_as_with_routing[:5])}"
                        f"{' and more' if len(anomaly_as_with_routing) > 5 else ''}) showed <em>both</em> traffic anomalies and routing security issues, "
                        f"suggesting that the traffic disruptions are likely <strong>routing-related</strong> (e.g., hijacking or path manipulation).</p>"
                    )
                else:
                    summary_parts.append(
                        f"<p><strong>Correlation Analysis:</strong> Traffic anomalies were detected, but no corresponding routing security issues were found "
                        f"for the affected AS during this time window. This suggests the traffic disruptions may be <strong>non-routing-related</strong> "
                        f"(e.g., application-layer issues, DDoS, or infrastructure failures).</p>"
                    )
            else:
                summary_parts.append(
                    f"<p><strong>No routing security alerts were detected during this period.</strong> "
                    f"The traffic anomalies observed are likely <strong>not related to BGP routing issues</strong> and may stem from other causes "
                    f"(application problems, network congestion, or external attacks not involving route manipulation).</p>"
                )
            return "".join(summary_parts)
        
        executive_summary_html = build_executive_summary()
        
        # Replace placeholders
        report_html = BATCH_HTML_TEMPLATE.replace("{{TIME_RANGE}}", f"{start_time} to {end_time}")
        report_html = report_html.replace("{{TOTAL_AS_COUNT}}", str(total_as_count))
        report_html = report_html.replace("{{ANOMALY_AS_COUNT}}", str(anomaly_count))
        report_html = report_html.replace("{{ANALYSIS_TIMESTAMP}}", batch_result.get("batch_result", {}).get("analysis_timestamp", datetime.now().isoformat()))
        report_html = report_html.replace("{{EXECUTIVE_SUMMARY}}", executive_summary_html)
        report_html = report_html.replace("{{AS_RESULTS_TABLE}}", as_results_table)
        report_html = report_html.replace("{{TRAFFIC_GALLERY}}", traffic_gallery_html)
        report_html = report_html.replace("{{ROUTING_SECTION}}", routing_section_html)
        report_html = report_html.replace("{{AS_DETAILS}}", as_details_html)
        
        # Save report
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_html)
        
        return str(report_file)
        
    except Exception as e:
        import traceback
        print(f"Failed to generate batch HTML report: {e}")
        traceback.print_exc()
        return None


async def generate_comprehensive_report(
    llm: Any,
    routing_analysis: Dict[str, Any] = None,
    traffic_analysis: Dict[str, Any] = None,
    law_analysis: Dict[str, Any] = None,
    reasoning_analysis: Dict[str, Any] = None,
    start_time: str = None,
    output_dir: Path = None,
    org_name: str = None,
    asn: str = None,
    fallback_report_func: Any = None,
) -> Dict[str, Any]:
    """Generate comprehensive report with LLM insights, traffic diagrams, and root cause analysis"""
    
    # Extract extended time range from reasoning analysis if available
    extended_time_range = None
    if reasoning_analysis:
        try:
            source = reasoning_analysis
            if isinstance(source, str):
                source = json.loads(source)
            ev = (source or {}).get("evidence_summary", {})
            extended_time_range = (ev or {}).get("extended_analysis_time_range")
        except Exception:
            pass
    
    # Prepare comprehensive analysis data for LLM summarization
    analysis_data = {
        "asn": asn,
        "org_name": org_name or "Unknown Organization",
        "start_time": start_time,
        "extended_analysis_time_range": extended_time_range,
        "routing_analysis": routing_analysis or {},
        "traffic_analysis": traffic_analysis or {},
        "law_analysis": law_analysis or {},
        "reasoning_analysis": reasoning_analysis or {}
    }
    
    schema_hint = {
        "executive_summary": {"overview": "", "key_findings": []},
        "traffic_analysis": {"status": "", "details": [], "insights": []},
        "routing_analysis": {"status": "", "alerts": [], "notable_prefixes": []},
        "root_cause": {"assessment": "", "evidence": []},
        "impact_assessment": {"business_impact": "", "technical_impact": "", "severity": ""},
        "recommendations": {"immediate_actions": [], "long_term": []},
        "technical_details": {"confidence": "", "data_quality": "", "limitations": []}
    }
    
    report_prompt = f"""
You are a network outage analyst. Summarize the incident strictly as JSON following this schema:
{json.dumps(schema_hint, indent=2)}

Rules:
- Output valid JSON only, no markdown or code fences.
- Use English.
- Ground every statement in the provided evidence.
- Limit each string to two sentences when possible.

Analysis data:
{json.dumps(analysis_data, indent=2, ensure_ascii=False)}
"""

    try:
        response = llm.complete(report_prompt)
        raw_text = response.text if hasattr(response, "text") else str(response)
        summary_payload = parse_llm_json(raw_text)
        
        html_content = render_summary_html(
            summary_payload=summary_payload,
            routing_analysis=routing_analysis,
            traffic_analysis=traffic_analysis,
            law_analysis=law_analysis,
            reasoning_analysis=reasoning_analysis,
            org_name=org_name,
            asn=asn,
            start_time=start_time
        )
        
        # Save HTML report
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = output_dir / f"comprehensive_analysis_AS{asn}_{timestamp}.html"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        from .logger import logger
        logger.info(f"📊 Comprehensive report generated: {html_file}")
        
        return {
            "success": True,
            "html_report_path": str(html_file),
            "report_type": "comprehensive_analysis",
            "asn": asn,
            "org_name": org_name,
            "analysis_timestamp": datetime.now().isoformat(),
            "report_summary": summary_payload,
            "includes": {
                "traffic_analysis": bool(traffic_analysis),
                "routing_analysis": bool(routing_analysis),
                "law_analysis": bool(law_analysis),
                "reasoning_analysis": bool(reasoning_analysis),
                "llm_insights": True
            }
        }
        
    except Exception as e:
        from .logger import logger
        logger.error(f"Failed to generate comprehensive report: {e}")
        # Fallback to basic report if provided
        if fallback_report_func:
            return fallback_report_func(
                routing_analysis=routing_analysis,
                traffic_analysis=traffic_analysis,
                law_analysis=law_analysis,
                reasoning_analysis=reasoning_analysis,
                start_time=start_time,
                output_dir=output_dir,
                org_name=org_name,
                asn=asn,
            )
        raise 