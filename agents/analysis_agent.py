import os
import sys
import json
from datetime import datetime
from pathlib import Path

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from llm.llm_factory import setup_llm_settings
from utils.logger import logger
from config import MODEL, API_KEY, BASE_URL
import re
from html import escape as html_escape


def generate_comprehensive_analysis_report(
    traffic_analysis,
    routing_analysis,
    user_input=None
):
    try:
        llm, token_counter = setup_llm_settings(
            model=MODEL,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=0.3,
            timeout=300.0,
            max_retries=2
        )

        analysis_data = {
            "user_input": user_input,
            "analysis_timestamp": datetime.now().isoformat(),
            "traffic_analysis": traffic_analysis,
            "routing_analysis": routing_analysis
        }

        logger.info("Generating comprehensive analysis report...")

        traffic_json = json.dumps(traffic_analysis, ensure_ascii=False, indent=2)
        routing_json = json.dumps(routing_analysis, ensure_ascii=False, indent=2)

        prompt = f"""
You are a senior Internet reliability and BGP routing expert. Perform structured Root Cause Analysis (RCA)
for a traffic outage event using the provided traffic and routing analyses.

User query (if any):
{json.dumps(user_input, ensure_ascii=False)}

Current UTC time: {analysis_data['analysis_timestamp']}

=== Traffic Analysis (JSON) ===
{traffic_json}

=== Routing Analysis (JSON) ===
{routing_json}

Follow a multi-step deep-thinking procedure in your own mind, then produce a concise but comprehensive report:

1. Problem framing
   - Restate the suspected incident (who, when, where, what symptoms).
2. Evidence collection
   - Summarize key traffic anomalies (time range, magnitude, affected AS/prefixes).
   - Summarize key routing anomalies (hijacks, forged paths/MITM, leaks, outages).
3. Hypothesis generation
   - Enumerate 2-4 candidate root causes (e.g., origin hijack, MITM, route leak, pure traffic incident, other).
4. Hypothesis evaluation
   - For each hypothesis, list supporting and contradicting evidence from BOTH traffic and routing data.
   - Explicitly discuss temporal correlation and impact scope (prefixes / regions / services).
5. Root cause decision
   - Select the most likely root cause(s) and give a confidence level (High/Medium/Low).
   - Explain why this root cause best matches the evidence.
6. Impact and blast radius
   - Describe who is affected (AS, countries/regions, services) and severity.
7. Actionable recommendations
   - Give concrete next steps for operators (BGP mitigation / traffic mitigation / monitoring / data collection).

OUTPUT FORMAT REQUIREMENTS:
- Prefer an HTML report (starting with <!DOCTYPE html> or <html>) if convenient, suitable for direct rendering.
- If not using HTML, return a well-structured Markdown-style plain text report.
- Do NOT include any code blocks; use plain text or HTML only.
"""

        response = llm.complete(prompt)
        analysis_report = response.text if hasattr(response, "text") else str(response)

        if analysis_report.strip().lower().startswith("<!doctype html") or analysis_report.strip().startswith("<html"):
            output_dir = Path(__file__).parent.parent / "results" / "html"
            output_dir.mkdir(exist_ok=True, parents=True)
            asn = traffic_analysis.get('asn', routing_analysis.get('asn', 'Unknown'))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_file = output_dir / f"llm_report_AS{asn}_{timestamp}.html"
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(analysis_report)

            insights = extract_key_insights(traffic_analysis, routing_analysis)

            return {
                "success": True,
                "analysis_report": analysis_report,
                "insights": insights,
                "html_report_path": str(html_file),
                "generated_by_llm": True,
                "generation_timestamp": datetime.now().isoformat(),
                "token_usage": getattr(token_counter, 'total_tokens', 0) if token_counter else 0
            }

        insights = extract_key_insights(traffic_analysis, routing_analysis)
        html_report = generate_html_report(analysis_report, traffic_analysis, routing_analysis, insights)

        return {
            "success": True,
            "analysis_report": analysis_report,
            "insights": insights,
            "html_report_path": html_report,
            "generated_by_llm": True,
            "generation_timestamp": datetime.now().isoformat(),
            "token_usage": getattr(token_counter, 'total_tokens', 0) if token_counter else 0
        }

    except Exception as e:
        logger.error(f"Analysis agent error: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "analysis_report": "Analysis generation failed",
            "generated_by_llm": False
        }


def extract_key_insights(traffic_analysis, routing_analysis):
    outage_detected = routing_analysis.get('outage_analysis', {}).get('is_outage_suspected', False)
    insights = {
        "traffic_anomalies_detected": traffic_analysis.get('anomaly_count', 0) > 0,
        "routing_issues_detected": (
            routing_analysis.get('total_prefix_hijacks', 0) > 0 or
            routing_analysis.get('total_mitm_alerts', 0) > 0 or
            outage_detected
        ),
        "correlation_found": False,
        "confidence_level": "low",
        "primary_cause": "unknown",
        "outage_detected": outage_detected
    }

    if insights["traffic_anomalies_detected"] and insights["routing_issues_detected"]:
        insights["correlation_found"] = True
        insights["confidence_level"] = "high"
        insights["primary_cause"] = "routing_related"
    elif insights["traffic_anomalies_detected"] and not insights["routing_issues_detected"]:
        insights["confidence_level"] = "medium"
        insights["primary_cause"] = "non_routing_related"
    elif not insights["traffic_anomalies_detected"] and insights["routing_issues_detected"]:
        insights["confidence_level"] = "medium"
        insights["primary_cause"] = "routing_issues_without_traffic_impact"

    return insights


def generate_html_report(
    analysis_report,
    traffic_analysis,
    routing_analysis,
    insights
):
    try:
        def format_number(value):
            if isinstance(value, (int, float)):
                return f"{value:.2f}"
            return str(value) if value is not None else "N/A"

        output_dir = Path(__file__).parent.parent / "results" / "html"
        output_dir.mkdir(exist_ok=True, parents=True)

        asn = traffic_analysis.get('asn', routing_analysis.get('asn', 'Unknown'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        traffic_chart_html = ""
        multi_as_gallery_html = ""
        is_multi_as = traffic_analysis.get('analysis_type') == 'multi_as_country_analysis'
        if traffic_analysis.get('plot_path'):
            try:
                import base64
                with open(traffic_analysis['plot_path'], 'rb') as img_file:
                    img_data = img_file.read()
                    img_base64 = base64.b64encode(img_data).decode('utf-8')
                    traffic_chart_html = f'<img src="data:image/png;base64,{img_base64}" alt="Traffic Analysis Chart" style="max-width: 100%; height: auto;">'
            except Exception as e:
                logger.warning(f"Could not embed traffic chart: {e}")
                traffic_chart_html = f'<p>Traffic chart available at: {traffic_analysis["plot_path"]}</p>'
        elif traffic_analysis.get('timestamps') and traffic_analysis.get('current_values'):
            try:
                import io
                import base64
                import matplotlib.pyplot as _plt
                fig = _plt.figure(figsize=(10,2))
                _plt.plot(list(range(len(traffic_analysis['current_values']))), traffic_analysis['current_values'], color='#2E86AB')
                _plt.tight_layout()
                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=150)
                _plt.close(fig)
                traffic_chart_html = f'<img src="data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}" alt="Traffic Analysis Chart" style="max-width: 100%; height: auto;">'
            except Exception:
                pass
        if not traffic_chart_html and not is_multi_as:
            traffic_chart_html = "<p>No traffic visualization available for this run.</p>"

        if is_multi_as and traffic_analysis.get('results'):
            gallery_items = []
            for entry in traffic_analysis.get('results', []):
                plot_path = entry.get('plot_path')
                asn_label = entry.get('asn') or (entry.get('as_info') or {}).get('asn', 'N/A')
                if plot_path and os.path.exists(plot_path):
                    try:
                        import base64
                        with open(plot_path, 'rb') as img_file:
                            encoded = base64.b64encode(img_file.read()).decode('utf-8')
                        gallery_items.append(
                            f"<div class='traffic-multi-item'><div class='traffic-multi-title'>AS{asn_label}</div>"
                            f"<img src='data:image/png;base64,{encoded}' alt='Traffic chart for AS{asn_label}'/></div>"
                        )
                    except Exception:
                        continue
            if gallery_items:
                multi_as_gallery_html = "<div class='traffic-multi-grid'>" + "".join(gallery_items) + "</div>"
            if not traffic_chart_html:
                traffic_chart_html = "<p>Aggregate traffic chart is not available for multi-AS analysis.</p>"

        outage_analysis = routing_analysis.get('outage_analysis') or {}
        leak_analysis = routing_analysis.get('leak_analysis') or {}
        outage_status = 'Yes' if outage_analysis.get('is_outage_suspected') else 'No'
        outage_score_display = format_number(outage_analysis.get('outage_score'))
        outage_indicators = ", ".join(outage_analysis.get('indicators', [])) if outage_analysis.get('indicators') else "None"
        outage_anomalies = outage_analysis.get('anomalies') or []
        outage_anomaly_list = "".join(
            [
                f"<li><strong>{a.get('timestamp', 'N/A')}</strong> — {a.get('feature', 'unknown')} (value={format_number(a.get('value'))}, z={format_number(a.get('z_score'))})</li>"
                for a in outage_anomalies[:5]
            ]
        ) or "<li>No feature anomalies detected.</li>"
        leak_message = leak_analysis.get('message', 'Leak analysis did not run.')

        show_anomaly_details = bool(outage_anomalies or routing_analysis.get('origin_hijack') or routing_analysis.get('forge_hijack') or traffic_analysis.get('anomalies_detected'))
        show_technical_details = any([
            routing_analysis.get('as_rel_file'),
            routing_analysis.get('prefix2as_file'),
            routing_analysis.get('asorg_file'),
            insights.get('token_usage') if isinstance(insights, dict) else False
        ])

        routing_block = ""
        technical_block = ""

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traffic Outage Analysis Report - AS{asn}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .metric-card {{ background-color: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff; }}
        .metric-card.traffic {{ border-left-color: #28a745; }}
        .metric-card.routing {{ border-left-color: #dc3545; }}
        .metric-card.correlation {{ border-left-color: #ffc107; }}
        .metric-card.outage {{ border-left-color: #6f42c1; }}
        .metric-card h3 {{ margin: 0 0 10px 0; font-size: 16px; color: #666; }}
        .metric-value {{ font-size: 28px; font-weight: bold; margin: 0; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ margin: 0 0 15px 0; color: #333; }}
        .analysis-content {{ background-color: #f8f9fa; padding: 20px; border-radius: 6px; white-space: pre-wrap; line-height: 1.6; }}
        .chart-container {{ text-align: center; margin: 20px 0; }}
        .insights {{ background-color: #e9ecef; padding: 15px; border-radius: 6px; margin: 20px 0; }}
        .insight-item {{ margin: 10px 0; }}
        .confidence-high {{ color: #28a745; font-weight: bold; }}
        .confidence-medium {{ color: #ffc107; font-weight: bold; }}
        .confidence-low {{ color: #dc3545; font-weight: bold; }}
        .traffic-multi-grid {{ display: flex; flex-wrap: wrap; gap: 16px; justify-content: flex-start; margin-top: 20px; }}
        .traffic-multi-item {{ flex: 1 1 260px; max-width: 280px; background-color: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; box-shadow: 0 6px 18px rgba(15, 23, 42, 0.08); }}
        .traffic-multi-item img {{ width: 100%; height: auto; border-radius: 6px; }}
        .traffic-multi-title {{ font-weight: 600; margin-bottom: 8px; text-align: center; font-size: 0.95rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Traffic Outage Analysis Report</h1>
            <h2>AS{asn} - Comprehensive Analysis</h2>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="insights">
            <h3>Key Insights</h3>
            <div class="insight-item">
                <strong>Traffic Anomalies Detected:</strong> {'Yes' if insights['traffic_anomalies_detected'] else 'No'}
            </div>
            <div class="insight-item">
                <strong>Routing Issues Detected:</strong> {'Yes' if insights['routing_issues_detected'] else 'No'}
            </div>
            <div class="insight-item">
                <strong>Outage Indicators Raised:</strong> {'Yes' if insights.get('outage_detected') else 'No'}
            </div>
            <div class="insight-item">
                <strong>Correlation Found:</strong> {'Yes' if insights['correlation_found'] else 'No'}
            </div>
            <div class="insight-item">
                <strong>Confidence Level:</strong>
                <span class="confidence-{insights['confidence_level']}">{insights['confidence_level'].title()}</span>
            </div>
        </div>

        <div class="section">
            <h2>Traffic Analysis</h2>
            <div class="chart-container">
                {traffic_chart_html}
            </div>
            {multi_as_gallery_html}
            <p><strong>Analysis Period:</strong> {traffic_analysis.get('current_date_range', 'Unknown')}</p>
            <p><strong>Data Points:</strong> {traffic_analysis.get('data_points', 0)}</p>
            <p><strong>Percent Change:</strong> {traffic_analysis.get('percent_change', 0):.2f}%</p>
        </div>

        {routing_block}

        <div class="section">
            <h2>Comprehensive Analysis Report</h2>
            <div class="analysis-content">{analysis_report}</div>
        </div>

        {technical_block}
    </div>
</body>
</html>"""

        html_file = output_dir / f"traffic_outage_analysis_AS{asn}_{timestamp}.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML analysis report generated: {html_file}")
        return str(html_file)

    except Exception as e:
        logger.error(f"Failed to generate HTML report: {str(e)}")
        return ""


def run_analysis_agent(
    traffic_analysis,
    routing_analysis,
    user_input=None
):
    logger.info("Starting comprehensive analysis agent...")

    return generate_comprehensive_analysis_report(
        traffic_analysis=traffic_analysis,
        routing_analysis=routing_analysis,
        user_input=user_input
    )


__all__ = ["run_analysis_agent", "generate_comprehensive_analysis_report"]
