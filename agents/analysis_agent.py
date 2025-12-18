import os
import sys
import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from llm.llm_factory import setup_llm_settings
from utils.logger import logger
from config import MODEL, API_KEY, BASE_URL

def generate_comprehensive_analysis_report(
    traffic_analysis: Dict[str, Any],
    routing_analysis: Dict[str, Any],
    user_input: str = None
) -> Dict[str, Any]:
    """
    Generate comprehensive analysis report using LLM reasoning capabilities.
    
    Args:
        traffic_analysis: Results from traffic agent
        routing_analysis: Results from routing agent
        user_input: Original user input for context
    
    Returns:
        Dict with comprehensive analysis report
    """
    try:
        # Setup LLM
        llm, token_counter = setup_llm_settings(
            model=MODEL,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=0.3,
            timeout=120.0,
            max_retries=2
        )
        
        # Prepare analysis data
        analysis_data = {
            "user_input": user_input,
            "analysis_timestamp": datetime.now().isoformat(),
            "traffic_analysis": traffic_analysis,
            "routing_analysis": routing_analysis
        }
        
        # Create comprehensive prompt for LLM analysis
        prompt = f"""
You are a network security expert analyzing a traffic outage incident. Provide a comprehensive, readable report based on the following data. Use English only.

## User Report:
{user_input or "No user input provided"}

## Traffic Analysis Results:
- Success: {traffic_analysis.get('success', False)}
- ASN: {traffic_analysis.get('asn', 'Unknown')}
- Analysis Period: {traffic_analysis.get('current_date_range', 'Unknown')}
- Total Anomalies: {traffic_analysis.get('anomaly_count', 0)}
- Outage Period Anomalies: {traffic_analysis.get('outage_period_anomaly_count', 0)}
- Percent Change: {traffic_analysis.get('percent_change', 0):.2f}%
- Data Points: {traffic_analysis.get('data_points', 0)}
- Plot Available: {'Yes' if traffic_analysis.get('plot_path') else 'No'}

## Routing Analysis Results (with timestamps and AS paths):
- Success: {routing_analysis.get('success', False)}
- ASN: {routing_analysis.get('asn', 'Unknown')}
- Analysis Period: {routing_analysis.get('analysis_period', 'Unknown')}
- Prefix Hijacks (Victim): {routing_analysis.get('total_prefix_hijacks', 0)}
- Prefix Hijacking (Attacker): {routing_analysis.get('total_prefix_hijacking', 0)}
- MITM Alerts: {routing_analysis.get('total_mitm_alerts', 0)}

Victim events (first 5):
{json.dumps(routing_analysis.get('origin_hijacked', [])[:5], indent=2)}
MITM/path-forgery victim events (first 5):
{json.dumps(routing_analysis.get('forge_hijacked', [])[:5], indent=2)}
Attacker events (first 5):
{json.dumps(routing_analysis.get('origin_hijacking', [])[:5], indent=2)}

## Detailed Traffic Anomalies:
{json.dumps(traffic_analysis.get('outage_period_anomalies', [])[:5], indent=2) if traffic_analysis.get('outage_period_anomalies') else 'None'}

## Detailed Routing Events:
Prefix Hijacks (Victim):
{json.dumps(routing_analysis.get('origin_hijacked', [])[:3], indent=2) if routing_analysis.get('origin_hijacked') else 'None'}

MITM Alerts:
{json.dumps(routing_analysis.get('mitm_alerts', [])[:3], indent=2) if routing_analysis.get('mitm_alerts') else 'None'}

## Feature-Based Outage Analysis:
{json.dumps(routing_analysis.get('outage_analysis', {}), indent=2)}

## Leak Investigation Status:
{json.dumps(routing_analysis.get('leak_analysis', {}), indent=2)}

## Analysis Requirements:

Please provide a comprehensive analysis report with the following sections:

1. **Executive Summary**: 
   - Brief overview of the incident
   - Key findings and conclusions
   - Relationship between traffic anomalies and routing issues

2. **Traffic Analysis**:
   - Analysis of traffic patterns during the outage period
   - Comparison with historical data
   - Significance of detected anomalies
   - Visual analysis recommendations (reference the traffic chart)

3. **Routing Security Analysis** (aggregate and interpret alerts):
   - Group by category: origin hijack victim, origin hijacking attacker, path forgery/MITM
   - Summarize time windows, top prefixes, top suspicious ASNs, and representative AS paths
   - Highlight sequences where traffic anomalies align with routing alerts
   - Explain outage-detector findings and whether leak analysis yielded actionable evidence

4. **Correlation Analysis**:
   - Relationship between traffic anomalies and routing issues
   - Timeline correlation if applicable
   - Causal analysis

5. **Conclusion and Recommendations**:
   - Final assessment of whether traffic changes are routing-related
   - Alternative explanations if routing is not the cause
   - Recommendations for further investigation
   - Preventive measures

6. **Technical Details**:
   - Summary of technical findings
   - Data quality and limitations
   - Confidence levels in conclusions

Please ensure the analysis is:
- Professional and technical
- Based on the provided data
- Clear about uncertainties
- Actionable for network operators
- Written in English only

Generate a comprehensive report now.
"""
        
        logger.info("🧠 Generating comprehensive analysis report using LLM...")
        
        # Generate analysis using LLM
        response = llm.complete(prompt)
        analysis_report = str(response)
        
        # Extract key insights programmatically
        insights = extract_key_insights(traffic_analysis, routing_analysis)
        
        # Generate HTML report
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


def extract_key_insights(traffic_analysis: Dict[str, Any], routing_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key insights from analysis data."""
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
    
    # Determine correlation
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
    analysis_report: str,
    traffic_analysis: Dict[str, Any],
    routing_analysis: Dict[str, Any],
    insights: Dict[str, Any]
) -> str:
    """Generate HTML report with analysis results."""
    try:
        def format_number(value):
            if isinstance(value, (int, float)):
                return f"{value:.2f}"
            return str(value) if value is not None else "N/A"

        # Create output directory
        output_dir = Path(__file__).parent.parent / "results" / "html"
        output_dir.mkdir(exist_ok=True, parents=True)
        
        # Prepare data for HTML
        asn = traffic_analysis.get('asn', routing_analysis.get('asn', 'Unknown'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Handle traffic chart
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
            # Fallback: quick inline sparkline using ASCII if PNG not available
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
        
        # Multi-AS gallery
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

        # Generate HTML content
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

        <div class="section">
            <h2>Routing Outage Assessment</h2>
            <p><strong>Status:</strong> {outage_status}</p>
            <p><strong>Score:</strong> {outage_score_display}</p>
            <p><strong>Indicators:</strong> {outage_indicators}</p>
            <p><strong>Leak Module:</strong> {leak_message}</p>
            <h3>Representative Anomalies</h3>
            <ul>
                {outage_anomaly_list}
            </ul>
        </div>

        <div class="section">
            <h2>Comprehensive Analysis Report</h2>
            <div class="analysis-content">{analysis_report}</div>
        </div>

        <div class="section">
            <h2>Technical Details</h2>
            <p><strong>Analysis Timestamp:</strong> {datetime.now().isoformat()}</p>
            <p><strong>Generated by:</strong> LLM-powered Analysis Agent</p>
            <p><strong>Traffic Analysis Success:</strong> {'Yes' if traffic_analysis.get('success') else 'No'}</p>
            <p><strong>Routing Analysis Success:</strong> {'Yes' if routing_analysis.get('success') else 'No'}</p>
            <p><strong>Outage Detector Status:</strong> {outage_status}</p>
            <p><strong>Leak Module Message:</strong> {leak_message}</p>
        </div>
    </div>
</body>
</html>"""
        
        # Save HTML file
        html_file = output_dir / f"traffic_outage_analysis_AS{asn}_{timestamp}.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"📊 HTML analysis report generated: {html_file}")
        return str(html_file)
        
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {str(e)}")
        return ""


def run_analysis_agent(
    traffic_analysis: Dict[str, Any],
    routing_analysis: Dict[str, Any],
    user_input: str = None
) -> Dict[str, Any]:
    """
    Main function to run the analysis agent.
    
    Args:
        traffic_analysis: Results from traffic agent
        routing_analysis: Results from routing agent
        user_input: Original user input for context
    
    Returns:
        Dict with comprehensive analysis results
    """
    logger.info("🧠 Starting comprehensive analysis agent...")
    
    return generate_comprehensive_analysis_report(
        traffic_analysis=traffic_analysis,
        routing_analysis=routing_analysis,
        user_input=user_input
    )


__all__ = ["run_analysis_agent", "generate_comprehensive_analysis_report"]
