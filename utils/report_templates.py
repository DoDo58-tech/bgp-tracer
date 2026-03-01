"""
HTML templates for BGP security analysis reports.

This module contains all HTML templates, CSS styles, and JavaScript
components used for generating comprehensive BGP security reports.
"""

# Simplified HTML template for reports with no anomalies
NO_ANOMALIES_HTML_TEMPLATE = """<html>
  <head>
    <meta charset="utf-8" />
    <title>BGP Security Analysis Report</title>
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; font-size: 16px; }
      h2 { margin: 0.2em 0 0.4em 0; font-size: 24px; }
      .card { background: white; border-radius: 12px; box-shadow: 0 10px 25px rgba(15,23,42,.08); padding: 28px; margin-bottom: 24px; }
      .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.82rem; background: #eef2ff; color: #4338ca; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>BGP Security Analysis Report</h1>
      <p class="badge">AS{{TARGET_AS}} · Normal Operation</p>
      <p><strong>Analysis Window:</strong> {{TIME_RANGE}}</p>
    </div>

    <div class="card">
      <h2>Executive Summary</h2>
      {{EXEC_SUMMARY}}
    </div>
  </body>
</html>"""

# Main HTML template for BGP security analysis reports
BGP_SECURITY_HTML_TEMPLATE = """<html>
  <head>
    <meta charset="utf-8" />
    <title>BGP Security RCA Report</title>
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; font-size: 16px; }
      h2 { margin: 0.2em 0 0.4em 0; font-size: 24px; }
      h3 { margin: 0.8em 0 0.4em 0; font-size: 20px; }
      h4 { margin: 0.6em 0 0.3em 0; font-size: 18px; }
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
      .severity-critical { color: #d73027; font-weight: bold; }
      .severity-high { color: #f46d43; font-weight: bold; }
      .severity-medium { color: #fdae61; }
      .severity-low { color: #fee090; }
      .confidence-high { background-color: #e6f3ff; }
      .confidence-medium { background-color: #fff2e8; }
      .confidence-low { background-color: #ffebe9; }
      .card { background: white; border-radius: 12px; box-shadow: 0 10px 25px rgba(15,23,42,.08); padding: 28px; margin-bottom: 24px; }
      .grid { display: grid; gap: 20px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
      .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.82rem; background: #eef2ff; color: #4338ca; }
      .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 0.5em; }
      .status-normal { background-color: #28a745; }
      .status-warning { background-color: #ffc107; }
      .status-critical { background-color: #dc3545; }
      .expandable-section { cursor: pointer; background: #f8f9fa; padding: 1em; border-radius: 5px; margin: 0.5em 0; }
      .expandable-content { display: none; margin-top: 1em; }
      details { margin: 10px 0; background: #fafafa; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px 14px; }
      details summary { cursor: pointer; font-weight: 600; }
      .code-snippet { background: #f8f9fa; border-left: 4px solid #007bff; padding: 1em; margin: 1em 0; font-family: 'Courier New', monospace; }
    </style>
    <script>
      function toggleVisibility(element) {
        const content = element.querySelector('.expandable-content');
        if (content.style.display === 'none' || content.style.display === '') {
          content.style.display = 'block';
        } else {
          content.style.display = 'none';
        }
      }
    </script>
  </head>
  <body>
    <div class="card">
      <h1>BGP Security Root Cause Analysis Report</h1>
      <p class="badge">AS{{TARGET_AS}} · {{PRIMARY_CLASS}}</p>
      <p><strong>Analysis Window:</strong> {{TIME_RANGE}}</p>
      <p><strong>Detected Anomaly Period:</strong> {{DETECTED_TIME_RANGE}}</p>
      <p><strong>Total Events:</strong> {{TOTAL_EVENTS}}</p>
    </div>

    <div class="grid">
      <div class="card">
        <h2>Executive Summary</h2>
        {{EXEC_SUMMARY}}
      </div>
    </div>

    <div class="card">
      <h2>Traffic Analysis</h2>
      {{TRAFFIC_ANALYSIS}}
    </div>

    <div class="card">
      <h2>Routing Security Analysis</h2>
      <p><strong>Status:</strong> {{ROUTING_STATUS}}</p>

      <!-- Detection Type Summary -->
      <div style="display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin: 20px 0;">
        <!-- Hijack Detection Summary -->
        <div style="background: #fff3cd; border-left: 4px solid #d73027; padding: 12px; border-radius: 4px;">
          <h4 style="margin-top: 0; color: #d73027;">🚨 Hijack Detection</h4>
          <p style="margin: 8px 0;"><strong>Origin Hijacked:</strong> {{HIJACK_ORIGIN_COUNT}}</p>
          <p style="margin: 8px 0;"><strong>Forge Hijacked:</strong> {{HIJACK_FORGE_COUNT}}</p>
          <p style="margin: 8px 0;"><strong>Origin Hijacking:</strong> {{HIJACK_ORIGIN_ATTACKER_COUNT}}</p>
          <p style="margin: 8px 0;"><strong>Forge Hijacking:</strong> {{HIJACK_FORGE_ATTACKER_COUNT}}</p>
        </div>

        <!-- Route Leak Detection Summary -->
        <div style="background: #ffe8d6; border-left: 4px solid #fc8d59; padding: 12px; border-radius: 4px;">
          <h4 style="margin-top: 0; color: #fc8d59;">⚠️ Route Leak Detection</h4>
          <p style="margin: 8px 0;"><strong>Leaks Detected:</strong> {{LEAK_COUNT}}</p>
          <p style="margin: 8px 0;"><strong>Detection Success:</strong> {{LEAK_SUCCESS}}</p>
        </div>

        <!-- Outage Detection Summary -->
        <div style="background: #e8f4f8; border-left: 4px solid #1a9850; padding: 12px; border-radius: 4px;">
          <h4 style="margin-top: 0; color: #1a9850;">📊 Outage Detection</h4>
          <p style="margin: 8px 0;"><strong>Outage Score:</strong> {{OUTAGE_SCORE}}</p>
          <p style="margin: 8px 0;"><strong>Status:</strong> <span style="color: {{OUTAGE_COLOR}}; font-weight: bold;">{{OUTAGE_STATUS}}</span></p>
        </div>
      </div>

      <h3>Routing Alerts</h3>
      {{ROUTING_ALERTS}}

      <h3>Detailed Evidence</h3>
      {{ROUTING_ANALYSIS}}
    </div>

    <div class="card">
      <h2>Anomaly Details</h2>
      {{ANOMALY_DETAILS}}
    </div>

    <div class="card">
      <h2>Root Cause Analysis</h2>
      <div>{{ROOT_CAUSE_ANALYSIS}}</div>
    </div>

    <div class="card">
      <h2>Recommendations</h2>
      <ul>{{RECOMMENDATIONS}}</ul>
    </div>

    <div class="card">
      <h2>Technical Details</h2>
      <div>{{TECHNICAL_DETAILS}}</div>
    </div>
  </body>
</html>"""


# Template for batch analysis reports
BATCH_ANALYSIS_HTML_TEMPLATE = """<html>
  <head>
    <meta charset="utf-8" />
    <title>BGP Security Batch Analysis Report</title>
    <style>
      body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.5; }
      h2 { margin: 0.2em 0 0.4em 0; font-size: 28px; }
      h3 { margin: 0.8em 0 0.4em 0; font-size: 22px; }
      table { border-collapse: collapse; width: 100%; margin: 0.6em 0; }
      th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
      th { background: #f5f5f5; font-weight: 600; }
      .summary-table { margin: 1em 0; }
      .as-section { margin: 2em 0; padding: 1em; border: 1px solid #e0e0e0; border-radius: 8px; }
      .as-header { background: #f8f9fa; padding: 0.5em; margin: -1em -1em 1em -1em; border-radius: 8px 8px 0 0; }
      .metric-good { color: #28a745; }
      .metric-warning { color: #ffc107; }
      .metric-critical { color: #dc3545; }
      .anomaly-count { font-weight: bold; }
    </style>
  </head>
  <body>
    <h2>BGP Security Batch Analysis Report</h2>

    <h3>Analysis Overview</h3>
    <table class="summary-table">
      <tr><th>Analysis Period</th><td>{{ANALYSIS_PERIOD}}</td></tr>
      <tr><th>Total AS Analyzed</th><td>{{TOTAL_AS}}</td></tr>
      <tr><th>AS with Anomalies</th><td>{{ANOMALOUS_AS_COUNT}}</td></tr>
      <tr><th>Report Generated</th><td>{{REPORT_TIMESTAMP}}</td></tr>
    </table>

    <h3>Summary Statistics</h3>
    <table class="summary-table">
      <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
      <tr><td>Total Routing Anomalies</td><td>{{TOTAL_ROUTING_ANOMALIES}}</td><td>{{ROUTING_STATUS}}</td></tr>
      <tr><td>Total Traffic Anomalies</td><td>{{TOTAL_TRAFFIC_ANOMALIES}}</td><td>{{TRAFFIC_STATUS}}</td></tr>
      <tr><td>AS with High Severity Issues</td><td>{{HIGH_SEVERITY_AS}}</td><td>{{SEVERITY_STATUS}}</td></tr>
    </table>

    <h3>Per-AS Analysis Results</h3>
    {{PER_AS_SECTIONS}}

    <h3>Recommendations</h3>
    <ul>
      {{RECOMMENDATIONS}}
    </ul>
  </body>
</html>"""


# Template for individual AS section in batch reports
AS_SECTION_TEMPLATE = """
    <div class="as-section">
      <div class="as-header">
        <h4>AS{{ASN}} {{AS_NAME}}</h4>
      </div>

      <table>
        <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
        <tr><td>Routing Anomalies</td><td>{{ROUTING_ANOMALIES}}</td><td>{{ROUTING_STATUS}}</td></tr>
        <tr><td>Traffic Anomalies</td><td>{{TRAFFIC_ANOMALIES}}</td><td>{{TRAFFIC_STATUS}}</td></tr>
        <tr><td>Total Events</td><td>{{TOTAL_EVENTS}}</td><td>{{EVENTS_STATUS}}</td></tr>
      </table>

      {{TRAFFIC_CHART}}

      <h5>Key Findings</h5>
      <ul>{{KEY_FINDINGS}}</ul>
    </div>
"""


# CSS styles for enhanced report appearance
ENHANCED_CSS_STYLES = """
    <style>
      .report-container { max-width: 1200px; margin: 0 auto; }
      .header-section { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2em; border-radius: 10px; margin-bottom: 2em; }
      .metric-card { background: white; border-radius: 8px; padding: 1.5em; margin: 1em 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
      .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1em; }
      .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 0.5em; }
      .status-normal { background-color: #28a745; }
      .status-warning { background-color: #ffc107; }
      .status-critical { background-color: #dc3545; }
      .timeline { position: relative; padding-left: 2em; }
      .timeline-item { margin-bottom: 1em; position: relative; }
      .timeline-marker { position: absolute; left: -2.2em; width: 12px; height: 12px; border-radius: 50%; background: #007bff; border: 3px solid white; box-shadow: 0 0 0 2px #007bff; }
      .expandable-section { cursor: pointer; background: #f8f9fa; padding: 1em; border-radius: 5px; margin: 0.5em 0; }
      .expandable-content { display: none; margin-top: 1em; }
      .code-snippet { background: #f8f9fa; border-left: 4px solid #007bff; padding: 1em; margin: 1em 0; font-family: 'Courier New', monospace; }
    </style>
"""


def get_css_class_for_severity(severity: str) -> str:
    """Get CSS class for severity level."""
    severity_map = {
        'critical': 'severity-critical',
        'high': 'severity-high',
        'medium': 'severity-medium',
        'low': 'severity-low'
    }
    return severity_map.get(severity.lower(), 'severity-low')


def get_css_class_for_confidence(confidence: str) -> str:
    """Get CSS class for confidence level."""
    confidence_map = {
        'high': 'confidence-high',
        'medium': 'confidence-medium',
        'low': 'confidence-low'
    }
    return confidence_map.get(confidence.lower(), 'confidence-low')


def get_status_indicator_class(status: str) -> str:
    """Get CSS class for status indicator."""
    status_map = {
        'normal': 'status-normal',
        'good': 'status-normal',
        'warning': 'status-warning',
        'critical': 'status-critical',
        'anomalous': 'status-critical'
    }
    return status_map.get(status.lower(), 'status-normal')
