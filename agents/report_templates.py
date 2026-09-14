"""
Static HTML templates for report generation.

These are the ONLY HTML structures that are hardcoded.
All content comes from the LLM — this file only provides CSS and empty containers.
"""

# ── CSS shared by both the LLM prompt and the fallback ──────────────────────────
REPORT_HTML_CSS = """body { font-family: sans-serif; margin: 24px; line-height: 1.6; max-width: 900px; }
.header { background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
h1, h2, h3 { color: #1a1a2e; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background: #f5f5f5; }
.badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }
.badge-L1 { background: #dc3545; color: white; }
.badge-L2 { background: #fd7e14; color: white; }
.badge-L3 { background: #ffc107; color: #000; }
.badge-L4 { background: #198754; color: white; }
.badge-L5 { background: #6c757d; color: white; }
.cite { font-family: monospace; background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 0.85em; }
.traffic-plot img { max-width: 100%; margin: 16px 0; }
.counterfactual { background: #f8f9fa; border-left: 4px solid #6c757d; padding: 16px; margin: 16px 0; }
.hypothesis-card { border: 1px solid #dee2e6; border-radius: 8px; padding: 16px; margin: 16px 0; }
"""

# ── Fallback report (used only when LLM fails) ─────────────────────────────────
FALLBACK_REPORT_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>BGP Incident Report — AS{asn}</title>
<style>{css}</style>
</head>
<body>
<div class="header">
  <h1>BGP Routing Security Incident Report</h1>
  <p><strong>Target AS:</strong> {asn}</p>
  <p><strong>Analysis Window:</strong> {start} to {end}</p>
</div>

<h2>Executive Summary</h2>
<p>LLM report generation failed. Displaying raw data below.</p>
<p>Traffic anomalies: {traffic_count} | Routing events: {routing_events} | Hijacks: {hijacks} | Leaks: {leaks}</p>

<h2>Traffic Data</h2>
<pre>{traffic_data}</pre>

<h2>Routing Data</h2>
<pre>{routing_data}</pre>

<h2>Correlation Analysis</h2>
<pre>{correlation_data}</pre>

<h2>Auto-Probe Findings</h2>
<pre>{probes}</pre>

</body>
</html>""".format(css=REPORT_HTML_CSS)
