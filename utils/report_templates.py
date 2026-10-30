"""HTML templates for batch analysis reports."""

BATCH_ANALYSIS_HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Batch BGP Analysis</title></head>
<body>
<h1>Batch BGP Analysis Report</h1>
<p>Period: {analysis_period}</p>
<p>Total AS analyzed: {total_as}, with anomalies: {anomalous_as_count}</p>
{as_sections}
</body></html>"""

AS_SECTION_TEMPLATE = """<section>
<h2>AS{asn}</h2>
<p>Status: {status}</p>
<p>Anomaly count: {anomaly_count}</p>
</section>"""