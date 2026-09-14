"""HTML templates for batch analysis reports.

These templates are used by ``utils.report_exporters.generate_batch_html_report``
which is only invoked from the multi-AS batch branch of ``chief_agent``. The
single-event report path goes through ``report_agent.generate_report_html`` and
does not depend on this module.

The minimal templates below are intentionally simple — they exist so that the
batch branch imports cleanly. For richer batch output, expand ``BATCH_ANALYSIS_HTML_TEMPLATE``
or ``AS_SECTION_TEMPLATE``.
"""

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