#!/usr/bin/env python3
"""End-to-end smoke test for the 4-mode architecture.

⚠️  WARNING: This test mocks the LLM. It validates ARCHITECTURE
(workflow order, blackboard propagation, enhanced vs base payload divergence,
report-agent post-processing pipeline) but NOT the LLM's analytical content.

The real LLM call takes 8-15 minutes per mode which is too slow for a sanity
loop. This test mocks the LLM at the lowest-level seam so we can verify the
*architecture* in <30 seconds.

For end-to-end validation against the real LLM, use::

    BGP_TRACER_WORKFLOW_TIMEOUT_S=2700 REPORT_LLM_TIMEOUT_S=2400 \
        python scripts/run_4mode_batch.py --asn AS12479 ...

Usage::

    cd /data/bgp_tracer
    python scripts/e2e_4mode_smoke.py
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
import types
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path("/data/bgp_tracer")
sys.path.insert(0, str(PROJECT_ROOT))

print("=" * 70, file=sys.stderr)
print("WARNING: e2e_4mode_smoke.py uses a MOCK LLM, not the real upstream.",
      file=sys.stderr)
print("It validates architecture (workflow + report pipeline) but NOT",
      file=sys.stderr)
print("the LLM's analytical content. For real-LLM validation, run",
      file=sys.stderr)
print("scripts/run_4mode_batch.py with BGP_TRACER_WORKFLOW_TIMEOUT_S=2700.",
      file=sys.stderr)
print("=" * 70, file=sys.stderr)

MODES = [
    ("traffic_first",        "traffic_first",        False),
    ("traffic_first_enhanced","traffic_first",         True),
    ("react",                "react",                 False),
    ("react_enhanced",       "react",                 True),
]

MOCK_HTML_ENHANCED = """
<h2>Enhanced Analysis</h2>
<p>The debate between prosecutor and defense concluded prosecution arguments
were more compelling with confidence 0.85. Reactive decision: ran an extra
debate round to resolve low-confidence diagnosis. Overall evaluation score
0.78 gate passed.</p>
"""

MOCK_HTML_BASE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>AS{asn} BGP Incident Report</title>
<style>body{{font-family:sans-serif;margin:2rem}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #ccc;padding:6px}}
th{{background:#f5f5f5}}
h2{{margin-top:2rem}}
</style></head>
<body>
<h1>BGP Incident Analysis for AS{asn}</h1>
<p>Analysis window: 2024-01-03 14:45 to 2024-01-03 15:30 UTC</p>

<h2>Executive Summary</h2>
<p>Analysis of BGP routing data for AS{asn} revealed a moderate routing
instability event. Traffic anomalies detected correlate with routing changes.
Verdict: L2 Partial Correlation.</p>

<h2>Traffic Analysis</h2>
<p>2284 traffic events observed with 12 anomalies detected. Peak-to-trough
traffic drop of 81.69% at 14:52:00Z.</p>
<table><thead><tr><th>Timestamp</th><th>Metric</th><th>Value</th><th>Severity</th></tr></thead>
<tbody>
<tr><td>2024-01-03T14:45:00Z</td><td>traffic_volume</td><td>0.41</td><td>high</td></tr>
<tr><td>2024-01-03T14:50:00Z</td><td>traffic_volume</td><td>0.42</td><td>medium</td></tr>
<tr><td>2024-01-03T14:55:00Z</td><td>traffic_volume</td><td>0.39</td><td>high</td></tr>
</tbody></table>

<h2>Routing Security Analysis</h2>
<p>Routing analysis identified potential route instability events. Origin hijacks: 0.</p>

<h2>Evidence Chain</h2>
<p>Correlation analysis: routing events=7, traffic events=12, temporal proximity=35s.</p>

<h2>Refutable Hypotheses</h2>
<p>H1: BGP route leak caused the traffic drop. Confidence: 0.45. Status: UNCONFIRMED</p>

<h2>Counterfactual Analysis</h2>
<p>Alternative: infrastructure maintenance. No maintenance records found.</p>

<h2>Gaps &amp; Limitations</h2>
<ul>
<li>RIPE RIS data coverage limited to RRC00</li>
<li>Traffic anomaly window expanded by 15 minutes</li>
</ul>

<h2>Operational Recommendations</h2>
<ul>
<li>Monitor AS{asn} for 48 hours for recurrence</li>
<li>Enable RPKI validation on edge routers</li>
</ul>

{enhanced_block}
</body>
</html>"""


def make_mock_llm_instance(asn: str, enhanced: bool) -> types.SimpleNamespace:
    """Create a mock LLM instance that supports both sync and stream interfaces."""
    asn_stripped = asn.replace("AS", "")
    canned = MOCK_HTML_BASE.format(
        asn=asn_stripped,
        enhanced_block=MOCK_HTML_ENHANCED if enhanced else "",
    )

    class _MockResponse:
        text = canned
        choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=canned))]

    class _StreamDelta:
        def __init__(self, content=""):
            self.content = content
        def __getitem__(self, k):
            return self.content

    class _StreamChoice:
        def __init__(self, text):
            self.delta = _StreamDelta(text)
            self.finish_reason = "stop"
        def __getitem__(self, k):
            return self.delta

    class _StreamChunk:
        def __init__(self, text):
            self.choices = [_StreamChoice(text)]

    def _stream_create(*args, **kwargs):
        for i in range(0, len(canned), 60):
            yield _StreamChunk(canned[i:i + 60])

    class _MockLLM:
        def __init__(self):
            self._step = 0
            self._canned = canned
            self.temperature = 0.7
            self._model_name = "mock-gpt-4"  # used by report_agent.generate_report_html

        def complete(self, prompt, *args, **kwargs):
            return _MockResponse()

        def acomplete(self, prompt, *args, **kwargs):
            return _MockResponse()

        def chat(self, messages, *args, **kwargs):
            return _MockResponse()

        def stream_chat(self, messages, *args, **kwargs):
            """Yield streaming chunks; react modes get ReAct actions first."""
            step = self._step
            self._step += 1
            if step == 0:
                # Ask for report generation
                text = (
                    f"Thought: Traffic and routing evidence available. "
                    f"Action: generate_report\n"
                    f'Action Input: {{"asn": "{asn_stripped}", '
                    f'"start_time": "2024-01-03 14:45", '
                    f'"end_time": "2024-01-03 15:30"}}'
                )
            else:
                # Done
                text = (
                    f"Thought: Report generated. Analysis complete.\n"
                    f"Action: Answer\n"
                    f'{{"answer": "report_generated"}}'
                )
            for i in range(0, len(text), 40):
                yield _StreamDelta(text[i:i + 40])
            yield _StreamDelta("\n")

    mock = _MockLLM()
    # Attach streaming client for report_agent.generate_report_html
    mock.client = types.SimpleNamespace(
        chat=types.SimpleNamespace(
            completions=types.SimpleNamespace(
                create=lambda *a, **kw: iter(_stream_create())
            )
        )
    )
    return mock


async def run_mode(mode_name: str, asn: str = "AS12479") -> dict:
    """Run one mode end-to-end with mocked LLM and return summary."""
    enhanced = "_enhanced" in mode_name
    base_mode = mode_name.replace("_enhanced", "")
    t0 = time.perf_counter()

    cache_path = PROJECT_ROOT / "results/quick/quick_12479_2024-01-03_1445_2024-01-03_1530.json"
    if not cache_path.exists():
        return {"mode": mode_name, "error": "quick cache not found", "success": False}

    cache = json.loads(cache_path.read_text())
    # Adapt flat routing to nested shape workflow_engine expects
    flat_r = cache.get("routing") or {}
    cache["routing"] = {
        "success": True,
        "asn": flat_r.get("asn", asn.replace("AS", "")),
        "hijack": {
            "origin_hijacked": flat_r.get("origin_hijacked", []),
            "forge_hijacked": flat_r.get("forge_hijacked", []),
            "origin_hijacking": flat_r.get("origin_hijacking", []),
            "forge_hijacking": flat_r.get("forge_hijacking", []),
            "mitm_alerts": flat_r.get("mitm_alerts", []),
        },
        "leak": {"route_leaks": []},
        "anomalies_detected": bool(flat_r.get("origin_hijacked")),
        "_source": "precomputed",
    }

    mock_llm = make_mock_llm_instance(asn, enhanced)

    # For react_enhanced: patch ReportCoordinator.generate to skip slow LLM calls.
    # This makes the smoke test complete in seconds rather than 60+ seconds.
    import agents.enhanced.multi_report as _multi_mod

    async def _fast_generate(self, **kw):
        class _R:
            final_html = mock_llm.complete("").text
            metadata = {"mock": True}
            conflict_resolutions = []
            confidence_calibration_log = []
            generation_trace = "[mock] skipped all coordinator LLM calls"
        return _R()

    # Patches must be visible to all modules that import llm_factory
    import llm.llm_factory as _llmf
    import agents.report_agent as _ra_mod
    import chief_agent as _ca_mod

    _orig = _llmf.setup_llm_settings

    def _patched_setup(*a, **kw):
        return mock_llm, None

    # Patch module-level _llm reference so generate_report_html (standalone
    # function that calls _get_llm() internally) also uses the mock.
    _orig_llm = getattr(_ra_mod, "_llm", None)

    summary = {"mode": mode_name, "asn": asn, "enhanced": enhanced}
    try:
        # Also set the module-level _llm directly so generate_report_html
        # (which calls _get_llm() at module level) picks up the mock.
        _ra_mod._llm = mock_llm
        with patch.object(_llmf, "setup_llm_settings", _patched_setup), \
             patch.object(_ra_mod, "setup_llm_settings", _patched_setup), \
             patch.object(_ca_mod, "setup_llm_settings", _patched_setup), \
             patch.object(_multi_mod.ReportCoordinator, "generate", _fast_generate):
            from chief_agent import analyze_deep_from_quick
            result = await asyncio.to_thread(
                analyze_deep_from_quick, cache,
                analysis_mode=base_mode, enhanced=enhanced,
            )
    except Exception as exc:
        summary["error"] = repr(exc)
        summary["elapsed_seconds"] = round(time.perf_counter() - t0, 2)
        return summary

    elapsed = round(time.perf_counter() - t0, 2)
    summary["elapsed_seconds"] = elapsed
    summary["deep_success"] = result.get("success", False)

    # Find HTML report path across all possible locations
    html_path = (
        result.get("html_report_path")
        or result.get("report_path")
        or result.get("final_result", {}).get("html_report_path")
        or result.get("analysis_report", {}).get("html_report_path")
        or result.get("chief_expert_analysis", {}).get("html_report_path")
        or ""
    )
    if html_path and Path(html_path).exists():
        html = Path(html_path).read_text()
        summary["html_size_bytes"] = len(html)
        summary["contains_enhanced_section"] = "Enhanced Analysis" in html
        summary["contains_placeholder_brackets"] = bool(
            re.search(r"\[([a-zA-Z_][\w.\[\]]+)\]", html)
        )
        summary["starts_with_doctype"] = html.lstrip().lower().startswith("<!doctype")
        summary["contains_target_asn"] = asn.replace("AS", "") in html
        out_dir = PROJECT_ROOT / "results/html/smoke"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{mode_name}_AS12479.html"
        out_path.write_text(html)
        summary["smoke_path"] = str(out_path)
    else:
        summary["html_error"] = f"no report_path (looked in: html_report_path etc.)"

    return summary


async def main():
    rows = []
    for mode_name, base_mode, enhanced in MODES:
        row = await run_mode(mode_name)
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False, indent=2), flush=True)
        print("---", flush=True)

    print("\n=== SUMMARY ===", flush=True)
    print(f"{'Mode':30s} {'OK':5s} {'Size(KB)':9s} {'Enhanced?':10s} {'Clean':8s}", flush=True)
    ok_count = 0
    for row in rows:
        ok = "✅" if row.get("html_size_bytes") and row.get("contains_target_asn") else "❌"
        size_kb = round(row.get("html_size_bytes", 0) / 1024, 1)
        has_enh = "✅" if row.get("contains_enhanced_section") else "⚠️"
        clean = "✅" if not row.get("contains_placeholder_brackets") else "❌"
        print(f"{row.get('mode','?'):30s} {ok:5s} {size_kb:8.1f} {has_enh:10s} {clean:8s}", flush=True)
        if ok == "✅":
            ok_count += 1

    print(f"\n{ok_count}/4 modes passed", flush=True)
    if ok_count < 4:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
