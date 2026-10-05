# Deterministic HTML Report Architecture (2026-09-19)

## Why

The previous report generator delegated the entire HTML structure to the
LLM. The LLM was asked to produce a self-contained HTML document. This
caused three systemic problems:

1. **Hallucination** — the LLM frequently invented ASNs, prefixes, and
   timestamps not present in the analysis payload. Reviewers had to
   manually cross-check every number in the rendered report.
2. **Inconsistency** — the HTML produced by the LLM often disagreed
   with the numeric tables in other parts of the same document
   (e.g. the executive summary mentioned "AS13335" while the routing
   table showed "AS3223"). The `enforce_section_completeness` and
   `inject_code_rendered_tables` post-processes existed primarily to
   patch over this.
3. **Slow** — generating a full HTML document via Kimi/GLM took 30–50
   seconds per event, dominating Phase 2 wall-clock time. Rate limits
   were hit frequently, falling back to the offline renderer.

The new architecture addresses all three.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       HTML Report Pipeline                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Python (deterministic)         LLM (prose only)                │
│   ──────────────────────         ────────────────                │
│                                                                  │
│   1. Parse structured payload     1. fill_slots()                 │
│      (traffic, routing, TCA,                                   │
│       ROA, evidence chain)        inputs:  structured payload    │
│                                    output:  3 prose strings       │
│   2. assemble_body()                       (executive_summary,   │
│      - Headline Metrics                    hypothesis_notes,     │
│      - Event Time Chain  ◀── new           gap_analysis)          │
│      - Traffic Analysis                   + defensive scrub     │
│      - Routing Security                                                  │
│      - Causal Direction (TCA)            rules: NO numbers,      │
│      - Evidence Chain                                 NO JSON,    │
│      - Hypotheses                                       NO HTML   │
│      - Confounders                                                    │
│      - Operational Recommendations  ◀── new (executable)        │
│      - LLM prose slots                                                   │
│                                                                  │
│   3. build_html_shell()                                          │
│      - Inject <style> blocks (shared + builder CSS)              │
│      - Embed traffic plot (base64)                               │
│      - Inject JS wiring for Execute buttons                      │
│                                                                  │
│   4. Save to results/html/llm_report_AS<N>_<TS>.html             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## File layout

| File                                          | Role                                                                              |
|-----------------------------------------------|-----------------------------------------------------------------------------------|
| `agents/report_builder.py` (new)              | Deterministic HTML builder: timeline, tables, charts, executable recommendations.  |
| `llm/annotation.py` (new)                     | `fill_slots()` — minimal LLM call returning 3 named prose strings as JSON.        |
| `scripts/report_server.py` (new)              | Local Flask server exposing the project's tool registry so recommendations work.  |
| `agents/report_agent.py` (modified)           | `_generate_report_html` / `generate_report_html` short-circuit to deterministic when `REPORT_USE_DETERMINISTIC=1` (default). |
| `agents/report_templates.py` (bug-fixed)      | `FALLBACK_REPORT_TEMPLATE` no longer raises `KeyError` on import.                  |
| `config.py` (modified)                        | New env var `REPORT_USE_DETERMINISTIC` (default: 1).                              |
| `workflow_engine.py` (modified)               | `_run_legacy_report` skips legacy LLM run when deterministic sentinel present.    |
| `tests/test_round19_deterministic_report.py`  | 11 unit tests for the new architecture (10 pass, 1 skip).                        |

## The two new sections

### Event Time Chain

A chronological view of all routing events → traffic anomalies →
ROA / threat-intel findings, sorted by timestamp. Each row shows:

```
[2025-04-01 07:35:00] [ROUTING] [HIJACK] AS3223  AS62390  1.2.3.0/24
[2025-04-01 07:50:00] [TRAFFIC] [DROP]   severity=high z=-4.5
```

Clicking an ASN or prefix chip copies it to the clipboard (for pasting
into a ticket or chat).

### Operational Recommendations (executable)

A table where every row is an action the system can take *right now*
when you click **Execute ▶**. Each button POSTs to the local report
server (`scripts/report_server.py`):

```
POST /api/execute_recommendation
{
  "tool": "as_business_profile",
  "params": {"asn": "3223"},
  "event_id": "leak_voxility_2025"
}
```

The server runs the tool through the project's `ToolRegistry` and
returns the observation + structured data. The response is rendered
under the button as a `<pre>` block. If the server is offline, a
status indicator at the top of the report turns red.

## Running the report server

```bash
# In a separate terminal
python3 scripts/report_server.py --port 7878
```

The server reads from the same `ToolRegistry` used by `chief_agent.py`
and `workflow_engine.py`. Each tool call is wrapped in a worker thread
so Flask stays responsive. CORS headers are set so the report HTML
(served from a local file:// URL) can fetch from `127.0.0.1:7878`.

## Switching back to the LLM path

```bash
REPORT_USE_DETERMINISTIC=0 python3 scripts/smoke_test_1event.py
```

The old LLM-driven path is preserved for debugging / comparison.

## Tests

```bash
pytest tests/test_round19_deterministic_report.py -v
```

Coverage:
- All 12 canonical sections present, in order.
- Time chain is sorted chronologically.
- Every recommendation button references a tool in `EXECUTABLE_TOOLS`.
- `fill_slots()` does not raise on malformed JSON.
- `fill_slots()` defensive scrub redacts ASN/prefix/percent patterns.
- Deterministic builder is **<1s** per event (vs 30–50s for LLM).
- Execute endpoint is wired into the HTML shell.
- `FALLBACK_REPORT_TEMPLATE` imports without `KeyError` (regression).
- Report server is importable, registers `/api/health`,
  `/api/tools`, `/api/execute_recommendation`.

## Migration notes for existing callers

`generate_report_html` and `ReportAgent._generate_report_html` now
default to the deterministic path. To opt back into the LLM path,
set `REPORT_USE_DETERMINISTIC=0`.

The deterministic shortcut publishes a sentinel key
`blackboard[report][deterministic_sentinel] = "v1"` so downstream
callers (notably `workflow_engine._run_legacy_report`) can detect the
shortcut and avoid running the legacy LLM path a second time.

The HTML shell includes a marker comment
`<!-- data-deterministic-template-v1 -->` so other tools can recognise
the new format by inspecting the first 800 bytes.
