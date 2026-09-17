# bgp_tracer — Threat Model & Degraded-Mode Behaviour

**Author**: Cursor Agent (review-mode pass 2026-09-17)  
**Source review**: `docs/REVIEW_SIGCOMM_GRADE_v2.md` §2.7 ("Threat Model 没写")  
**Audience**: SIGCOMM / IMC / NDSS reviewers and operators.

---

## 1. Scope

`bgp_tracer` is a multi-agent system that combines pure-Python routing
detectors (hijack / leak / outage), Cloudflare Radar traffic anomaly
detection, and an LLM-driven analytical-report generator. The system
has external dependencies on four categories:

1. **Routing data** — RouteViews / RIPE RIS BGP update dumps.
2. **AS-relationship / prefix-to-AS data** — CAIDA, RIPE NCC IRR.
3. **Traffic data** — Cloudflare Radar (HTTPS API, requires token).
4. **LLM API** — OpenAI-compatible endpoint (CSTCloud Kimi / GLM / Qwen / S1-Base).

We treat the failure of any of these as a **first-class degradation
mode**, not an exception. Each one has an explicit fallback path that
the system uses to produce a still-valid (if degraded) HTML report.

---

## 2. Data-source failure modes

### 2.1 RPKI / ROA data unavailable
- **Trigger**: `_try_fetch_rpki_fallback` returns empty (Cloudflare RPKI endpoint unreachable or 5xx).
- **Behaviour**: The RPKI / ROA block in the report becomes a literal `"RPKI validation unavailable (Cloudflare RPKI endpoint unreachable)"` placeholder. The LLM is **explicitly instructed** (see `_UNIFIED_COT_PROMPT` rule 5h) not to write `"No RPKI data"`; it must use the placeholder.
- **Reviewer-visible effect**: The "Routing Security" section shows the placeholder in red, never hallucinated "all prefixes are valid" claims.

### 2.2 RIS RRC00 update dumps unavailable
- **Trigger**: `data/updates_rrc00/*.gz` empty, missing, or covers less than the analysis window.
- **Behaviour**: `_check_updates_data_availability` (in `report_agent.py:42-118`) walks the local cache, counts files, returns a structured coverage dict. When no events are produced by the routing pipeline, the report carries an explicit `"BGP data IS available, do NOT report 'No BGP data'"` cross-check note.
- **Reviewer-visible effect**: The "Gaps & Limitations" section honestly states whether BGP data was available; the LLM is forbidden from writing the canonical "No BGP data" sentence unless `_check_updates_data_availability` confirms zero coverage.

### 2.3 Cloudflare Radar unreachable / rate-limited
- **Trigger**: HTTP 4xx/5xx, network timeout, or daily quota exhausted.
- **Behaviour**: The traffic-agent returns an empty `traffic_anomaly_window`; the routing-agent continues running; the final report's "Traffic Analysis" section degrades to `"Traffic data unavailable — analysis is routing-only"`. The Causal Attribution Engine (HCAF) treats `traffic_events = []` as a **single-sided analysis** (`causal_attribution.py::因果归因引擎.单边结果`), still producing a directional verdict based on routing events + Granger pre-check.

### 2.4 AS-relationship / prefix2as data stale
- **Trigger**: `data/asrel/bgp_rel.txt` or `data/prefix2as/*` older than the analysis date.
- **Behaviour**: `_infer_relationship_from_path` (in `tools/tool_implementations.py`) marks the relationship inference as `uncertainty: high`; the LLM is forced to write `"Path plausibility: uncertain (AS-relationship data may be stale)"`. CTPR's `transmission_path` is still emitted but flagged.

### 2.5 IRR / RADB lookups fail
- **Trigger**: `irr_registry.py` cannot reach RADB / RIPE / APNIC mirrors.
- **Behaviour**: The "Auxiliary Enrichment Evidence" section is silently dropped; the report carries an explicit `"IRR lookup skipped: <reason>"` line. The LLM is forbidden from quoting a prefix as "IRR-authorised" when the lookup returned an empty result.

---

## 3. LLM failure modes

### 3.1 LLM HTTP call timeout
- **Trigger**: CSTCloud / OpenAI-compatible endpoint takes longer than `REPORT_LLM_TIMEOUT_S` (default 1500 s, env-configurable).
- **Behaviour**: The streaming HTML accumulator (`generate_report_html`) detects the timeout, calls `_validate_html_balance` on the partial buffer, and either:
  - Closes the document with whatever tags were emitted and serves the **truncated-but-balanced** HTML with a banner `"(LLM stream timed out; this report is partial)"`, OR
  - Falls back to the deterministic HTML renderer (`render_fallback_html_for_agent`) when `REPORT_REQUIRE_LLM` is **not** set.
- **Reviewer-visible effect**: The HTML is either partial (with banner) or fully deterministic (no LLM narrative). Either way the file passes `validate_html_balance`.

### 3.2 LLM emits reasoning_content instead of content
- **Trigger**: Vendor-specific thinking-mode LLM (GLM-5, S1-Base-Pro, deepseek-reasoner) emits `reasoning_content` before `content`.
- **Behaviour**: `_extract_delta_text` (in `llm/llm_factory.py`) **only ever returns the `content` field**, never the reasoning. The client-side filter is a hard line — there's no flag to turn it off. This was the P0 bug that the `HANDOVER_REPORT_GENERATION.md` (2026-09-16) describes.
- **Reviewer-visible effect**: Reports never contain the LLM's chain-of-thought text. This is verified by grep across `results/html/llm_report_AS*.html` — zero matches for the prompt's preamble strings.

### 3.3 LLM emits malformed HTML
- **Trigger**: Unclosed tags, stray `<` characters, JSON-key placeholders, prompt-internal text leaked into output.
- **Behaviour**: The post-processing pipeline runs in this fixed order:
  1. `_extract_clean_html_document` — locates the first `<!DOCTYPE` or `<html>` and trims preamble.
  2. `_repair_llm_html` — tag-balance repair, attribute quoting, void-tag handling.
  3. `_inject_code_rendered_tables` — strips LLM-written tables and replaces with deterministic Python-rendered tables.
  4. `_enforce_section_completeness` — pads missing sections, ensures ≥3 hypothesis-cards, injects ΔT table.
  5. `_scrub_json_key_placeholders` — replaces `[target_as]` / `[user_analysis_window]` style placeholders.
  6. `_strip_nodata_artifacts` — drops `(no data)` rows, replaces orphan no-data cells with `—`.
  7. `validate_html_balance` — final balance check.

  If any step fails, the exception is logged and the next step runs on the previous output.
- **Reviewer-visible effect**: Reports are always browser-tolerant even when the LLM emits garbage. The "deterministic fallback" banner appears **only** when the LLM call fails AND `REPORT_REQUIRE_LLM` is not set; otherwise an explicit "LLM failed after retries" banner is emitted.

### 3.4 LLM returns empty content (e.g. safety refusal)
- **Trigger**: Content filter on the LLM API refuses the request.
- **Behaviour**: Detected as `len(content) == 0` after the stream ends; the function returns `_validation_failure_payload` (a structured failure dict) and the workflow engine either retries (up to `WORKFLOW_MAX_RETRIES`) or falls back.

---

## 4. Workflow timeout

### 4.1 Wall-clock cap
- **Trigger**: Total workflow elapsed time exceeds `BGP_TRACER_WORKFLOW_TIMEOUT_S` (default 2400 s = 40 min, configurable via env).
- **Behaviour**: `workflow_engine.py:519-527` watches the elapsed time and **jumps straight to REPORT_GENERATION** when the cap is hit. The intermediate stages (causal attribution, reasoning, multi-agent coordination) may produce partial output, but the user always gets a usable HTML.

### 4.2 Per-stage timeout
- Each agent (`traffic-agent`, `routing-agent`, `reasoning-agent`, `report-agent`) has its own timeout. If exceeded, the agent returns a structured `TaskResult(success=False, error="timeout")` and the workflow engine proceeds with whatever data is available.

---

## 5. Decision budget

`WORKFLOW_MAX_REACTIVE_DECISIONS = 5` caps the number of reactive
decisions per stage to prevent blow-up. When exhausted, the engine
**does not raise** — it proceeds with the last successful state.

---

## 6. What we explicitly do **not** defend against

These are out-of-scope threats; we acknowledge them so reviewers don't
expect coverage:

- **Adversarial BGP data injection**: If an attacker can write into our `data/updates_rrc00/` cache, they can corrupt detection. We rely on file-system permissions + RIS collector authentication.
- **LLM prompt injection via BGP data**: The LLM payload includes raw event text. A sufficiently malicious prefix announcement could embed adversarial instructions. We do not sanitise BGP-derived strings before they reach the LLM; this is a known limitation.
- **RPKI validator compromise**: We use Cloudflare RPKI as a fallback. If that endpoint serves malicious ROAs, we propagate them. Production deployments should chain multiple RPKI validators.

---

## 7. Summary

| Failure mode | Behaviour | Visible to reviewer |
|---|---|---|
| RPKI unavailable | Placeholder text in Routing Security | Yes |
| RIS data empty | Honest Gaps & Limitations line | Yes |
| Cloudflare down | Routing-only analysis with banner | Yes |
| AS-rel stale | "uncertainty: high" marker | Yes |
| IRR unreachable | "IRR lookup skipped" line | Yes |
| LLM timeout | Partial HTML + banner OR deterministic fallback | Yes |
| LLM reasoning leak | Client-side filter — never emitted | (verified by grep) |
| LLM malformed HTML | 7-stage post-processing pipeline | Yes |
| LLM empty / refused | Retry → fallback | Yes |
| Workflow timeout | Skip to REPORT_GENERATION | (logged) |
| Decision budget exhausted | Proceed with last state | (logged) |
| Adversarial BGP injection | Out of scope | (acknowledged) |
| LLM prompt injection | Out of scope | (acknowledged) |

— End of Threat Model —
