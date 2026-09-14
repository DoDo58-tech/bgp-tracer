# BGP Tracer

A multi-agent BGP security analysis system that fuses routing anomalies
(hijacks / leaks / outages) with traffic anomalies (from Cloudflare Radar) to
produce LLM-driven analytical reports.

The system runs in three modes:

- `traffic_first` (default): state-machine workflow that runs traffic and
  routing detectors in parallel, then fuses evidence via a three-card joint
  scorer + HCAF causal attribution.
- `react`: ReAct-style loop where the LLM picks tools. Useful for
  exploratory analysis.
- `--enhanced`: adds a debate agent, online quality gate, and self-correction
  on top of `traffic_first`.

---

## 1. Layout

```
bgp_tracer/
├── chief_agent.py            ← CLI entry point (run events here)
├── workflow_engine.py        ← State machine (traffic_first / enhanced modes)
├── config.py                 ← Env-driven configuration (loads .env)
├── run_v2_events.sh          ← Batch runner for the 18-event suite
│
├── agents/                   ← All LLM-driven and detection agents
│   ├── traffic_agent.py          Cloudflare Radar traffic analysis
│   ├── routing_agent.py          Hijack + leak + outage detection
│   ├── reasoning_agent.py        Cross-domain LLM reasoning
│   ├── report_agent.py           LLM-driven HTML report
│   ├── react_agent.py            ReAct mode orchestrator
│   ├── causal_attribution.py     HCAF causal attribution (MSCBD/CTPR/CIC + Granger)
│   ├── coordination_utils.py     Shared helpers (timestamp, AS lookup, anomaly periods)
│   ├── payload_builder.py        Blackboard payload capping for LLM
│   ├── token_budget.py           Per-stage token budget
│   ├── hypothesis_manager.py     Hypothesis tracking
│   ├── multi_role_classifier.py  LLM role classifier
│   ├── llm_reasoning.py          Shared LLM reasoning helpers
│   ├── llm_wrapper.py            Thin LLM wrapper
│   ├── investigation_supervisor.py  ReAct-loop supervisor
│   ├── auto_probe_executor.py    Auto-execute probing tools
│   ├── core.py                   Agent base class + Blackboard
│   ├── enhanced/                 Enhanced-mode agents
│   │   ├── debate_agent.py           LLMDebateAgent (prosecutor/defense/judge)
│   │   ├── evaluation_loop.py        QualityEvaluator + StageQualityGate
│   │   ├── message_bus.py            AgentMessageBus (pub/sub backbone)
│   │   ├── reactive_decision.py      ReactiveDecisionEngine
│   │   └── multi_report.py           MultiAgentReportAgent
│   └── impl/                     Heavy detector orchestration code
│       ├── traffic_impl.py
│       └── routing_impl.py
│
├── detectors/                ← Pure-Python detectors (no LLM)
│   ├── traffic/                  Cloudflare traffic anomaly detectors
│   │   ├── traffic_detector.py      Public API (CloudflareRadarAPI)
│   │   ├── combined.py              Union detector (statistical + ML + peak/trough)
│   │   ├── detectors.py             Individual detectors (statistical, percentile, IF)
│   │   ├── sudden.py                Sudden drop/jump/post-jump-drop
│   │   ├── sustained.py             Sustained outage / deviation / non-periodic
│   │   ├── periodicity.py           Period detection (FFT/autocorr)
│   │   ├── multi_scale_baseline.py  Multi-scale baseline + CausalCorrelationScorer
│   │   ├── clustering.py            Anomaly window clustering + statistics
│   │   ├── preprocessing.py        Non-aligned preprocessing
│   │   ├── preprocessing_aligned.py Same-weekday-hour alignment
│   │   └── traffic_plotting.py      Traffic comparison chart rendering
│   ├── hijack/                    Origin / forge hijack detection
│   │   ├── hijack_detector.py          High-level API
│   │   ├── hijack_detector_core.py     Core detection logic
│   │   ├── hijack_prefix_processor.py  Prefix trie + target prefix extraction
│   │   ├── hijack_cache_manager.py     SQLite cache for hijack alerts
│   │   ├── hijack_analyzer.py           Aggregation + streaming alert output
│   │   └── hijack_utils.py             Fake-connection detection helpers
│   ├── leak/                      Route-leak detection (PathProb integration)
│   │   └── leak_detector.py
│   ├── outage/                    Route outage detection
│   │   ├── outage_detector.py
│   │   └── extract_event_features.py
│   ├── evidence_chain_builder.py   LLM-driven evidence chain builder
│   └── unified_result.py           Shared result schema (DetectionType, wrap)
│
├── tools/                    ← LLM-callable tools (18 tools registered)
│   ├── tool_registry.py           REGISTRY singleton + @tool decorator
│   ├── tool_implementations.py     Core tools (analyze_traffic, analyze_routing, ...)
│   ├── router_agent.py             LLM-driven tool router
│   ├── session_manager.py          Conversation history + evidence store
│   ├── rpki_validation.py          RPKI ROA validation
│   ├── ip_geolocation.py           IP-to-geolocation lookup
│   ├── as_topology.py              AS topology position in provider-customer graph
│   ├── as_business_profile.py       AS business type inference
│   ├── long_term_baseline.py       Long-term traffic baseline comparison
│   ├── threat_intelligence.py       Threat intel lookup
│   ├── news_context.py             News event context search
│   ├── irr_registry.py             IRR registry lookup
│   └── historical_behavior.py      Historical BGP behavior baseline
│
├── utils/                    ← Shared helpers
│   ├── logger.py                  Structured logger (file + console)
│   ├── helpers.py                 JSON safety, LLM response parsing
│   ├── report_exporters.py        JSON/HTML save, comprehensive report generation
│   └── report_templates.py        Minimal batch-report HTML templates
│
├── llm/                      ← LLM factory + prompts (vendor-agnostic)
│   ├── llm_factory.py             OpenAI-compatible client (llama-index)
│   └── prompt.py                  System/user prompts for all agents
│
├── data/                     ← Data files (gitignored)
│   ├── as2org/                  CAIDA AS-organization data
│   ├── asrel/                   CAIDA AS-relationship data
│   ├── prefix2as/               RIPE NCC prefix-to-AS data
│   ├── updates_rrc00/           RouteViews/RIPE RIS BGP update dumps
│   ├── pathprob/                PathProb model (pathprob.txt)
│   └── traffic/, traffic_plots/  Cloudflare Radar cache + plots
│
├── data_check/               ← Evaluation / ground-truth data
│   ├── hijack/                     Ground-truth hijack event CSVs
│   ├── leak/                       Ground-truth leak event CSVs
│   ├── traffic_anomalies_events/   Ground-truth traffic anomaly subsets
│   └── traffic_plots/              Reference traffic plots
│
├── results/                  ← Runtime outputs (gitignored)
│   ├── html/                    LLM HTML reports
│   ├── json/                    Structured JSON results
│   ├── checkpoints/             Per-event checkpointing (resumable)
│   └── hijack_detection/        Hijack detector raw output
│
└── logs/                     ← Runtime logs (bgp_tracer.log)
```

---

## 2. Install

```bash
pip install -r requirements.txt
# or
conda env create -f environment.yml && conda activate bgp_tracer
```

Copy and configure environment variables:

```bash
cp .env.example .env   # fill in your API keys
# All configuration is done via .env (no hardcoded values in config.py)
```

Required variables in `.env`:

| Variable               | Default                         | Purpose                          |
|-----------------------|---------------------------------|----------------------------------|
| `OPENAI_API_KEY`      | *(empty)*                       | LLM API key                      |
| `OPENAI_BASE_URL`     | `https://uni-api.cstcloud.cn/v1` | LLM API endpoint              |
| `OPENAI_MODEL`        | `qwen3.5`                      | Model name                        |
| `CLOUDFLARE_API_TOKEN`| *(empty)*                      | Cloudflare Radar (traffic data)  |

Optional: `REACT_MAX_ROUNDS`, `REACT_STREAMING_ENABLED`, `MITM_DETECTION_ENABLED`,
`CHECKPOINTING_ENABLED`, `JSON_OUTPUT_ENABLED`, `REPORT_LLM_TIMEOUT_S`,
`REPORT_MAX_TOKENS`, `REPORT_REQUIRE_LLM`, `ES_*`, `RIPESTAT_TOKEN`,
`RIPE_DB_WHOIS_*`.

---

## 3. Run a single event

```bash
python chief_agent.py \
    --asn 12479 \
    --start "2024-01-03 14:45" \
    --end "2024-01-03 18:00" \
    --mode traffic_first
```

Options:

- `--mode react` — LLM-driven ReAct loop (streaming, exploratory)
- `--enhanced` — debate agent + quality gate + self-correction
- `--json-output` — emit full JSON to stdout
- `--user-input "..."` — natural-language event description (auto-parses ASN + times)

---

## 4. Run the v2 event suite (18 events)

```bash
bash run_v2_events.sh traffic_first
# Output: data_check/reality_case/evaluation_results_fresh/
```

Existing JSON files are skipped, so reruns are idempotent.

---

## 5. Architecture overview

```
                          ┌────────────────────┐
                          │   chief_agent.py   │
                          │  (CLI / entry)     │
                          └─────────┬──────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
        mode=traffic_first    mode=react       mode=enhanced
                │                   │                   │
       ┌────────▼────────┐  ┌───────▼────────┐  ┌───────▼───────────┐
       │ workflow_engine │  │ react_agent.py │  │ workflow_engine    │
       │ (state machine) │  │  (LLM picks    │  │ + debate / quality │
       │                 │  │   tools)       │  │   gate / reactive  │
       └────────┬────────┘  └────────────────┘  └────────────────────┘
                │
   ┌────────────┼────────────┐
   │            │            │
┌──▼──┐    ┌────▼────┐  ┌────▼────┐
│traffic   │ routing  │  │evidence │
│agent →   │ agent →  │  │fusion   │
│Cloudflare│ detectors│  │         │
│Radar API │(hijack/  │  │         │
│          │ leak/    │  │         │
│          │ outage)  │  │         │
└──────────┴──────────┘  └─────────┘
                │
                ▼
   ┌─────────────────────────┐
   │  causal_attribution     │ ← HCAF: MSCBD / CTPR / CIC + Granger
   └─────────────────────────┘
                │
                ▼
   ┌─────────────────────────┐
   │  report_agent           │ ← LLM HTML report → results/html/
   └─────────────────────────┘
```

Blackboard (`agents/core.py:Blackboard`) carries typed state between agents;
`payload_builder` enforces size caps before LLM calls;
`token_budget` enforces per-stage spend.

---

## 6. Where to look

| If you want to…                          | Look at                                      |
|------------------------------------------|----------------------------------------------|
| Add a new traffic detector               | `detectors/traffic/` → call from `combined.py` |
| Add a new LLM-callable tool              | `tools/` → register via `@tool` decorator      |
| Change how reports are rendered          | `agents/report_agent.py` + `utils/report_exporters.py` |
| Adjust routing detection thresholds       | `detectors/{hijack,leak,outage}/`            |
| Add a new workflow state                | `workflow_engine.py` (`WorkflowState` enum)   |
| Change LLM configuration                 | `llm/llm_factory.py` + `.env`                |

---

## 7. Recent fixes (2026-09-04)

### 7.1 Restored `correlation_analysis` (P0)

**Root cause**: `report_agent.py` (slim refactor) had a placeholder line
`correlation_analysis = reasoning_result_norm.get("correlation_analysis") or {}`
that depended on the LLM filling it from raw evidence. But the LLM prompt
sends the *unwrapped* traffic/routing, and the helper functions for ΔT,
hypothesis generation, and timeline merging lived only in
`report_agent.before_rewrite.py` (the backup). Net result: `correlation_analysis`
was always `{}` in the final report, leading to LLM-side confessions like
"correlation_analysis empty".

**Fix**: Extracted the analysis pipeline into a new self-contained module
`agents/correlation_analyzer.py` (~600 lines) and called it from `report_agent.py`
*before* the LLM payload is built. The module re-implements:
`extract_traffic_events`, `extract_routing_events`, `compute_delta_t`,
`assign_correlation_level`, `cross_validate_correlation`,
`build_merged_timeline`, `generate_refutable_hypotheses`,
`build_victim_verification`, plus the top-level `analyze_temporal_correlation`
entry point. The output matches the format expected by `_generate_report_html`.

### 7.2 RPKI / ROA validation fallback (P0)

**Root cause**: `roa_validation_result` is normally filled by the
`reason_and_classify` tool via `_validate_roa_status()`. The
`workflow_engine.py` calls `run_reasoning_agent()` (different agent) which
does **not** invoke that tool, so `roa_validation_result` was always empty
in `traffic_first` mode — exactly the kind of "No ROA/RPKI data" gap that
shows up in the Gaps & Limitations section.

**Fix**: Added `_try_fetch_rpki_fallback()` in `report_agent.py` that calls
the public Cloudflare RPKI endpoint (`https://rpki.cloudflare.com/rpki.json`,
no auth) for every hijacked prefix in `origin_hijacked` /
`origin_hijacking`, validates each `(prefix, origin_asn)` pair, and returns
a structured `{success, source, summary, results}` dict. The cached RPKI
data is shared 5-min across calls. Auto-triggers whenever `roa_validation_result`
is empty.

Also fixed the `tool_implementations._fetch_cloudflare_roa` URL (was
404'ing at `api/v1/roas`).

### 7.3 ProbeAgent rebuilt (P4)

**Root cause**: `workflow_engine.py` line 1809 had a comment "ProbeAgent has
been removed; this branch is kept for logging/forward-compat but no longer
performs external probes." Every probe decision silently dropped.

**Fix**: The "probe" branch now imports `AutoProbeExecutor` and dispatches
context-aware recommendations: `rpki_validation`, `check_victim_traffic`,
`bgp_path_analysis` when hijacks detected; `bgp_path_analysis` for leaks.
Results are stored on `context.probe_results`.

### 7.4 Uncovered and still-open

- `affected_prefixes` empty on route leaks — leak detector doesn't yet attach
  the actual prefix list.
- `expected_origin` null — depends on having a current `prefix2as` snapshot
  that maps `130.137.85.0/24 → AS16509`.
- `traffic_anomaly_window` misalignment — propagation is best-effort and
  still requires the upstream detector to write `anomaly_window` to the
  traffic blackboard section.

### 7.5 Killed 5 dead `report_agent.*.py` variants (2026-09-04 14:30)

`report_agent.before_prompt.py`, `report_agent.before_rewrite.py`,
`report_agent_new.py`, `report_agent_simple.py`,
`report_agent_backup_full.py` were all 2,400–3,800 lines of unreferenced
code. None were imported by `chief_agent`, `workflow_engine`,
`react_agent`, `tools/tool_implementations`, or `utils/report_exporters`.
They were vestigial from earlier refactors and only caused confusion
("which file is the canonical one?"). All five moved to
`/tmp/report_agent_archive/`.

The remaining canonical file is `agents/report_agent.py` — Python
pre-computes correlation + RPKI + probes; LLM reasons over the structured
payload and writes HTML.

### 7.6 Added fallbacks for empty `victim_asns`, `threat_intel_result`,
###     `data_availability` (2026-09-04 16:00)

**Root cause**: `reason_and_classify` tool normally fills
`victim_asns` and `threat_intel_result`, but `workflow_engine.py` uses
`run_reasoning_agent()` (a different agent) which doesn't run that tool.
Result: in `traffic_first` mode these two fields were always empty, and
the LLM hallucinates "Victim ASN list empty" / "No threat intel" into
Gaps & Limitations.

**Fix**: Three new helper functions in `report_agent.py`:
- `_infer_victim_asns(routing_result)`: scrapes `origin_hijacked` /
  `forge_hijacked` events for their `victim_as` field.
- `_try_threat_intel_fallback(routing_result, asn)`: builds a thin
  threat-intel dict from routing signals (attacker count, hijack events)
  without making external API calls. Avoids rate-limit noise in
  fallback path.
- `_check_updates_data_availability(routing_result, start, end)`: walks
  `data/updates_rrc00/` for gz + decoded files, returns a coverage dict
  with file counts and explicit `data_source_available=True/False`.
  Cross-checks routing_result for actual events and embeds a hard note
  `"BGP data IS available, do NOT report 'No BGP data'"`.

These flow into the LLM payload automatically; the LLM CoT prompt now
also carries hard rules 3b/3c so the model reads `data_availability`
and `auto_probe_findings` before writing the Gaps section.

### 7.7 ProbeAgent now auto-executes (P0, 2026-09-04 14:30)

The "probe" decision branch in `workflow_engine.py` previously had
a comment `ProbeAgent has been removed`. Now it dispatches context-aware
recommendations to `AutoProbeExecutor`:
- `rpki_validation` for any hijack event
- `check_victim_traffic` for `origin_hijacked` events
- `bgp_path_analysis` for both hijacks and leaks

Findings are stored on `context.probe_results`. The LLM prompt rule 3c
reserves "Operational Recommendations" for actions operators must take,
not "run probes" — those have already run.
