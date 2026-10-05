# BGP Tracer — Joint Traffic-BGP Anomaly Attribution

A two-phase analyzer that fuses control-plane routing telemetry (RIPE RIS /
RouteViews BGPStream) and data-plane traffic dynamics (Cloudflare Radar)
to attribute Internet anomalies (hijacks / leaks / outages).

This is the implementation of **CSS** (Causal Sufficiency Score) inside
the **HCAF** (Hybrid Causal Attribution Framework), and serves as the
artifact for our paper submission.

> **Paper focus**: a *novel* causal-attribution method (CSS, based on
> Pearl's do-calculus / Probability of Necessity and Sufficiency) for
> joint traffic-routing correlation. CSS replaces the previous
> weighted-vote scheme in HCAF. We benchmark against four traditional
> baselines (Pearson lag, Granger causality, timestamp distance,
> Transfer Entropy). See `agents/css_engine.py` for the core
> implementation and `scripts/eval_hcaf_vs_baselines.py` for the
> ablation driver.

---

## 1. Two-Phase Architecture

The system runs in **two phases**. Phase 1 is deterministic and fast (no
LLM); Phase 2 is the LLM-driven reasoning stage.

```
┌──────────────────────────────────────────────────────────────┐
│  Phase 1: QUICK (--mode quick, ~60s, 0 LLM calls)            │
│                                                              │
│   chief_agent.analyze_quick(asn, start, end)                 │
│      │                                                       │
│      ├─► TrafficAgent ─── Cloudflare Radar timeseries        │
│      │     anomaly_count, peak_trough_drop_pct               │
│      │                                                       │
│      └─► RoutingAgent ── BGPStream (RRC00)                   │
│            origin_hijack / forge_hijack / route_leak /       │
│            outage detectors                                  │
│                                                              │
│   → results/quick/quick_AS<n>_<timestamp>.json              │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼ (cache file passed via --quick-cache)
┌──────────────────────────────────────────────────────────────┐
│  Phase 2: DEEP (--mode deep, LLM reasoning + HTML report)    │
│                                                              │
│   chief_agent.analyze_deep_from_quick(quick_cache)           │
│      │                                                       │
│      ├─► CorrelationAnalyzer ── ΔT computation, hypothesis   │
│      │     generation, timeline merging                       │
│      │                                                       │
│      ├─► CausalAttribution ─── HCAF (CSS + 5 evidence channels: │
│      │     MSBD / CTPR / CIC / Granger / Transfer Entropy,      │
│      │     Bayesian-synthesised — paper §5.2 primary)          │
│      │                                                       │
│      ├─► CausalBaselines ──── Pearson lag / Granger /        │
│      │     timestamp distance / Transfer Entropy              │
│      │     (paper §6 ablation, 4 baselines total)            │
│      │                                                       │
│      └─► ReportAgent ──────── LLM HTML report                │
│            results/html/llm_report_AS<n>_<timestamp>.html     │
└──────────────────────────────────────────────────────────────┘
```

For batch runs use `--mode auto`, which runs Phase 1 synchronously then
spawns Phase 2 as a subprocess with the cache file.

The `--mode traffic_first` legacy path remains available and routes
through the `WorkflowEngine` state machine; the new two-phase path is the
recommended operational mode.

---

## 2. Installation

```bash
pip install -r requirements.txt
# or
conda env create -f environment.yml && conda activate bgp_tracer
```

Configure environment:

```bash
cp .env.example .env
# All configuration is done via .env (no hardcoded values in config.py)
```

Required `.env` entries:

| Variable               | Default                         | Purpose                          |
|------------------------|---------------------------------|----------------------------------|
| `OPENAI_API_KEY`       | *(empty)*                       | LLM API key                      |
| `OPENAI_BASE_URL`      | `https://uni-api.cstcloud.cn/v1`| LLM API endpoint                  |
| `OPENAI_MODEL`         | `qwen3.5`                       | Model name                       |
| `CLOUDFLARE_API_TOKEN` | *(empty)*                       | Cloudflare Radar (traffic data)  |

Optional: `REACT_MAX_ROUNDS`, `MITM_DETECTION_ENABLED`,
`REPORT_LLM_TIMEOUT_S`, `REPORT_MAX_TOKENS`, `ES_*`, `RIPESTAT_TOKEN`,
`RIPE_DB_WHOIS_*`.
