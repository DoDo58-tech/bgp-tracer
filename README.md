# BGP Tracer — Joint Traffic-BGP Anomaly Attribution

A two-phase analyzer that fuses control-plane routing telemetry (RIPE RIS /
RouteViews BGPStream) and data-plane traffic dynamics (Cloudflare Radar)
to attribute Internet anomalies (hijacks / leaks / outages).

This is the implementation of **PADDLE** (Paired Displacement,
Difference-in-differences, with Ledger Evidence), and serves as the
artifact for our paper submission.

> **Paper focus**: a *novel* causal-attribution method for joint
> traffic-routing correlation. PADDLE anchors on the data plane's
> trough onset, measures the control plane's displacement there against
> the same clock slots on the preceding days, and commits a direction
> only when four vetoes pass --- precedence, exclusivity against the
> same-clock placebo null, provenance scope, and directional congruence.
> See `agents/paddle_attribution.py` for the estimator and
> `agents/paddle_runtime.py` for the production adapter.

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
      ├─► PADDLE ──────────────── the only causal estimator  │
      │     (paired displacement vs the same-clock null;       │
      │      four vetoes — paper §4)                           │
      │                                                       │
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

---

## 3. Layout

```
bgp_tracer/
├── chief_agent.py            ← CLI entry point (--mode quick|deep|auto)
├── workflow_engine.py        ← State machine (legacy --mode traffic_first)
├── config.py                 ← Env-driven configuration (loads .env)
│
├── agents/
│   ├── traffic_agent.py          Cloudflare Radar traffic analysis
│   ├── routing_agent.py          Hijack + leak + outage detection
│   ├── correlation_analyzer.py   ΔT computation + hypothesis generation
│   ├── paddle_attribution.py     PADDLE — the causal estimator (paper §4)
│   ├── paddle_runtime.py         PADDLE's production adapter
│   ├── control_plane.py          The routing side as a rate series
│   ├── control_plane_archive.py  The target's own announcements, from the archive
│   ├── reasoning_agent.py        Cross-domain LLM reasoning
│   ├── report_agent.py           LLM HTML report
│   ├── react_agent.py            ReAct loop (legacy --mode react)
│   ├── hardened_pipeline.py      Report section post-processing
│   ├── hypothesis_manager.py     Hypothesis tracking
│   ├── multi_role_classifier.py  LLM role classifier
│   ├── payload_builder.py        Blackboard payload capping for LLM
│   ├── token_budget.py           Per-stage token budget
│   ├── llm_reasoning.py          Shared LLM reasoning helpers
│   ├── llm_wrapper.py            Thin LLM wrapper
│   ├── investigation_supervisor.py  ReAct-loop supervisor
│   ├── auto_probe_executor.py    Auto-execute probing tools
│   └── core.py                   Agent base class + Blackboard
│
├── detectors/                ← Pure-Python detectors (no LLM)
│   ├── traffic/                  Cloudflare traffic anomaly detectors
│   ├── hijack/                   Origin / forge hijack detection
│   ├── leak/                     Route-leak detection
│   └── outage/                   Route outage detection
│
├── tools/                    ← LLM-callable tools (18 tools registered)
│
├── utils/                    ← Shared helpers
│
├── llm/                      ← LLM factory + prompts (vendor-agnostic)
│
├── data/                     ← Data files (gitignored)
│   ├── as2org/                  CAIDA AS-organization data
│   ├── asrel/                   CAIDA AS-relationship data
│   ├── prefix2as/               RIPE NCC prefix-to-AS data
│   ├── updates_rrc00/           RouteViews/RIPE RIS BGP update dumps
│   └── pathprob/                PathProb model (pathprob.txt)
│
├── data_check/               ← Evaluation / ground-truth data
│   └── ground_truth_collection/
│       ├── final_ground_truth.csv         ← canonical 17-event dataset
│       ├── final_ground_truth_build.json  ← dataset construction log
│       ├── final_ground_truth_rejected.csv
│       └── seed_events.py
│
├── scripts/                  ← Active batch runners
│   ├── run_4mode_batch.py       ← Batch runner for the two-phase pipeline
│   ├── eval_paddle_corpus.py    ← PADDLE on the canonical corpus (paper §6)
│   ├── paddle_calibration.py    ← Size, power and common-shock calibration
│   ├── paddle_coverage_on_caches.py ← Coverage over every cached window
│   ├── component_ablation.py    ← Component ablation (paper appendix)
│   ├── verify_paper.py          ← Runs every paper-number gate
│   └── check_paper_numbers.py   ← Headline numbers vs the artefacts
│
├── results/                  ← Runtime outputs (gitignored)
│   ├── quick/                 Phase-1 JSON caches
│   ├── html/                  Phase-2 LLM HTML reports
│   └── eval/                  PADDLE corpus, calibration and ablation artefacts
│
└── logs/                     ← Runtime logs (bgp_tracer.log)
```

The `agents/enhanced/` directory (multi-agent debate, online
evaluation, reactive decisions) was **removed 2026-09-29** during
paper-grade cleanup.

---

## 4. Running

### Single event

```bash
# Phase 1 (deterministic, ~60s, no LLM)
python chief_agent.py --asn 12479 --start "2024-01-03 14:45" \
    --end "2024-01-03 18:00" --mode quick

# Phase 2 (LLM reasoning + HTML report)
python chief_agent.py --asn 12479 --start "2024-01-03 14:45" \
    --end "2024-01-03 18:00" --mode deep \
    --quick-cache results/quick/quick_AS12479_*.json
```

### Full auto (Phase 1 + Phase 2 in subprocess)

```bash
python chief_agent.py --asn 12479 --start "2024-01-03 14:45" \
    --end "2024-01-03 18:00" --mode auto
```

### Batch run

```bash
bash scripts/launch_4mode_eval.sh
# Output: results/html/llm_report_AS*.html
```

### Paper §6: PADDLE on the canonical corpus and its operating curve

```bash
# The estimator on every labelled event, through the production path.
python scripts/eval_paddle_corpus.py

# Size, power and common-shock behaviour on synthetic geometry.
python scripts/paddle_calibration.py

# Coverage over every cached window in the tree.
python scripts/paddle_coverage_on_caches.py
```

`eval_paddle_corpus.py` calls the same `agents.paddle_runtime.run_paddle`
the chief agent calls, so the measured coverage is the coverage the
system actually has. `paddle_calibration.py` plants a routing pulse
followed by a traffic drop at a known lag, and counts how often the
estimator commits and how often the committed direction is right.

#### Latest operating characteristics

```
Size (no planted effect), 400 windows per autocorrelation level
  rho=0.0   0.0% committed
  rho=0.5   0.0% committed
  rho=0.8   0.0% committed

Power (planted routing pulse then traffic drop), 200 windows per cell
  12 lag-drop cells, 2,342 commitments out of 2,400
  100% of the commitments name the correct direction

Common shock (both sides move together), 200 windows per level
  simultaneous pulse          2.0% false commitments
  simultaneous, 1-bucket skew 6.0% false commitments
```


---

## 5. PADDLE — the causal estimator (paper §4)

PADDLE is the only causal estimator in the codebase. It answers a
physical question: when the data plane deviated, had the control plane
already deviated, and by more than it does at this hour on an ordinary
day?

### The shape of the method

```
anchor    the data plane's trough onset (the first observation of the
          deepest sustained fall)
measure   the control plane's paired displacement at that moment:
          its rate around the anchor against the same clock slots on
          the preceding days, summarised by medians
null      the same measurement applied to ordinary days, split by
          direction, giving an empirical tail probability
commit    only when all four vetoes pass
```

The four vetoes are tests, not scores, and the conjunction is logical:
no weight, prior or floor binds them, and a refusal names the veto that
produced it.

| Veto | Question | Refusal |
|-------|----------|---------|
| V1 precedence | had the control plane already moved? | `inadmissible_precedence` |
| V2 exclusivity | is this more than an ordinary day shows? | `not_exclusive` |
| V3 provenance | do the two sides cover the same entities? | `provenance_disjoint` |
| V4 congruence | do the two movements point the same way? | `mirror_contradicted` |

### Why no voting, and why no earlier methods

The estimator that preceded PADDLE combined several sub-methods by
summing their weighted strengths. A weighted sum is functionally a vote
with continuous weights: it cannot resolve a direction conflict, it
cannot distinguish weak correlation from weak evidence, and it cannot
support a significance claim. PADDLE replaces all of that with a
single paired measurement and a conjunction of vetoes, and the earlier
methods --- Granger causality, transfer entropy, MSBD, CTPR, CIC and
the weighted-vote scheme --- were removed from the tree in commit
`06e0ffb`. The pre-cleanup state is preserved on the
`origin/backup/pre-cleanup-20261031` branch.

### Public API

```python
from agents.paddle_attribution import attribute

verdict = attribute(control_series, traffic_observations)
print(verdict.direction)     # routing_to_traffic | traffic_to_routing | unknown
print(verdict.reason)        # committed | not_exclusive | ...
print(verdict.as_dict())
```

See `agents/paddle_attribution.py` for the implementation and
`tests/test_paddle_attribution.py` for the unit tests.

---

## 6. Where to look

| If you want to…                            | Look at                                                |
|--------------------------------------------|--------------------------------------------------------|
| Add a new traffic detector                 | `detectors/traffic/` → register in `combined.py`         |
| Add a new LLM-callable tool                | `tools/` → register via `@tool` decorator               |
| Change how reports are rendered            | `agents/report_agent.py` + `agents/hardened_pipeline.py` |
| Adjust routing detection thresholds        | `detectors/{hijack,leak,outage}/`                       |
| Change the two-phase pipeline              | `chief_agent.py` (analyze_quick / analyze_deep_from_quick) |
| Modify the causal estimator                 | `agents/paddle_attribution.py`                          |
| Change the routing-side representation     | `agents/control_plane.py` + `agents/control_plane_archive.py` |
| Re-evaluate against ground truth           | `scripts/eval_paddle_corpus.py`                         |
| Re-measure size, power and common shocks   | `scripts/paddle_calibration.py`                         |
| Check the paper's numbers against the data | `python scripts/verify_paper.py`                        |

---

## 7. Paper-grade status (2026-09-29)

The following cleanup and methodology rounds have been applied for
SIGCOMM/IMC submission:

- **Round 29** (2026-09-29): Deleted `agents/enhanced/` (3,742 LoC) and
  all `if self.enhanced:` branches. Replaced stub no-ops with active
  single-agent paths.
- **Round 30** (2026-09-29): Deleted 9 `if False:` blocks in
  `workflow_engine.py`, the `_collect_enhanced_artefact_rows` function
  in `report_agent.py` (~63 LoC), the `_SECTION_TITLE_ENHANCED` regex,
  the `_run_legacy_report` enhanced payload injection, the
  `enhanced=` parameter propagation chain across 4 files.
- **Round 30** (2026-09-29): Archived 30 one-shot research scripts to
  `scripts/_archive_round29/`.
- **Round 30** (2026-09-29): Removed 5 orphaned config keys
  (`WORKFLOW_TRACE_ENABLED`, `WORKFLOW_EVENT_DRIVEN_ENABLED`,
  `WORKFLOW_MAX_REACTIVE_DECISIONS`, `BGP_TRACER_HCAF_BASELINES_ENABLED`,
  `WORKFLOW_ANALYSIS_MODE`).
- **Round 32** (2026-10-31): **PADDLE replaces the multi-method
  synthesis.** The earlier estimator combined MSBD, CTPR, CIC, Granger
  and transfer entropy by summing weighted strengths; those modules were
  removed in commit `06e0ffb` and the pre-cleanup state was preserved on
  the `origin/backup/pre-cleanup-20261031` branch. PADDLE measures one
  paired displacement against the same-clock null and admits a direction
  only when four vetoes pass.
- **Round 33** (2026-11-02): **The trough anchor is the onset of the
  deepest sustained fall**, rather than the first observation that
  crossed the fall floor. A noise wobble could previously steal the
  anchor from a real drop, and the estimator then measured the control
  plane at the wrong moment. Power over the twelve planted lag--drop
  cells rose from 701 to 2,342 commitments out of 2,400, with every
  commitment still correct.

Active LoC reduced by ~1,000 lines after Round-30 cleanup. The two-phase
quick→deep pipeline is the canonical operational path; the legacy
`WorkflowEngine` state machine is reachable via `--mode traffic_first`.

---

## 8. Citing

If you use this code, please cite our paper:

```bibtex
@inproceedings{bgp_tracer_2026,
  title     = {Joint Traffic-BGP Anomaly Attribution via Paired
               Displacement and a Same-Clock Null},
  author    = {Anonymous Authors},
  booktitle = {Proceedings of SIGCOMM / IMC},
  year      = {2026},
}
```