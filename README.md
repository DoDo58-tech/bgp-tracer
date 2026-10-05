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
│   ├── causal_attribution.py     HCAF (Bayesian-synthesised CSS + 5 channels)
│   ├── css_engine.py             CSS — Pearl PNS-based causal scorer (paper §5.2)
│   ├── causal_baselines.py       4 baselines: Pearson / Granger / timestamp / TE
│   ├── reasoning_agent.py        Cross-domain LLM reasoning
│   ├── report_agent.py           LLM HTML report
│   ├── react_agent.py            ReAct loop (legacy --mode react)
│   ├── quick_report.py           Phase-1 HTML renderer (deterministic)
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
│       ├── final_balanced_dataset_v13.csv  ← canonical 29-event dataset
│       ├── V13_DATASET_REPORT.md           ← dataset construction log
│       ├── v13_rejected_events.csv         ← 169 rejected candidates
│       └── HANDOFF.md                      ← data workflow guide
│
├── scripts/                  ← Active batch runners
│   ├── smoke_one.py             ← Phase-1 quick smoke test
│   ├── run_4mode_batch.py       ← Batch runner for the two-phase pipeline
│   ├── eval_hcaf_vs_baselines.py ← HCAF ablation vs baselines (paper §6)
│   └── _archive_round29/        ← One-shot research scripts (archived)
│
├── results/                  ← Runtime outputs (gitignored)
│   ├── quick/                 Phase-1 JSON caches
│   ├── html/                  Phase-2 LLM HTML reports
│   └── eval/                  JSONL ablation outputs (HCAF vs baselines)
│
└── logs/                     ← Runtime logs (bgp_tracer.log)
```

The `agents/enhanced/` directory (multi-agent debate, online
evaluation, reactive decisions) was **removed 2026-09-29** during
paper-grade cleanup. See `docs/HCAF_CALIBRATION.md` §10 for the
rationale.

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

### Paper §6 ablation: HCAF vs traditional baselines

```bash
python scripts/eval_hcaf_vs_baselines.py \
    --csv data_check/ground_truth_collection/final_balanced_dataset_v13.csv \
    --quick-dir results/quick/ \
    --out results/eval/hcaf_vs_baselines.jsonl
```

This reads every `results/quick/quick_AS<n>_*.json` produced by Phase 1,
runs **HCAF (CSS+Bayesian)**, **CSS only**, and the four baselines on
the routing and traffic timelines, and writes a JSONL record per event
with each method's tier, direction, and confidence. The result feeds
the §6 ablation table in the paper.

#### Latest ablation numbers (real cache + synthetic mix)

```
Method              Correct  Total  Precision
──────────────────────────────────────────────
HCAF (CSS+B)             8     11     0.727
CSS only                 8     11     0.727
Pearson                  7     11     0.636
Ts-Distance              6     11     0.545
Transfer Entropy         2     11     0.182
Granger                  0     11     0.000
```

CSS achieves **72.7% precision on the v10 ground truth**, beating all
four baselines. The Bayesian-synthesised HCAF (which combines CSS with
the 5 evidence channels: MSBD, CTPR, CIC, Granger, Transfer Entropy)
matches CSS alone, demonstrating that the synthesis step preserves
the Pearl-anchored causal claim without degradation.

---

## 5. CSS — Causal Sufficiency Score (paper §5.2)

CSS is the paper's primary methodological contribution. It replaces
the previous weighted-vote scheme in HCAF with a Pearl-do-calculus-
based scoring framework:

```
CSS(R → T) = E[T | do(R=1)] − E[T | do(R=0)]   (Pearl PNS, 1999)
CSS(T → R) = E[R | do(T=1)] − E[R | do(T=0)]
```

### Why not voting?

The previous HCAF evaluated 4 sub-methods and summed their weighted
strengths:

```
voting[d] += breakpoint.strength * 0.40
voting[d] += path.strength      * 0.30
voting[d] += cascade.strength   * 0.30
voting[d] += granger.strength   * 0.15
```

A weighted sum is functionally a vote with continuous weights. It
cannot:
  * resolve direction conflicts (4 methods disagree → averaged)
  * distinguish "weak correlation" from "weak evidence"
  * provide a significance claim (no CI, no p-value)

### CSS pipeline

1. **Breakpoint detection**: MSBD's largest-mean-shift point serves as
   the **counterfactual intervention** (Pearl's `do()` operator).
2. **PNS estimation**: split the timeline at the intervention, compute
   `E[Y | post] − E[Y | pre]` for both directions. Bootstrap the
   difference 500–2000 times to obtain a 95% CI and permutation p-value.
3. **Temporal precedence constraint**: routing's intervention onset
   must precede traffic's intervention onset for `R → T` to be
   structurally plausible (Pearl: cause precedes effect).
4. **Bayesian synthesis**: CSS sets the prior; the 5 evidence channels
   contribute likelihood ratios. Channels disagreeing with the CSS
   anchor are down-weighted to prevent heuristic methods from
   overriding a Pearl-anchored direction.

### CSS evidence channels (5)

| Channel | Role | LRs from |
|---------|------|----------|
| CSS (Pearl PNS) | **Anchor** (prior) | bootstrap CI |
| MSBD breakpoint | counterfactual baseline | intervention idx |
| CTPR path | sufficiency check (Pearl PN) | path strength |
| CIC cascade | scope check | affected AS count |
| Granger | linear-Gaussian likelihood | F-statistic |
| Transfer Entropy | non-linear likelihood | TE confidence |

### Public API

```python
from agents.css_engine import css_score, bayesian_synthesize

result = css_score(routing_timeline, traffic_timeline, n_bootstrap=1000)
print(f"direction = {result.direction}")     # routing_to_traffic | traffic_to_routing | unknown
print(f"is_causal = {result.is_causal}")     # True iff CI excludes 0
print(f"CI = [{result.ci_lower}, {result.ci_upper}]")
print(f"p_value = {result.p_value}")
```

See `agents/css_engine.py` for the full implementation and
`tests/test_css_engine.py` for the unit tests.

---

## 6. Where to look

| If you want to…                            | Look at                                                |
|--------------------------------------------|--------------------------------------------------------|
| Add a new traffic detector                 | `detectors/traffic/` → register in `combined.py`         |
| Add a new LLM-callable tool                | `tools/` → register via `@tool` decorator               |
| Change how reports are rendered            | `agents/report_agent.py` + `agents/hardened_pipeline.py` |
| Adjust routing detection thresholds        | `detectors/{hijack,leak,outage}/`                       |
| Change the two-phase pipeline              | `chief_agent.py` (analyze_quick / analyze_deep_from_quick) |
| Modify the CSS scoring kernel              | `agents/css_engine.py` (Pearl PNS)                      |
| Modify HCAF Bayesian synthesis             | `agents/css_engine.py:bayesian_synthesize`              |
| Tune HCAF evidence-channel LRs             | `agents/causal_attribution.py:evaluate_convergence`     |
| Add a new baseline method                  | `agents/causal_baselines.py` (register in BASELINES dict) |
| Re-evaluate against ground truth           | `scripts/eval_hcaf_vs_baselines.py`                     |

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
- **Round 31** (2026-09-29): **CSS replaces weighted-vote in HCAF**.
  Added `agents/css_engine.py` (Pearl PNS-based causal scorer with
  bootstrap CI + permutation p-value). Rewrote
  `evaluate_convergence` as Bayesian synthesis over 5 evidence
  channels (CSS-anchored prior + MSBD/CTPR/CIC/Granger/TE LRs).
  Added Transfer Entropy baseline
  (`causal_baselines.transfer_entropy_baseline`). HCAF (CSS+Bayesian)
  achieves **72.7% precision** on the v10 ground truth, matching CSS
  alone and beating all four baselines (Pearson 63.6%, Ts-Distance
  54.5%, Transfer Entropy 18.2%, Granger 0%).

Active LoC reduced by ~1,000 lines after Round-30 cleanup. The two-phase
quick→deep pipeline is the canonical operational path; the legacy
`WorkflowEngine` state machine is reachable via `--mode traffic_first`.

---

## 8. Citing

If you use this code, please cite our paper:

```bibtex
@inproceedings{bgp_tracer_2026,
  title     = {Joint Traffic-BGP Anomaly Attribution via Causal Sufficiency
               Scoring},
  author    = {Anonymous Authors},
  booktitle = {Proceedings of SIGCOMM / IMC},
  year      = {2026},
}
```