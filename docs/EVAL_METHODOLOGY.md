# Multi-Metric Evaluation: Design & Methodology

## Overview

This document describes the multi-metric evaluation framework for the BGP anomaly analyzer's 4 modes:
- `traffic_first` — traffic analysis first, then routing
- `traffic_first_enhanced` — traffic_first + LLM debate + online evaluation
- `react` — reactive reasoning loop (multi-round)
- `react_enhanced` — react + LLM debate + online evaluation

## Evaluation Dataset

**Ground truth**: `ground_truth_v5.csv` (68 events)
- 20 hijacks, 14 leaks, 12 outages, 22 no_incident
- Sources: Cloudflare official, BGPStream hijack, BGPStream leak
- Each event has: causal_direction, AS victim/attacker, traffic/routing scores, confidence
- 10 events >24h window are excluded (would timeout): `bgpstream_hijack_85798`, `bgpstream_hijack_109666`, etc.
- Effective dataset: **58 actionable events**

## Metric Categories

### M1: Detection Accuracy

**What it measures**: Does the system correctly classify events?

**Method**: Binary classification per mode × event
- `gt_has_anomaly = event_type != "no_incident"`
- `pred_has_anomaly = hijack_detected OR leak_detected OR outage_detected`

**Metrics**:
- Precision, Recall, F1, Accuracy
- Per-event-type breakdown (hijack / leak / outage)

**Limitation**: Current `DetectionResult` dataclass doesn't yet parse detection flags from logs. Detection metrics will show 0 until detection output parsing is added.

### M2: Causal Direction Agreement

**What it measures**: Does the LLM-generated report's implied causal direction match ground truth?

**Method**: Heuristic keyword matching in HTML report
- `routing → traffic`: "routing caused traffic", "routing → traffic"
- `traffic → routing`: "traffic caused routing", "traffic → routing"
- `bidirectional`: "bidirectional", "mutual"
- `none`: "no causal", "no clear", "no incident"

**Metrics**: Agreement rate per mode, per ground-truth direction

**Limitation**: Keyword matching is approximate. LLM reports may use varied phrasing.

### M3: Scientific Soundness

**What it measures**: Did the HCAF causal attribution pipeline complete without errors?

**Method**: Log analysis for stationarity check outcomes
- Look for "granger" + "stationarity" keywords in logs
- Count pass vs fail

**Metrics**: Stationarity check pass rate

### M4: Report Quality

**What it measures**: Is the LLM-generated HTML report well-formed and content-rich?

**Method**: Automated HTML + text analysis of each report file

**Metrics**:
| Metric | Method |
|--------|--------|
| Section completeness | 8 required section keywords in text |
| Data citations | Count of "evidence:", ASN mentions, prefix mentions |
| Images | `<img>` tag count |
| Tables | `<table>` tag count |
| HTML balance | Opening vs closing tag match |
| LLM-driven | No "fallback" keyword in text, size > 50KB |
| Content score | Weighted composite of above |

### M5: Efficiency

**What it measures**: Resource consumption

**Metrics**:
- Wall-clock time per event
- LLM tokens per event (from log extraction)
- Report size (KB)

### M6: Robustness

**What it measures**: Does the system fail gracefully?

**Metrics**:
- Fallback rate (fallback vs LLM-driven)
- Timeout count
- Budget exhaustion count
- Fallback reason distribution

## Running the Evaluation

### Phase 1: traffic_first (all 58 events)
```bash
tmux new-session -d -s eval_phase1 -c /data/bgp_tracer \
  'PYTHONPATH=/data/bgp_tracer BGP_TRACER_PARALLEL_CHUNKS=1 \
   python3 -u scripts/run_full_evaluation.py \
     --budget-aware --max-calls-this-run 700 \
     --modes traffic_first --max-duration-hours 24 \
     2>&1 | tee logs/eval_runs/phase1_traffic_first_$(date +%Y%m%d_%H%M%S).log'
```

### Phase 2: react (all 58 events)
```bash
# Run after Phase 1 completes (or when budget refreshes)
bash scripts/_launch_phase2.sh
```

### Merge Results
```bash
python3 scripts/merge_eval_runs.py \
  data_check/evaluation/run_*/metrics.json \
  -o data_check/evaluation/FINAL_REPORT.md
```

## Expected Outcomes

### traffic_first
- Baseline: fast, deterministic-ish, lower quality prose
- Detection: moderate (no reasoning loop)
- Report quality: good (traffic + routing data tables)
- Speed: fastest (~3 min/event)

### traffic_first_enhanced  
- Baseline + debate + probe: higher quality
- Detection: same as traffic_first (debate doesn't change detection)
- Report quality: higher (debate generates opposing views)
- Speed: slower (~15 min/event, 5× budget calls)

### react
- Multi-round reasoning loop: better causal analysis
- Detection: potentially better (reasoning loop can self-correct)
- Report quality: best (iterative refinement)
- Speed: medium (~7 min/event)

### react_enhanced
- react + debate: best quality but most expensive
- Detection: potentially best
- Report quality: highest
- Speed: slowest (~15 min/event)

## Current Limitations

1. **Detection parsing not implemented**: `DetectionResult.hijack_detected`, etc. are None. M1 will show 0 until logs are parsed.
2. **M2 keyword matching is approximate**: LLM may use varied phrasing for direction.
3. **M3 relies on log keywords**: Not a true scientific evaluation of Granger correctness.
4. **Budget constraint**: 950 calls / 5h means not all modes can run on all events. Enhanced modes only run on subset.
5. **Ground truth has 0 detection labels for LLM reports**: We don't have ground-truth detection verdicts — only causal direction labels. Detection accuracy must rely on log parsing.
