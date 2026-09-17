# Phase 1 Evaluation Plan & Status

**Started**: 2026-09-18 02:26 UTC+8
**Mode**: traffic_first (cheapest)
**Budget**: 950 LLM calls / 5h window

## Goals

1. Run all 4 modes on the 68 ground-truth events
2. Multi-metric evaluation (M1-M6)
3. Long-running with tmux
4. Budget-aware graceful degradation

## Phases

### Phase 1 (Current): traffic_first
- **Scope**: 68 events × traffic_first
- **Budget cost**: ~200 LLM calls (62 fresh × ~3, 6 cached × 0)
- **Expected runtime**: 5-10 hours (62 fresh events × ~5-10 min each)
- **Why first**: Cheapest mode, gives baseline for all 68 events

### Phase 2: react
- **Scope**: 68 events × react
- **Budget cost**: ~480 LLM calls (62 fresh × ~7, 6 cached × 0)
- **Cumulative**: ~680 calls
- **Why second**: Medium cost, allows us to compare reasoning loops

### Phase 3: traffic_first_enhanced
- **Scope**: 68 events × traffic_first_enhanced
- **Budget cost**: ~1020 calls — would exceed remaining budget!
- **Reduced scope**: ~18-20 events (whatever budget allows)
- **Why third**: Tests the "debate" enhancement

### Phase 4: react_enhanced
- **Scope**: As many as budget allows
- **Budget cost**: ~21 calls/event
- **Why last**: Most expensive, only if budget remains

## Multi-Metric Framework

### M1: Detection Accuracy
- Binary classification: agent detects anomaly vs. ground truth says anomaly
- Per-event-type: hijack / leak / outage / no_incident
- Metrics: precision, recall, F1, accuracy, per-type breakdown

### M2: Causal Direction Agreement
- Heuristic parsing of LLM output for direction keywords
- Match against ground_truth_v5.csv `causal_direction` field
- Per-direction agreement rates

### M3: Scientific Soundness
- Granger stationarity checks (ADF + differencing)
- HCAF method consensus (MSBD, CTPR, CIC, Granger)
- Pass/fail rate per mode

### M4: Report Quality
- Section completeness (8 required sections)
- Data citation count (mentions of ASN, prefix, evidence)
- Image/table presence
- HTML balance check
- Aggregate content_score (0-1)

### M5: Efficiency
- Wall-clock time per event
- LLM tokens consumed
- Report size

### M6: Robustness
- Budget exhaustion events
- Fallback reason distribution
- Timeout occurrences

## Output

After each phase, results are written to:
- `data_check/evaluation/run_<timestamp>/metrics.json` — raw metrics
- `data_check/evaluation/run_<timestamp>/report.md` — rendered report
- Cross-phase merge: `python3 scripts/merge_eval_runs.py data_check/evaluation/run_*/metrics.json`

## Files Created

- `scripts/run_full_evaluation.py` — full evaluation framework
- `scripts/render_eval_report.py` — single-run report renderer
- `scripts/merge_eval_runs.py` — multi-phase report merger
