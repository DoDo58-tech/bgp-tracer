#!/bin/bash
# Launch Phase 2: react mode on all events
#
# This continues from Phase 1 (traffic_first). Phase 1 used ~3 LLM calls per
# event, so ~174 calls total. Budget remaining should be ~776.
#
# react mode uses ~7 LLM calls per event, so:
#   - 58 events × 7 = 406 calls → budget: 776 - 406 = 370 remaining
#
# Usage:
#   tmux new-session -d -s eval_phase2 -c /data/bgp_tracer \
#     'PYTHONPATH=/data/bgp_tracer BGP_TRACER_PARALLEL_CHUNKS=1 \
#      python3 -u scripts/run_full_evaluation.py \
#        --budget-aware --max-calls-this-run 400 \
#        --modes react \
#        --max-duration-hours 24 \
#        2>&1 | tee logs/eval_runs/phase2_react_$(date +%Y%m%d_%H%M%S).log'

cd /data/bgp_tracer
PYTHONPATH=/data/bgp_tracer BGP_TRACER_PARALLEL_CHUNKS=1 \
  python3 -u scripts/run_full_evaluation.py \
    --budget-aware --max-calls-this-run 400 \
    --modes react \
    --max-duration-hours 24 \
    2>&1 | tee "logs/eval_runs/phase2_react_$(date +%Y%m%d_%H%M%S).log"
