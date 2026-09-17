#!/bin/bash
# Auto-launcher for Phase 2 after Phase 1 completes
# Polls the checkpoint.jsonl until all Phase 1 events are done,
# then launches Phase 2 (react mode).

set -e
cd /data/bgp_tracer

PHASE1_LOG="logs/eval_runs/phase1_cached_short_$(ls -t logs/eval_runs/phase1_cached_short_*.log | head -1 | sed 's/.*phase1_cached_short_//;s/.log//').log"

echo "Monitoring Phase 1 progress..."
while tmux ls 2>/dev/null | grep -q eval_full; do
    # Count checkpoints
    LATEST_CP=$(ls -t data_check/evaluation/run_*/checkpoint.jsonl 2>/dev/null | head -1)
    DONE=$(wc -l < "$LATEST_CP" 2>/dev/null || echo 0)
    echo "[$(date +%H:%M:%S)] Phase 1: $DONE events done (waiting for completion)..."
    sleep 60
done

echo "Phase 1 complete (tmux session ended). Launching Phase 2..."
sleep 5

tmux new-session -d -s eval_full -c /data/bgp_tracer \
  "PYTHONPATH=/data/bgp_tracer BGP_TRACER_PARALLEL_CHUNKS=1 python3 -u scripts/run_full_evaluation.py \
     --budget-aware --max-calls-this-run 400 \
     --modes react \
     --max-duration-hours 24 \
     2>&1 | tee logs/eval_runs/phase2_react_$(date +%Y%m%d_%H%M%S).log"

echo "Phase 2 launched as 'eval_full' tmux session"
