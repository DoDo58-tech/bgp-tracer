#!/bin/bash
# 4-mode evaluation launch — runs run_4mode_batch.py detached in tmux.
# Settings:
#   - BGPT_BATCH_MAX_HOURS=6 → skip events whose duration > 6h
#   - per-mode timeout = 900s (set inside run_4mode_batch.py)
#   - logs under logs/4mode_batch_<timestamp>/<event>/<mode>.log
#   - summary results under logs/4mode_batch_<timestamp>/results.jsonl
# Rate-limit note: 1000 API requests per 5h. ~23 events × 4 modes × ~5 LLM
# calls ≈ 460 LLM calls — within budget.

set -u
cd /data/bgp_tracer
export BGP_TRACER_ENV_FILE=".env"
export BGPT_BATCH_MAX_HOURS=6
export PYTHONUNBUFFERED=1

BATCH_ID="$(date +%Y%m%d_%H%M%S)_eval4mode"
LOG_DIR="logs/${BATCH_ID}"
mkdir -p "$LOG_DIR"

echo "============================================================"
echo " 4-Mode Evaluation Launch"
echo "  Batch ID: $BATCH_ID"
echo "  Log dir:  $LOG_DIR"
echo "  Started:  $(date)"
echo "============================================================"

# Run detached so the tmux session can keep going after this shell exits.
nohup python scripts/run_4mode_batch.py > "$LOG_DIR/launcher.log" 2>&1 &
LAUNCHER_PID=$!
echo $LAUNCHER_PID > "$LOG_DIR/launcher.pid"

echo "Launched run_4mode_batch.py as PID $LAUNCHER_PID"
echo "Tail -f $LOG_DIR/launcher.log"
echo "Tail -f $LOG_DIR/../bgp_tracer.log  (live chief_agent log)"
echo
echo "Monitor per-event logs:"
echo "  watch -n 30 'ls -lt $LOG_DIR/*/' 2>/dev/null"
echo
echo "To reattach the tmux session:"
echo "  tmux attach -t bgp_eval"
