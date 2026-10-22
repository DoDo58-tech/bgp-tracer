#!/bin/bash
# =============================================================================
# Cloudflare Radar Alert → BGP Tracer Pipeline
# =============================================================================
# This script orchestrates the full alert-flood experiment:
#   1. Fetch 2025 Cloudflare Radar alerts (annotations + leaks + hijacks)
#   2. Run BGP Tracer Phase-1 (quick) on each alert
#   3. Produce alert-reduction report + dangerous alerts list
#
# Usage:
#   # Full run (background):
#   nohup bash scripts/cloudflare_alerts/run_pipeline.sh &
#
#   # Check progress:
#   tail -f logs/cf_pipeline.log
#
#   # Kill:
#   pkill -f "run_pipeline.sh\|run_bgpt_on_alerts"
#
# Inputs:
#   CLOUDFLARE_API_TOKEN env var (or --token)
#
# Outputs:
#   results/cloudflare_alerts/
#     ├── raw/raw_alerts.json          ← alert feed
#     ├── per_alert_verdict.jsonl     ← BGP Tracer verdicts
#     ├── dangerous_alerts.csv         ← real incident alerts
#     ├── reduction_table.csv         ← reduction stats
#     ├── alert_reduction_summary.json
#     └── README.md
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_DIR="$PROJECT_DIR/logs/cf_pipeline"
RAW_DIR="$PROJECT_DIR/results/cloudflare_alerts/raw"
OUT_DIR="$PROJECT_DIR/results/cloudflare_alerts"

mkdir -p "$LOG_DIR" "$RAW_DIR" "$OUT_DIR"

LOG="$LOG_DIR/pipeline_$(date +%Y%m%d_%H%M%S).log"

echo "=== Cloudflare Alert → BGP Tracer Pipeline ===" | tee "$LOG"
echo "Started: $(date -u)" | tee -a "$LOG"
echo "Log: $LOG" | tee -a "$LOG"

# =============================================================================
# Step 1: Fetch alerts
# =============================================================================
STEP1_LOG="$LOG_DIR/fetch_$(date +%Y%m%d_%H%M%S).log"
echo "" | tee -a "$LOG"
echo "=== Step 1: Fetch Cloudflare Radar alerts ===" | tee -a "$LOG"

# Check if raw_alerts.json already exists (resume support)
if [ -f "$RAW_DIR/raw_alerts.json" ]; then
    ALERT_COUNT=$(python3 -c "import json; print(len(json.load(open('$RAW_DIR/raw_alerts.json')))")
    echo "Found existing raw_alerts.json with $ALERT_COUNT alerts — skipping fetch (resume)" | tee -a "$LOG"
else
    echo "Fetching 2025 alerts..." | tee -a "$LOG"
    nohup env \
        CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}" \
        python3 "$PROJECT_DIR/scripts/cloudflare_alerts/fetch_cloudflare_alerts.py" \
            --date-start 2025-01-01T00:00:00Z \
            --leaks-prefix-count-min 5 \
            --hijacks-confidence-min 4 \
            --out-dir "$RAW_DIR" \
        > "$STEP1_LOG" 2>&1 &
    FETCH_PID=$!
    echo "Fetch PID: $FETCH_PID" | tee -a "$LOG"
    wait $FETCH_PID
    FETCH_EXIT=$?
    if [ $FETCH_EXIT -ne 0 ]; then
        echo "ERROR: fetch failed (exit $FETCH_EXIT)" | tee -a "$LOG"
        cat "$STEP1_LOG" | tee -a "$LOG"
        exit $FETCH_EXIT
    fi
    echo "Fetch complete." | tee -a "$LOG"
fi

# Report raw alert counts
if [ -f "$RAW_DIR/raw_alerts.json" ]; then
    python3 -c "
import json
d = json.load(open('$RAW_DIR/raw_alerts.json'))
from collections import Counter
by_s = Counter(r['source'] for r in d)
print(f\"Raw alerts loaded: {len(d)}\")
for s, c in sorted(by_s.items()): print(f'  {s}: {c}')
" | tee -a "$LOG"
fi

# =============================================================================
# Step 2: Run BGP Tracer on each alert
# =============================================================================
STEP2_LOG="$LOG_DIR/bgpt_$(date +%Y%m%d_%H%M%S).log"
echo "" | tee -a "$LOG"
echo "=== Step 2: Run BGP Tracer (Phase 1 quick) on alerts ===" | tee -a "$LOG"
echo "Started: $(date -u)" | tee -a "$LOG"

nohup env \
    CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}" \
    BGPT_LOG_LEVEL=INFO \
    python3 "$PROJECT_DIR/scripts/cloudflare_alerts/run_bgpt_on_alerts.py" \
        --raw-dir "$RAW_DIR" \
        --out-dir "$OUT_DIR" \
        --workers 4 \
        --shuffle \
    > "$STEP2_LOG" 2>&1 &
BGPT_PID=$!
echo "BGP Tracer PID: $BGPT_PID" | tee -a "$LOG"

# =============================================================================
# Wait for BGP Tracer to complete (with periodic progress)
# =============================================================================
PROGRESS_INTERVAL=60  # seconds
while kill -0 $BGPT_PID 2>/dev/null; do
    sleep $PROGRESS_INTERVAL
    if [ -f "$OUT_DIR/per_alert_verdict.jsonl" ]; then
        DONE=$(wc -l < "$OUT_DIR/per_alert_verdict.jsonl")
        echo "[$(date -u)] BGP Tracer running (PID $BGPT_PID), $DONE alerts processed" | tee -a "$LOG"
    else
        echo "[$(date -u)] BGP Tracer running (PID $BGPT_PID)..." | tee -a "$LOG"
    fi
done
wait $BGPT_PID
BGPT_EXIT=$?
echo "BGP Tracer finished (exit $BGPT_EXIT)" | tee -a "$LOG"

if [ $BGPT_EXIT -ne 0 ]; then
    echo "WARNING: BGP Tracer exited with code $BGPT_EXIT" | tee -a "$LOG"
    tail -20 "$STEP2_LOG" | tee -a "$LOG"
fi

# =============================================================================
# Step 3: Produce reduction report
# =============================================================================
STEP3_LOG="$LOG_DIR/analysis_$(date +%Y%m%d_%H%M%S).log"
echo "" | tee -a "$LOG"
echo "=== Step 3: Alert reduction analysis ===" | tee -a "$LOG"

python3 "$PROJECT_DIR/scripts/cloudflare_alerts/alert_reduction_cloudflare.py" \
    --in-dir "$OUT_DIR" \
    --out-dir "$OUT_DIR" \
    2>&1 | tee -a "$STEP3_LOG"

echo "" | tee -a "$LOG"
echo "=== Pipeline complete ===" | tee -a "$LOG"
echo "Finished: $(date -u)" | tee -a "$LOG"
echo "" | tee -a "$LOG"
echo "Key outputs:" | tee -a "$LOG"
echo "  Verdicts:     $OUT_DIR/per_alert_verdict.jsonl" | tee -a "$LOG"
echo "  Dangerous:     $OUT_DIR/dangerous_alerts.csv" | tee -a "$LOG"
echo "  Reduction:    $OUT_DIR/reduction_table.csv" | tee -a "$LOG"
echo "  Summary:      $OUT_DIR/alert_reduction_summary.json" | tee -a "$LOG"
echo "  README:       $OUT_DIR/README.md" | tee -a "$LOG"