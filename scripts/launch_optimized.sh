#!/bin/bash
# Optimized batch launcher for v8+ (2026-10-08 r18)
#
# Token-budget optimizations vs v7:
#   - REPORT_PAYLOAD_MAX_CHARS=30000    (was 60000; p95 21k tokens → ~7.5k)
#   - REACT_MAX_CONTEXT_CHARS=25000     (was 50000; 13k → 6k tokens)
#   - REACT_OBSERVATION_MAX_CHARS=2500  (was 4000)
#   - REACT_MAX_ROUNDS=6                (was 8; converges by round 4-5)
#   - slim_payload limits 10→4          (LLM only needs the cause label
#                                         and key metrics; the rest is
#                                         rendered deterministically)
#   - _MAX_PAYLOAD_BYTES=80000          (was 220000; final guardrail)
#   - LLM_BUDGET_SHARED_FILE=<path>     (cross-subprocess budget tracking)
#   - BGPT_INTER_MODE_SLEEP_S=8         (was 5; give TPM time to refresh)
#   - BGPT_INTER_EVENT_SLEEP_S=45       (was 30; with new payload it's
#                                         2-3x faster per call, so we
#                                         can afford longer inter-event)
#   - REPORT_USE_DETERMINISTIC=1        (keep fallback for 429 cases)
#
# Expected throughput vs v7:
#   - Per-event cost: 6-9 LLM calls (was 8-12) at 6-10k tokens (was 12-20k)
#   - 30 events × 2 modes = 60 events; ~500 LLM calls (was ~700)
#   - Wall-clock: ~2-3h (was 5-6h); well within the 5h budget window

set -e
cd "$(dirname "$0")/.."

BATCH_DIR_NAME="4mode_batch_optimized_$(date +%Y%m%d_%H%M%S)"
LOG_DIR="logs/${BATCH_DIR_NAME}"
mkdir -p "$LOG_DIR"
BUDGET_FILE="${LOG_DIR}/llm_budget.shared"
# Pre-create the budget file so llm_factory._BudgetTracker doesn't need
# to create it lazily. The tracker also rotates the file every 50 appends
# so it stays bounded.
touch "$BUDGET_FILE"

# CSV
CSV="data_check/ground_truth_collection/final_balanced_dataset_v17.csv"

# Token-budget env vars (passed to chief_agent subprocesses)
export REPORT_PAYLOAD_MAX_CHARS="${REPORT_PAYLOAD_MAX_CHARS:-30000}"
export REACT_MAX_CONTEXT_CHARS="${REACT_MAX_CONTEXT_CHARS:-25000}"
export REACT_OBSERVATION_MAX_CHARS="${REACT_OBSERVATION_MAX_CHARS:-2500}"
export REACT_MAX_ROUNDS="${REACT_MAX_ROUNDS:-6}"
export REPORT_USE_DETERMINISTIC="${REPORT_USE_DETERMINISTIC:-1}"
export REPORT_LLM_TIMEOUT_S="${REPORT_LLM_TIMEOUT_S:-1500}"

# Cross-process budget tracking. 2026-10-08 (r18): if the monitor
# already seeded a budget file (from v7's HTTP-call history), use it.
# Otherwise create a fresh one in this batch's log dir.
if [ -n "${LLM_BUDGET_SHARED_FILE:-}" ] && [ -f "$LLM_BUDGET_SHARED_FILE" ]; then
    BUDGET_FILE="$LLM_BUDGET_SHARED_FILE"
    echo "Using pre-seeded budget file: $BUDGET_FILE"
else
    BUDGET_FILE="${LOG_DIR}/llm_budget.shared"
    touch "$BUDGET_FILE"
fi
export LLM_BUDGET_SHARED_FILE="$BUDGET_FILE"
export LLM_BUDGET_MAX_CALLS="${LLM_BUDGET_MAX_CALLS:-950}"
export LLM_BUDGET_WINDOW_S="${LLM_BUDGET_WINDOW_S:-18000}"

# 429 circuit breaker (already in llm_factory)
export LLM_429_BREAKER_WINDOW_S="${LLM_429_BREAKER_WINDOW_S:-60}"
export LLM_429_BREAKER_THRESHOLD="${LLM_429_BREAKER_THRESHOLD:-3}"
export LLM_429_COOLDOWN_S="${LLM_429_COOLDOWN_S:-5.0}"

# Pacing (adaptive inter-event sleep in run_4mode_batch.py)
export BGPT_INTER_MODE_SLEEP_S="${BGPT_INTER_MODE_SLEEP_S:-8}"
export BGPT_INTER_EVENT_SLEEP_S="${BGPT_INTER_EVENT_SLEEP_S:-45}"
export BGPT_BUDGET_BACKOFF_S="${BGPT_BUDGET_BACKOFF_S:-60}"
export BGPT_MODE_TIMEOUT_S="${BGPT_MODE_TIMEOUT_S:-2400}"

# Logging
echo "=== v8+ optimized batch launcher ==="
echo "Batch dir:    $LOG_DIR"
echo "Budget file:  $BUDGET_FILE"
echo "CSV:          $CSV"
echo "Modes:        ${BGPT_MODES:-traffic_first,react}"
echo "Inter-mode:   ${BGPT_INTER_MODE_SLEEP_S}s"
echo "Inter-event:  ${BGPT_INTER_EVENT_SLEEP_S}s (adaptive)"
echo "Budget:       ${LLM_BUDGET_MAX_CALLS} calls / ${LLM_BUDGET_WINDOW_S}s"
echo ""
echo "Token-budget knobs (passed to subprocesses):"
echo "  REPORT_PAYLOAD_MAX_CHARS=$REPORT_PAYLOAD_MAX_CHARS"
echo "  REACT_MAX_CONTEXT_CHARS=$REACT_MAX_CONTEXT_CHARS"
echo "  REACT_OBSERVATION_MAX_CHARS=$REACT_OBSERVATION_MAX_CHARS"
echo "  REACT_MAX_ROUNDS=$REACT_MAX_ROUNDS"
echo ""

# Choose modes (default: both)
MODES_ARG=""
if [ -n "${BGPT_MODES:-}" ]; then
    IFS=',' read -ra MODE_ARR <<< "$BGPT_MODES"
    for m in "${MODE_ARR[@]}"; do
        MODES_ARG="$MODES_ARG --mode $m"
    done
fi

nohup python scripts/run_4mode_batch.py \
    --csv "$CSV" \
    $MODES_ARG \
    > "${LOG_DIR}/launcher.log" 2>&1 &

PID=$!
echo "Launched PID=$PID"
echo "Tail logs:    tail -f ${LOG_DIR}/launcher.log"
echo "Monitor:      tail -f ${LOG_DIR}/launcher.log | grep -E 'Event|sleep|FAIL|PASS'"

# Create a sentinel file so external monitors can detect launch
echo "$PID" > "${LOG_DIR}/launcher.pid"
echo "$(date)" > "${LOG_DIR}/launched_at"
