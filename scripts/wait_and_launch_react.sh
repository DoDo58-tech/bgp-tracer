#!/bin/bash
# Wait for v7 4mode batch to finish, then launch react-only batch.
# 2026-10-08 (r18): v7 was launched with old prompts (REPORT_PAYLOAD_MAX_CHARS=60K,
# REACT_MAX_ROUNDS=8, no budget file) and at current pace (~30min/event) would
# take another 10h — past the 5h quota window. The monitor now also
# kills v7 if it's been running > 6h, so the optimized r18 batch can
# start fresh with the smaller prompts and finish within the budget.

BATCH_DIR="/data/bgp_tracer/logs/4mode_batch_20261008_111109"
CSV="/data/bgp_tracer/data_check/ground_truth_collection/final_balanced_dataset_v17.csv"
LOG="/data/bgp_tracer/logs/bgp_tracer.log"
REACT_LOG="/data/bgp_tracer/logs/react_only_batch.log"
V7_MAX_RUNTIME_S="${V7_MAX_RUNTIME_S:-21600}"   # 6h default

total=$(($(awk -F',' 'NR>1{print}' "$CSV" | wc -l)))

echo "[$(date)] Monitor started. Total events: $total"
echo "[$(date)] v7 max runtime: ${V7_MAX_RUNTIME_S}s ($((${V7_MAX_RUNTIME_S}/3600))h)"

# Track v7 start time
V7_START_FILE="/tmp/v7_start_time"
if [ ! -f "$V7_START_FILE" ]; then
    V7_PID=$(pgrep -f "run_4mode_batch.py" | head -1)
    if [ -n "$V7_PID" ]; then
        V7_LSTART=$(ps -o lstart= -p "$V7_PID" 2>/dev/null | xargs)
        echo "$V7_LSTART" > "$V7_START_FILE"
        echo "[$(date)] Recorded v7 start: $V7_LSTART"
    else
        date > "$V7_START_FILE"
    fi
fi

launch_r18() {
    local reason="$1"
    echo "[$(date)] $reason"
    cd /data/bgp_tracer
    BGPT_MODES=react nohup bash scripts/launch_optimized.sh > "$REACT_LOG" 2>&1 &
    local r18_pid=$!
    echo "[$(date)] Optimized react-only batch launched. PID=$r18_pid" | tee -a "$REACT_LOG"
    # 2026-10-08 (r18): wait a few seconds and verify the batch actually
    # started — catches failures like "LLM_BUDGET_SHARED_FILE path unreadable"
    # or "missing CSV" before we declare victory and exit.
    sleep 15
    if ! pgrep -f "run_4mode_batch.py" > /dev/null 2>&1; then
        echo "[$(date)] ⚠️  r18 launch failed. Check ${REACT_LOG}. Retrying once..."
        tail -20 "$REACT_LOG" 2>/dev/null | head -10
        BGPT_MODES=react nohup bash scripts/launch_optimized.sh > "${REACT_LOG}.retry" 2>&1 &
        echo "[$(date)] Retry PID=$!" | tee -a "$REACT_LOG"
    fi
    exit 0
}

# Write v7's accumulated LLM call timestamps to the budget file so r18
# inherits accurate quota state. v7 didn't have a budget file enabled, so
# we reconstruct from the bgp_tracer.log: every chat-completion HTTP POST
# timestamp counts as one LLM call.
seed_budget_from_v7() {
    local v7_log="/data/bgp_tracer/logs/bgp_tracer.log"
    local r18_log_dir="/data/bgp_tracer/logs/4mode_batch_optimized_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$r18_log_dir"
    local r18_budget="$r18_log_dir/llm_budget.shared"
    if [ ! -f "$v7_log" ]; then
        echo "  (no bgp_tracer.log found; r18 will start with empty budget)"
        return 1
    fi
    # Extract every "HTTP Request: POST" timestamp (one per LLM call) within
    # the last BGPT_BUDGET_WINDOW_S seconds (default 5h).
    local window_s="${BGPT_BUDGET_WINDOW_S:-18000}"
    local cutoff=$(($(date +%s) - window_s))
    # bgp_tracer.log format: "2026-10-08 14:14:02,903 ... HTTP Request: POST"
    local count=0
    touch "$r18_budget"
    while IFS= read -r ts; do
        local epoch=$(date -d "$ts" +%s 2>/dev/null)
        if [ -n "$epoch" ] && [ "$epoch" -ge "$cutoff" ]; then
            echo "$epoch" >> "$r18_budget"
            count=$((count + 1))
        fi
    done < <(grep "HTTP Request: POST" "$v7_log" | awk '{print $1, $2}' | tr ',' '.' | sort -u)
    # Set the env var so launch_optimized.sh knows where the file is
    export LLM_BUDGET_SHARED_FILE="$r18_budget"
    echo "[$(date)] Seeded r18 budget file with $count v7 calls (in last $((window_s/3600))h window)"
    return 0
}

# Run seeding once at startup
seed_budget_from_v7 2>/dev/null || true

while true; do
    # 1. Has v7 already finished naturally?
    if ! pgrep -f "run_4mode_batch.py" > /dev/null 2>&1; then
        done_count=$(ls -d "$BATCH_DIR"/*/ 2>/dev/null | wc -l)
        echo "[$(date)] run_4mode_batch.py finished. Events done: $done_count/$total"
        launch_r18 "v7 done ($done_count/$total). Launching r18 react-only."
    fi

    # 2. Has v7 been running too long? Kill it and start r18.
    V7_PID=$(pgrep -f "run_4mode_batch.py" | head -1)
    if [ -n "$V7_PID" ] && [ -f "$V7_START_FILE" ]; then
        V7_LSTART=$(ps -o lstart= -p "$V7_PID" 2>/dev/null | xargs)
        if [ -n "$V7_LSTART" ]; then
            V7_START_EPOCH=$(date -d "$V7_LSTART" +%s 2>/dev/null)
            NOW_EPOCH=$(date +%s)
            if [ -n "$V7_START_EPOCH" ]; then
                V7_RUNTIME=$((NOW_EPOCH - V7_START_EPOCH))
                if [ "$V7_RUNTIME" -gt "$V7_MAX_RUNTIME_S" ]; then
                    echo "[$(date)] ⚠️  v7 running ${V7_RUNTIME}s ($((${V7_RUNTIME}/3600))h > max ${V7_MAX_RUNTIME_S}s). Killing."
                    kill -TERM "$V7_PID" 2>/dev/null
                    sleep 5
                    pgrep -f "run_4mode_batch.py" > /dev/null 2>&1 && kill -KILL "$V7_PID" 2>/dev/null
                    launch_r18 "v7 killed (runtime exceeded). Launching r18."
                fi
            fi
        fi
    fi

    # 3. Progress heartbeat — count only event subdirectories
    done_count=$(ls -d "$BATCH_DIR"/*/ 2>/dev/null | wc -l)
    remaining=$((total - done_count))
    echo "[$(date)] v7 still running. Progress: $done_count/$total, ~$remaining events left"

    last_event=$(ls -lt "$BATCH_DIR" 2>/dev/null | grep -v "^total" | head -1 | awk '{print $NF}')
    if [ -n "$last_event" ]; then
        echo "  Latest event dir: $last_event"
    fi

    sleep 600  # check every 10 min
done
