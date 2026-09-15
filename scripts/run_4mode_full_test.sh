#!/bin/bash
# 4-mode 完整测试 - 在 tmux 后台运行
# 同时跑 traffic_first / traffic_first_enhanced / react / react_enhanced

set -u
cd /data/bgp_tracer
export BGP_TRACER_ENV_FILE=".env"
# Bug fix 2026-09-15: user explicitly wants LLM-generated reports, not the
# deterministic fallback template. Set REQUIRE_LLM=1 so HTML balance
# failures surface as errors instead of being silently replaced.
export REPORT_REQUIRE_LLM=1
export PYTHONUNBUFFERED=1
export JSON_OUTPUT_ENABLED=0

TS=$(date +%Y%m%d_%H%M%S)
LOG_DIR="logs/4mode_full_${TS}"
mkdir -p "$LOG_DIR"

echo "=== 4-Mode Full Test: $(date) ===" | tee "$LOG_DIR/summary.log"
echo "Log dir: $LOG_DIR" | tee -a "$LOG_DIR/summary.log"
echo "Event: AS12479 (Orange España RPKI hijack) 2024-01-03 14:45 → 18:00" | tee -a "$LOG_DIR/summary.log"
echo "==========================================" | tee -a "$LOG_DIR/summary.log"

run_mode() {
    local idx=$1
    local label=$2
    local mode=$3
    local extra=$4
    local log_file="$LOG_DIR/${label}.log"

    echo "" | tee -a "$LOG_DIR/summary.log"
    echo "==========================================" | tee -a "$LOG_DIR/summary.log"
    echo "▶ [$idx/4] $label (mode=$mode)" | tee -a "$LOG_DIR/summary.log"
    echo "==========================================" | tee -a "$LOG_DIR/summary.log"

    local t0=$(date +%s)
    python chief_agent.py --asn 12479 --start "2024-01-03 14:45" --end "2024-01-03 18:00" --mode "$mode" $extra > "$log_file" 2>&1
    local t1=$(date +%s)
    local elapsed=$((t1 - t0))
    local exit_code=$?

    echo "[$label] exit=$exit_code elapsed=${elapsed}s" | tee -a "$LOG_DIR/summary.log"

    if [ $exit_code -eq 0 ]; then
        echo "✅ $label PASSED (${elapsed}s)" | tee -a "$LOG_DIR/summary.log"
    else
        echo "❌ $label FAILED (exit $exit_code, ${elapsed}s)" | tee -a "$LOG_DIR/summary.log"
        echo "=== Last 50 lines of log ===" | tee -a "$LOG_DIR/summary.log"
        tail -50 "$log_file" | tee -a "$LOG_DIR/summary.log"
    fi

    echo "${label} exit_code=${exit_code} elapsed=${elapsed}" >> "$LOG_DIR/summary.log"
}

run_mode 1 "traffic_first"            "traffic_first" ""
run_mode 2 "traffic_first_enhanced"   "traffic_first" "--enhanced"
run_mode 3 "react"                    "react"         ""
run_mode 4 "react_enhanced"           "react"         "--enhanced"

echo "" | tee -a "$LOG_DIR/summary.log"
echo "==========================================" | tee -a "$LOG_DIR/summary.log"
echo "=== 4-Mode Full Test Complete: $(date) ===" | tee -a "$LOG_DIR/summary.log"
echo "" | tee -a "$LOG_DIR/summary.log"
echo "=== Generated reports ===" | tee -a "$LOG_DIR/summary.log"
ls -la results/html/llm_report_AS12479_*.html 2>/dev/null | tail -10 | tee -a "$LOG_DIR/summary.log"
echo "" | tee -a "$LOG_DIR/summary.log"
echo "=== Mode summary ===" | tee -a "$LOG_DIR/summary.log"
grep -E "(PASSED|FAILED|elapsed)" "$LOG_DIR/summary.log" | tee -a "$LOG_DIR/summary.log"
