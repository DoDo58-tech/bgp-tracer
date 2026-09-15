#!/bin/bash
# run_v2_events.sh - Run the 18-event v2 evaluation suite
# Usage: bash run_v2_events.sh [mode]
#   mode  — traffic_first (default) or react

set -e
# Resolve script directory so this works from any working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUTPUT_DIR="data_check/reality_case/evaluation_results_fresh"
mkdir -p "$OUTPUT_DIR"

MODE="${1:-traffic_first}"
echo "Mode: $MODE | Output: $OUTPUT_DIR"
echo "=========================================="

run_event() {
    local seq=$1
    local asn=$2
    local start=$3
    local end=$4
    local name=$5
    local out_json="$OUTPUT_DIR/result_${seq}_AS${asn}.json"

    echo ""
    echo "[$seq/18] AS${asn} — ${name}"
    echo "  Time: ${start} → ${end}"

    if [ -f "$out_json" ] && [ -s "$out_json" ]; then
        echo "  → Already exists, skipping."
        return
    fi

    # --json-output emits full structured JSON to stdout
    python chief_agent.py \
        --asn "$asn" \
        --start "$start" \
        --end "$end" \
        --mode "$MODE" \
        --json-output \
        > "$out_json" 2>&1

    # Verify we got valid JSON
    if [ -s "$out_json" ] && head -1 "$out_json" | grep -q '^{'; then
        echo "  → Saved JSON ($(wc -l < "$out_json") lines)"
    else
        echo "  ⚠ Failed — see $out_json"
    fi
}

# ── 18 v2 events ─────────────────────────────────────────────

run_event 1  12479  "2024-01-03 14:45:00" "2024-01-03 18:00:00"   "Orange España RPKI 劫持"
run_event 2  16276  "2024-10-30 13:21:00" "2024-10-30 13:40:00"   "OVHcloud 骨干中断"
run_event 3  24389  "2024-07-17 19:30:00" "2024-07-18 00:00:00"   "孟加拉国全国断网"
run_event 4  17557  "2024-07-31 08:30:00" "2024-07-31 10:30:00"   "Pakistan PTCL 断网"
run_event 5  8048   "2024-08-01 08:45:00" "2024-08-01 09:45:00"   "委内瑞拉 CANTV 流量暴跌"
run_event 6  14593  "2025-07-24 19:13:00" "2025-07-24 21:28:00"   "Starlink 第一次断网"
run_event 7  14593  "2025-09-15 04:00:00" "2025-09-15 05:00:00"   "Starlink 第二次断网"
run_event 8  3223   "2025-04-01 07:35:00" "2025-04-01 07:55:00"   "Voxility 路径泄露"
run_event 9  44244  "2025-06-18 12:50:00" "2025-06-19 05:00:00"   "伊朗 Irancell 断网"
run_event 10 27947  "2023-06-06 14:20:00" "2023-06-06 14:35:00"   "Telesur/RET 劫持"
run_event 11 398722 "2023-06-15 08:00:00" "2023-06-15 09:30:00"   "加密劫持 campaign"
run_event 12 9121   "2023-07-14 11:00:00" "2023-07-14 14:30:00"   "土耳其 Türk Telekom 泄露"
run_event 13 20940  "2023-09-18 07:00:00" "2023-09-18 07:45:00"   "Akamai 路径劫持"
run_event 14 9498   "2024-01-25 03:00:00" "2024-01-25 04:30:00"   "Airtel 路由泄露"
run_event 15 9121   "2024-02-12 07:00:00" "2024-02-12 08:30:00"   "土耳其断网"
run_event 16 4761   "2025-03-12 08:00:00" "2025-03-12 10:00:00"   "印尼 Telkomsel 泄露"
run_event 17 44244  "2025-06-22 08:00:00" "2025-06-22 20:00:00"   "伊朗 Irancell 再次断网"
run_event 18 16509  "2025-08-10 14:30:00" "2025-08-10 15:15:00"   "AWS Virginia 路由异常"

echo ""
echo "=========================================="
echo "Done! Results: $OUTPUT_DIR/"
echo "Run with --mode react for ReAct-style analysis."
