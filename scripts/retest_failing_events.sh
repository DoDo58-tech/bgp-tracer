#!/bin/bash
# Re-run failing events from v3 batch with the validator fix in place
set -e

LOG=logs/4mode_retest_20260928/cox_tata_retest.log
mkdir -p logs/4mode_retest_20260928

run_event() {
    local eid=$1
    local asn=$2
    local start=$3
    local end=$4
    echo "=== ${eid} (AS${asn}) ===" >> $LOG
    date >> $LOG
    timeout 600 python3 chief_agent.py --asn $asn --start "$start" --end "$end" --mode react >> $LOG 2>&1
    echo "---" >> $LOG
}

# Cox (22773) - had fallback
run_event "leak_cox_2025" "22773" "2025-04-17T17:00:00" "2025-04-17T20:00:00"

# Tata Voxility (6453) - had fallback
run_event "leak_tata_voxility_2025" "6453" "2025-03-15T07:35:00" "2025-03-15T08:00:00"

echo "Done" >> $LOG
