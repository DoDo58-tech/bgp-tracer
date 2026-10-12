#!/bin/bash
# Show the current state of a batch run: processes, latest log, results.
cd "$(dirname "$0")"

echo "============================================"
echo "BGP Tracer Batch Status — $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

CHIEF=$(ps -ef | grep "chief_agent" | grep -v grep | wc -l)
BATCH=$(ps -ef | grep "run_4mode_batch" | grep -v grep | wc -l)
echo "Processes:"
echo "  chief_agent: $CHIEF"
echo "  batch:       $BATCH"
if [ "$BATCH" -eq 0 ]; then
    echo "  WARNING: no batch process is running"
fi
if [ "$CHIEF" -gt 2 ]; then
    echo "  WARNING: $CHIEF chief_agent processes, possible orphans"
fi
echo ""

BATCH_LOG=$(ls -t logs/tmux_bg_batch*.log 2>/dev/null | head -1)
if [ -z "$BATCH_LOG" ]; then
    echo "No batch log found"
else
    echo "Latest batch log: $BATCH_LOG"
    echo "Last 5 lines:"
    tail -5 "$BATCH_LOG"
    echo ""

    RESULTS="logs/$(basename "$BATCH_LOG" .log)/results.jsonl"
    if [ -f "$RESULTS" ]; then
        echo "Results: $RESULTS"
        echo "  total:   $(wc -l < "$RESULTS")"
        echo "  success: $(grep -c '"success": true' "$RESULTS" 2>/dev/null || echo 0)"
        echo "  failed:  $(grep -c '"success": false' "$RESULTS" 2>/dev/null || echo 0)"
        VERDICTS=$(grep -c '"verdict"' "$RESULTS" 2>/dev/null || echo 0)
        echo "  with verdict: $VERDICTS"
        if [ "$VERDICTS" -gt 0 ]; then
            echo "  JSON parsed correctly"
        else
            echo "  No verdicts parsed; check the results file"
        fi
        echo ""
        echo "Last 3 records:"
        tail -3 "$RESULTS" | python3 -m json.tool 2>/dev/null \
            | grep -E '"event_id"|"mode"|"success"|"verdict"|"quality"|"token"' \
            | head -20
    fi
fi

echo ""
echo "Latest 5 HTML reports:"
ls -lt results/html/llm_report_AS*.html 2>/dev/null | head -5 \
    | awk '{print "  " $6, $7, $8, "  " $9}'

LATEST_HTML=$(ls -t results/html/llm_report_AS*.html 2>/dev/null | head -1)
if [ -n "$LATEST_HTML" ]; then
    PLACEHOLDERS=$(grep -c "\[target_as\]\|\[user_analysis_window\]" "$LATEST_HTML" 2>/dev/null)
    PLACEHOLDERS=${PLACEHOLDERS:-0}
    HTML_TAG=$(grep -c "<html" "$LATEST_HTML" 2>/dev/null)
    HTML_TAG=${HTML_TAG:-0}
    echo ""
    echo "Latest report: $LATEST_HTML ($(du -h "$LATEST_HTML" 2>/dev/null | cut -f1))"
    if [ "$PLACEHOLDERS" -gt 0 ]; then
        echo "  $PLACEHOLDERS unresolved placeholder(s); the report is incomplete"
    elif [ "$HTML_TAG" -eq 0 ]; then
        echo "  No <html> tag; this may not be a rendered report"
    else
        echo "  Structure looks correct"
    fi
fi

echo ""
echo "============================================"
