#!/bin/bash
# bgp_tracer/batch_status.sh — 快速查看 batch 运行状态
cd "$(dirname "$0")"

echo "============================================"
echo "BGP Tracer Batch Status — $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

# 进程检查
CHIEF=$(ps -ef | grep "chief_agent" | grep -v grep | wc -l)
BATCH=$(ps -ef | grep "run_4mode_batch" | grep -v grep | wc -l)
echo "进程状态:"
echo "  chief_agent 进程数: $CHIEF"
echo "  batch 进程数:     $BATCH"
if [ "$BATCH" -eq 0 ]; then
    echo "  ⚠  WARNING: batch 进程不存在!"
fi
if [ "$CHIEF" -gt 2 ]; then
    echo "  ⚠  WARNING: chief_agent 进程过多，可能有孤儿!"
fi
echo ""

# 最新 batch log
BATCH_LOG=$(ls -t logs/tmux_bg_batch*.log 2>/dev/null | head -1)
if [ -n "$BATCH_LOG" ]; then
    echo "最新 Batch Log: $BATCH_LOG"
    echo "最后 5 行:"
    tail -5 "$BATCH_LOG"
    echo ""
    
    # 提取 batch ID
    BATCH_ID=$(basename "$BATCH_LOG" .log)
    RESULTS="logs/${BATCH_ID}/results.jsonl"
    
    if [ -f "$RESULTS" ]; then
        echo "结果文件: $RESULTS"
        TOTAL=$(wc -l < "$RESULTS")
        SUCCESS=$(grep -c '"success": true' "$RESULTS" 2>/dev/null || echo 0)
        FAILED=$(grep -c '"success": false' "$RESULTS" 2>/dev/null || echo 0)
        HAS_VERDICT=$(grep -c '"verdict"' "$RESULTS" 2>/dev/null || echo 0)
        echo "  总事件数: $TOTAL"
        echo "  成功: $SUCCESS | 失败: $FAILED"
        echo "  有 verdict 指标: $HAS_VERDICT 条"
        if [ "$HAS_VERDICT" -gt 0 ]; then
            echo "  ✅ JSON 解析正常 (非 N/A)"
        else
            echo "  ❌ JSON 解析可能有问题 (全部 N/A)"
        fi
        echo ""
        echo "最后 3 条记录:"
        tail -3 "$RESULTS" | python3 -m json.tool 2>/dev/null | grep -E '"event_id"|"mode"|"success"|"verdict"|"quality"|"token"' | head -20
        echo ""
    fi
else
    echo "❌ 未找到 batch log"
fi

# 最新 HTML 报告
echo "最新 5 个 HTML 报告:"
ls -lt results/html/llm_report_AS*.html 2>/dev/null | head -5 | awk '{print "  " $6, $7, $8, "  " $9}'
echo ""

# 检查最新报告是否有占位符
LATEST_HTML=$(ls -t results/html/llm_report_AS*.html 2>/dev/null | head -1)
if [ -n "$LATEST_HTML" ]; then
    HAS_PLACEHOLDER=$(grep -c "\[target_as\]\|\[user_analysis_window\]" "$LATEST_HTML" 2>/dev/null)
    HAS_PLACEHOLDER=${HAS_PLACEHOLDER:-0}
    HAS_HTML_TAG=$(grep -c "<html" "$LATEST_HTML" 2>/dev/null)
    HAS_HTML_TAG=${HAS_HTML_TAG:-0}
    SIZE=$(du -h "$LATEST_HTML" 2>/dev/null | cut -f1)
    echo "最新报告: $LATEST_HTML ($SIZE)"
    echo "  含 <html> 标签: $HAS_HTML_TAG"
    echo "  含占位符: $HAS_PLACEHOLDER"
    if [ "$HAS_PLACEHOLDER" -gt 0 ] 2>/dev/null; then
        echo "  ❌ 报告含占位符!"
    elif [ "$HAS_HTML_TAG" -eq 0 ] 2>/dev/null; then
        echo "  ❌ 报告不含 <html> 标签，可能不是 HTML!"
    else
        echo "  ✅ 报告结构正常"
    fi
fi

echo ""
echo "============================================"
