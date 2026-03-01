#!/bin/bash
# 启动Elasticsearch（如果已安装）

set -e

echo "=========================================="
echo "启动Elasticsearch"
echo "=========================================="

# 检查ES是否已运行
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "✅ Elasticsearch已在运行"
    curl -s http://localhost:9200 | python3 -m json.tool 2>/dev/null | head -10 || curl -s http://localhost:9200
    exit 0
fi

# 查找ES安装路径
ES_PATHS=(
    "/opt/elasticsearch/bin/elasticsearch"
    "/usr/share/elasticsearch/bin/elasticsearch"
    "/usr/local/elasticsearch/bin/elasticsearch"
    "$HOME/elasticsearch/bin/elasticsearch"
)

ES_BIN=""
for path in "${ES_PATHS[@]}"; do
    if [ -f "$path" ]; then
        ES_BIN="$path"
        ES_DIR=$(dirname $(dirname "$path"))
        break
    fi
done

if [ -z "$ES_BIN" ]; then
    echo "❌ 未找到Elasticsearch安装路径"
    echo "请手动指定ES路径，或运行安装脚本:"
    echo "  bash scripts/install_and_start_es.sh"
    exit 1
fi

echo "📦 找到Elasticsearch: $ES_DIR"

# 检查用户
ES_USER="elasticsearch"
if ! id "$ES_USER" &>/dev/null; then
    ES_USER=$(whoami)
    echo "⚠️  使用当前用户启动: $ES_USER"
fi

# 启动ES
echo "🚀 启动Elasticsearch..."
if [ "$ES_USER" = "$(whoami)" ]; then
    # 当前用户启动
    $ES_BIN -d
else
    # 使用elasticsearch用户启动
    sudo -u $ES_USER $ES_BIN -d
fi

echo "⏳ 等待ES启动（约30秒）..."
sleep 30

# 验证
for i in {1..10}; do
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        echo "✅ Elasticsearch运行正常！"
        curl -s http://localhost:9200 | python3 -m json.tool 2>/dev/null | head -10 || curl -s http://localhost:9200
        echo ""
        echo "=========================================="
        echo "✅ 完成！现在可以导入数据了"
        echo "=========================================="
        echo ""
        echo "下一步："
        echo "  export ES_ENABLED=true"
        echo "  python scripts/import_updates_to_es.py --start \"2024-12-26 00:00\" --end \"2025-01-02 00:00\""
        exit 0
    else
        echo "⏳ 等待ES启动... ($i/10)"
        sleep 3
    fi
done

echo "❌ ES启动失败"
echo "检查日志:"
if [ -d "$ES_DIR/logs" ]; then
    tail -20 $ES_DIR/logs/*.log 2>/dev/null || echo "无法查看日志"
fi
exit 1

