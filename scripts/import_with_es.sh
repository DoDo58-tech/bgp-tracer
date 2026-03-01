#!/bin/bash
# 导入数据到ES的完整脚本（包含ES启动检查）

set -e

echo "=========================================="
echo "导入BGP数据到Elasticsearch"
echo "=========================================="

# 1. 检查ES是否运行
if ! curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "⚠️  ES未运行，正在启动..."
    
    ES_DIR="$HOME/elasticsearch-8.0.0"
    if [ ! -d "$ES_DIR" ]; then
        echo "❌ ES未安装在 $ES_DIR"
        exit 1
    fi
    
    cd "$ES_DIR"
    export ES_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64
    nohup ./bin/elasticsearch > /tmp/es.log 2>&1 &
    echo $! > /tmp/es.pid
    
    echo "⏳ 等待ES启动（30秒）..."
    sleep 30
    
    if ! curl -s http://localhost:9200 > /dev/null 2>&1; then
        echo "❌ ES启动失败，查看日志: tail -20 /tmp/es.log"
        exit 1
    fi
    echo "✅ ES已启动"
fi

# 2. 激活conda环境并导入数据
cd /data/bgp_tracer

source $(conda info --base)/etc/profile.d/conda.sh
conda activate bgp_tracer

export ES_ENABLED=true

# 3. 运行导入脚本
python scripts/import_updates_to_es.py "$@"

