#!/bin/bash
# 简单启动ES脚本（用户手动运行）

ES_DIR="$HOME/elasticsearch-8.0.0"

if [ ! -d "$ES_DIR" ]; then
    echo "❌ ES未安装在 $ES_DIR"
    exit 1
fi

cd "$ES_DIR"

# 设置Java路径
export ES_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64

# 后台启动
nohup ./bin/elasticsearch > /tmp/es.log 2>&1 &
echo $! > /tmp/es.pid

echo "🚀 ES已启动，PID: $(cat /tmp/es.pid)"
echo "⏳ 等待30秒让ES启动..."
echo ""
echo "验证: curl http://localhost:9200"
echo "日志: tail -f /tmp/es.log"
echo "停止: kill \$(cat /tmp/es.pid)"

