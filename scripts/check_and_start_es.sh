#!/bin/bash
# 检查并启动Elasticsearch

echo "=========================================="
echo "检查Elasticsearch状态"
echo "=========================================="

# 1. 检查ES是否已运行
echo "🔍 检查ES服务..."
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "✅ Elasticsearch已在运行！"
    curl -s http://localhost:9200 | python3 -m json.tool 2>/dev/null | head -10 || curl -s http://localhost:9200
    echo ""
    echo "✅ ES已就绪，可以导入数据了"
    exit 0
fi

echo "⚠️  ES未运行，尝试启动..."

# 2. 尝试不同的启动方式
echo ""
echo "请选择ES的启动方式："
echo ""
echo "方式1: 如果ES通过systemd安装"
echo "  sudo systemctl start elasticsearch"
echo ""
echo "方式2: 如果ES安装在 /opt/elasticsearch"
echo "  sudo -u elasticsearch /opt/elasticsearch/bin/elasticsearch -d"
echo ""
echo "方式3: 如果ES安装在 /usr/share/elasticsearch"
echo "  sudo systemctl start elasticsearch"
echo ""
echo "方式4: 如果使用Docker"
echo "  docker start elasticsearch"
echo ""
echo "方式5: 如果ES在自定义路径"
echo "  找到elasticsearch可执行文件，然后运行:"
echo "  <ES路径>/bin/elasticsearch -d"
echo ""
echo "=========================================="
echo "启动后，运行以下命令验证:"
echo "  curl http://localhost:9200"
echo ""
echo "然后启用ES并导入数据:"
echo "  export ES_ENABLED=true"
echo "  python scripts/import_updates_to_es.py --start \"2024-12-26 00:00\" --end \"2025-01-02 00:00\""
echo "=========================================="

