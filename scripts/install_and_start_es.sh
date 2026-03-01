#!/bin/bash
# 安装并启动Elasticsearch（不使用Docker）

set -e

echo "=========================================="
echo "安装并启动Elasticsearch"
echo "=========================================="

# 检查Java
if ! command -v java &> /dev/null; then
    echo "📦 安装Java..."
    sudo apt-get update
    sudo apt-get install -y openjdk-17-jdk
fi

echo "✅ Java版本:"
java -version

# ES配置
ES_VERSION="8.0.0"
ES_DIR="/opt/elasticsearch"
ES_USER="elasticsearch"

# 检查是否已安装
if [ -d "$ES_DIR" ]; then
    echo "✅ Elasticsearch已安装在 $ES_DIR"
else
    echo "📦 下载Elasticsearch ${ES_VERSION}..."
    cd /tmp
    wget -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz

    echo "📦 解压..."
    tar -xzf elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz
    sudo mv elasticsearch-${ES_VERSION} ${ES_DIR}

    # 创建用户
    if ! id "$ES_USER" &>/dev/null; then
        echo "👤 创建用户: $ES_USER"
        sudo useradd -r -s /bin/false $ES_USER
    fi

    # 设置权限
    sudo chown -R $ES_USER:$ES_USER ${ES_DIR}

    # 配置ES
    echo "⚙️  配置Elasticsearch..."
    sudo tee ${ES_DIR}/config/elasticsearch.yml > /dev/null <<EOF
cluster.name: bgp-tracer
node.name: node-1
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
EOF

    # 设置JVM内存（512MB）
    sudo sed -i 's/-Xms1g/-Xms512m/' ${ES_DIR}/config/jvm.options
    sudo sed -i 's/-Xmx1g/-Xmx512m/' ${ES_DIR}/config/jvm.options

    echo "✅ Elasticsearch安装完成！"
fi

# 检查是否已运行
if pgrep -f "elasticsearch" > /dev/null; then
    echo "✅ Elasticsearch已在运行"
    curl -s http://localhost:9200 | head -5
    exit 0
fi

# 启动ES
echo "🚀 启动Elasticsearch..."
sudo -u $ES_USER ${ES_DIR}/bin/elasticsearch -d

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

echo "❌ ES启动失败，检查日志:"
sudo tail -20 ${ES_DIR}/logs/*.log 2>/dev/null || echo "无法查看日志"
exit 1

