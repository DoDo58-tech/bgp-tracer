#!/usr/bin/env python3
"""
检查Elasticsearch连接状态
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import ES_HOST, ES_PORT, ES_ENABLED, ES_USER, ES_PASSWORD, ES_USE_SSL
from utils.logger import logger

def check_es_connection():
    """检查ES连接"""
    print("=" * 60)
    print("Elasticsearch连接诊断")
    print("=" * 60)
    
    # 1. 检查配置
    print(f"\n📋 配置信息:")
    print(f"  ES_ENABLED: {ES_ENABLED}")
    print(f"  ES_HOST: {ES_HOST}")
    print(f"  ES_PORT: {ES_PORT}")
    print(f"  ES_USE_SSL: {ES_USE_SSL}")
    if ES_USER:
        print(f"  ES_USER: {ES_USER}")
        print(f"  ES_PASSWORD: {'*' * len(ES_PASSWORD) if ES_PASSWORD else 'Not set'}")
    
    if not ES_ENABLED:
        print("\n⚠️  ES_ENABLED=False，请设置环境变量:")
        print("  export ES_ENABLED=true")
        return False
    
    # 2. 检查服务是否运行
    print(f"\n🔍 检查ES服务...")
    scheme = "https" if ES_USE_SSL else "http"
    url = f"{scheme}://{ES_HOST}:{ES_PORT}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"  ✅ ES服务正在运行: {url}")
            info = response.json()
            print(f"  ES版本: {info.get('version', {}).get('number', 'Unknown')}")
            print(f"  集群名称: {info.get('cluster_name', 'Unknown')}")
            return True
        else:
            print(f"  ❌ ES服务响应异常: HTTP {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"  ❌ 无法连接到ES服务: {url}")
        print(f"\n💡 可能的原因:")
        print(f"  1. ES服务未启动")
        print(f"  2. ES_HOST或ES_PORT配置错误")
        print(f"  3. 防火墙阻止连接")
        print(f"\n📝 解决方案:")
        print(f"  1. 启动ES服务:")
        print(f"     # Docker方式:")
        print(f"     docker run -d -p 9200:9200 -p 9300:9300 -e 'discovery.type=single-node' elasticsearch:8.0.0")
        print(f"     # 或使用系统服务:")
        print(f"     sudo systemctl start elasticsearch")
        print(f"  2. 检查ES是否运行:")
        print(f"     curl http://localhost:9200")
        return False
    except Exception as e:
        print(f"  ❌ 连接失败: {e}")
        return False

if __name__ == "__main__":
    success = check_es_connection()
    sys.exit(0 if success else 1)

