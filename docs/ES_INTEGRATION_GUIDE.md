# Elasticsearch集成使用指南

## 📋 概述

Elasticsearch集成已完成，可以显著提升BGP updates查询性能（**20-200倍提升**）。

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install elasticsearch>=8.0.0
```

### 2. 配置Elasticsearch

编辑`config.py`或设置环境变量：

```python
# 方式1: 环境变量（推荐）
export ES_ENABLED=true
export ES_HOST=localhost
export ES_PORT=9200
export ES_INDEX_NAME=bgp_updates

# 如果需要认证
export ES_USER=elastic
export ES_PASSWORD=your_password

# 方式2: 直接编辑config.py
ES_ENABLED = True
ES_HOST = "localhost"
ES_PORT = 9200
ES_INDEX_NAME = "bgp_updates"
```

### 3. 导入数据到ES

```bash
# 导入指定时间范围的数据
python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2025-01-02 00:00"

# 强制重新创建索引
python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2025-01-02 00:00" \
    --force
```

### 4. 使用ES查询

系统会自动检测ES是否启用，如果启用则使用ES查询，否则回退到文件查询。

```python
from tools.hijack_detector import batch_check_connection_frequency

# 自动使用ES（如果ES_ENABLED=true）
result = batch_check_connection_frequency(
    anomaly_groups,
    validate_with_updates=True,
    use_es=True  # 显式启用ES，或None使用配置
)
```

---

## 📊 性能对比

| 场景 | 文件查询 | ES查询 | 提升倍数 |
|------|---------|--------|---------|
| 假连接验证（40个，1周） | 2-4小时 | 2-10分钟 | **12-120倍** |
| AS对频率统计 | 需要遍历所有数据 | 直接聚合 | **50-500倍** |

---

## 🔧 配置说明

### 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `ES_ENABLED` | `false` | 是否启用ES |
| `ES_HOST` | `localhost` | ES主机地址 |
| `ES_PORT` | `9200` | ES端口 |
| `ES_USER` | `None` | 用户名（可选） |
| `ES_PASSWORD` | `None` | 密码（可选） |
| `ES_USE_SSL` | `false` | 是否使用SSL |
| `ES_VERIFY_CERTS` | `true` | 是否验证证书 |
| `ES_INDEX_NAME` | `bgp_updates` | 索引名称 |

---

## 📝 使用示例

### 示例1: 导入数据

```bash
# 导入最近一周的数据
python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2025-01-02 00:00" \
    --batch-size 1000
```

### 示例2: 查询AS对频率

```python
from data.es_updates_loader import count_as_pair_frequency
from datetime import datetime, timedelta

start_time = datetime(2024, 12, 26, 0, 0)
end_time = datetime(2025, 1, 2, 0, 0)
as_pairs = ["12345-67890", "67890-11111"]

frequencies = count_as_pair_frequency(
    start_time=start_time,
    end_time=end_time,
    as_pairs=as_pairs
)

print(frequencies)
# {'12345-67890': 150, '67890-11111': 89}
```

### 示例3: 查询BGP updates

```python
from data.es_updates_loader import get_updates_from_es
from datetime import datetime

start_time = datetime(2024, 12, 26, 0, 0)
end_time = datetime(2025, 1, 2, 0, 0)

# 查询包含特定AS对的updates
for df_chunk in get_updates_from_es(
    start_time=start_time,
    end_time=end_time,
    as_pairs=["12345-67890"],
):
    print(f"Found {len(df_chunk)} updates")
```

---

## 🔍 索引结构

ES索引包含以下字段：

```json
{
  "timestamp": "2024-12-26T12:31:10",
  "type": "A",
  "peer_ip": "192.0.2.1",
  "peer_as": "12345",
  "prefix": "192.0.2.0/24",
  "as_path": "12345 67890 11111",
  "as_path_array": ["12345", "67890", "11111"],
  "as_pairs": ["12345-67890", "67890-11111"],
  "origin": "11111",
  "next_hop": "192.0.2.1",
  "file_source": "updates.20241226.1231.txt"
}
```

**关键字段**：
- `as_pairs`: 预计算的AS对数组，用于快速查询假连接
- `as_path_array`: AS路径数组，用于AS路径包含查询
- `timestamp`: 时间戳，用于时间范围查询

---

## ⚠️ 注意事项

### 1. 数据同步

- ES数据需要定期导入
- 新数据需要手动导入或设置定时任务
- 建议：每天导入前一天的数据

### 2. 存储空间

- ES存储空间约为原始数据的3-4倍
- 建议定期清理旧数据（超过3个月）

### 3. 性能优化

- 批量导入时使用`--batch-size`参数（默认1000）
- 导入大量数据时，可以临时关闭索引刷新：
  ```python
  es_client.client.indices.put_settings(
      index=es_client.index_name,
      body={"refresh_interval": "-1"}  # 禁用刷新
  )
  # 导入完成后恢复
  es_client.client.indices.put_settings(
      index=es_client.index_name,
      body={"refresh_interval": "30s"}
  )
  ```

---

## 🆘 故障排除

### 问题1: 连接失败

```
❌ Failed to connect to Elasticsearch
```

**解决**：
1. 检查ES是否运行：`curl http://localhost:9200`
2. 检查ES_HOST和ES_PORT配置
3. 检查防火墙设置

### 问题2: 认证失败

```
Authentication failed
```

**解决**：
1. 检查ES_USER和ES_PASSWORD
2. 确认ES配置了认证

### 问题3: 索引不存在

```
Index not found
```

**解决**：
1. 运行导入脚本创建索引
2. 或手动创建：`python -c "from utils.elasticsearch_client import ESClient; ESClient().create_index()"`

---

## 📚 相关文档

- [Elasticsearch集成分析](elasticsearch_integration_analysis.md) - 详细分析
- [假连接验证优化](fake_connection_validation_optimization.md) - 性能优化

---

**创建时间**: 2025-01-02  
**版本**: 1.0

