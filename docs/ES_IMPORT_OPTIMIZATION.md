# ES导入性能优化说明

## 当前性能分析

### 测试结果（单个5分钟文件，54万条记录）

| 步骤 | 耗时 | 说明 |
|------|------|------|
| 文件读取 | ~1.5秒 | 从txt文件读取 |
| 文档转换 | ~0.4秒 | AS对提取+ID生成 |
| ES批量写入 | ~26-30秒 | **主要瓶颈** |
| **总计** | **~30秒** | 理想情况 |

### 实际观察
- 用户反馈：5分钟文件需要1分钟左右
- 可能原因：
  1. ES写入实际更慢（网络、磁盘I/O）
  2. 文档构建开销
  3. 日志输出开销

---

## 已实施的优化

### 1. 向量化文档转换 ⭐⭐⭐⭐⭐
- **替换**: `iterrows()` → 向量化操作
- **提升**: 10-50倍
- **实现**: `_convert_dataframe_to_docs_vectorized()`

### 2. 批量大小优化 ⭐⭐⭐⭐
- **默认**: 1000
- **推荐**: 5000-10000（更大批量减少ES调用次数）
- **使用**: `--batch-size 5000`

### 3. 禁用索引刷新 ⭐⭐⭐⭐⭐
- **自动**: 导入期间禁用刷新
- **提升**: 3-5倍写入速度
- **已内置**: 自动处理

### 4. 文档ID去重 ⭐⭐⭐⭐
- **功能**: 避免重复导入
- **实现**: 基于timestamp+peer_as+prefix+as_path的MD5

### 5. 减少日志频率 ⭐⭐
- **优化**: 每5万条或每10个文件输出一次
- **减少**: I/O开销

---

## 进一步优化建议

### 方法1: 增加批量大小（最简单）⭐⭐⭐⭐⭐

```bash
python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2024-12-27 00:00" \
    --batch-size 10000  # 增加到10000
```

**预期提升**: 20-30%

### 方法2: 调整ES设置（如果可控制）⭐⭐⭐⭐

```bash
# 导入前
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'
{
  "refresh_interval": "-1",
  "number_of_replicas": 0
}'

# 导入后恢复
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'
{
  "refresh_interval": "30s",
  "number_of_replicas": 1
}'
```

### 方法3: 并行导入（高级）⭐⭐⭐

可以修改脚本支持多进程导入不同时间段。

---

## 性能目标

### 当前
- 5分钟文件: ~60秒
- 1天数据(288文件): ~4.8小时

### 优化后（batch-size=10000）
- 5分钟文件: ~40-50秒
- 1天数据: ~3-4小时

### 进一步优化（ES设置优化）
- 5分钟文件: ~30-40秒
- 1天数据: ~2-3小时

---

## 实际使用建议

### 快速测试（1天数据）
```bash
conda activate bgp_tracer
export ES_ENABLED=true

python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2024-12-27 00:00" \
    --batch-size 10000
```

### 完整导入（7天数据）
```bash
# 后台运行
nohup python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2025-01-02 00:00" \
    --batch-size 10000 \
    > /tmp/es_import.log 2>&1 &

# 查看进度
tail -f /tmp/es_import.log
```

---

## 瓶颈分析

### 主要瓶颈：ES批量写入
- **原因**: 网络延迟、磁盘I/O、索引更新
- **优化**: 增加批量大小、禁用刷新、减少副本

### 次要瓶颈：文档转换
- **已优化**: 使用向量化操作
- **剩余**: AS对提取仍需循环（无法完全向量化）

### 最小瓶颈：文件读取
- **速度**: 30万行/秒
- **优化空间**: 有限

---

**创建时间**: 2025-12-18

