# ES导入常见问题

## 问题1: 数据源是什么？

**答案**: 是的，从`data/updates_rrc00/decoded/`目录读取`.txt`文件

代码位置：`data/updates_loader.py` 第148行
```python
decoded_dir = UPDATES_DIR / "decoded"
decoded_file = decoded_dir / f"updates.{time_str}.txt"
```

如果`.txt`文件不存在，会尝试读取`.gz`文件。

---

## 问题2: 重新导入会重复吗？

**当前情况**: **会重复导入** ❌

当前代码没有去重机制，如果重新导入相同时间段的数据，会重复插入。

**解决方案**: 需要添加文档ID去重机制（见下方优化方案）

---

## 问题3: 如何加速导入？

### 方法1: 增加批量大小 ⭐⭐⭐⭐⭐

```bash
python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2024-12-27 00:00" \
    --batch-size 5000  # 默认1000，增加到5000可提升2-3倍速度
```

### 方法2: 禁用索引刷新（导入期间）⭐⭐⭐⭐⭐

导入前：
```bash
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'
{
  "refresh_interval": "-1"
}'
```

导入后恢复：
```bash
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'
{
  "refresh_interval": "30s"
}'
```

**性能提升**: 3-5倍

### 方法3: 使用并行导入（多进程）⭐⭐⭐

可以修改脚本支持多进程导入不同时间段。

### 方法4: 减少副本数（导入期间）⭐⭐

```bash
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'
{
  "number_of_replicas": 0
}'
```

导入完成后恢复为1。

---

## 优化方案：添加去重功能

### 当前问题
- 没有文档ID，ES会自动生成，导致重复导入
- 重新导入相同时间段会重复插入

### 解决方案：使用唯一文档ID

基于以下字段生成唯一ID：
- `timestamp` + `peer_as` + `prefix` + `as_path`

这样可以：
1. **避免重复导入**: 相同文档只会更新，不会重复插入
2. **支持增量导入**: 可以安全地重新导入，只更新已存在的文档

---

## 快速导入1天数据

```bash
# 1. 禁用刷新（加速）
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'{"refresh_interval": "-1"}'

# 2. 导入（增加批量大小）
python scripts/import_updates_to_es.py \
    --start "2024-12-26 00:00" \
    --end "2024-12-27 00:00" \
    --batch-size 5000

# 3. 恢复刷新
curl -X PUT "localhost:9200/bgp_updates/_settings" -H 'Content-Type: application/json' -d'{"refresh_interval": "30s"}'
```

**预计时间**: 从3-4小时降低到 **1-2小时**

---

**创建时间**: 2025-12-18

