# Outage检测详细说明

## 概述
Outage检测模块用于检测BGP路由中断事件。它通过分析BGP更新消息的时间序列特征，比较事件时间段和基线时间段，识别异常模式。

## 检测流程

### 1. 数据准备阶段 (`RouteOutageDetector.analyze`)

#### 1.1 时间窗口设置
- **事件窗口 (Event Window)**: 用户指定的时间段 `[start_time, end_time]`
- **基线窗口 (Baseline Window)**: `[start_time - 24小时, start_time)`，默认使用事件前24小时作为基线
- **数据文件查找范围**: `[baseline_start, end_time]`，覆盖基线和事件两个时间段

```python
baseline_start = start_dt - timedelta(hours=24)  # 默认24小时基线
plot_files = find_update_files(baseline_start, end_dt)  # 查找所有需要的BGP更新文件
```

#### 1.2 BGP更新文件查找
- 文件命名格式: `updates.YYYYMMDD.HHMM.txt` (每5分钟一个文件)
- 从 `data/updates_rrc00/decoded/` 目录查找
- 找到所有在时间范围内的文件

#### 1.3 时间序列提取 (`extract_timeseries_for_as`)
- 对每个BGP更新文件，提取与目标AS相关的消息
- 相关消息判断标准：
  - `peer_as` 等于目标AS，或
  - `as_path` 中包含目标AS
- 将消息按5分钟时间桶(bucket)分组处理

### 2. 特征提取阶段 (`_process_single_file_timeseries`)

对每个5分钟时间桶，提取以下特征：

#### 2.1 基础计数特征
- `announcement_count`: 宣告消息数量
- `withdrawal_count`: 撤销消息数量
- `total_messages`: 总消息数
- `announced_prefix_count`: 被宣告的前缀数量
- `withdrawn_prefix_count`: 被撤销的前缀数量
- `unique_prefix_count`: 唯一前缀数量
- `flapping_prefix_count`: 震荡前缀数量（既有宣告又有撤销的前缀）

#### 2.2 路由变化特征
- `ori_change_rate`: Origin AS变化率 = `num_ori_change / announcement_count`
- `num_ori_change`: Origin AS变化的次数
- `path_change_rate`: 路径变化率 = `(num_longer + num_shorter) / announcement_count`
- `num_longer`: 路径变长的次数
- `num_shorter`: 路径变短的次数

#### 2.3 异常行为特征
- `dup_A_rate`: 重复宣告率 = `num_dup_A / announcement_count`
- `num_dup_A`: 重复宣告次数
- `num_dup_W`: 重复撤销次数
- `avg_arrival_interval`: 平均消息到达间隔（秒）

#### 2.4 路径多样性特征
- `editDis_entropy`: 路径编辑距离的熵值（衡量路径多样性）
- `unique_as_count`: 唯一AS数量
- `avg_path_length`: 平均AS路径长度
- `max_path_length`: 最大AS路径长度
- `min_path_length`: 最小AS路径长度

### 3. 时间窗口分割 (`_split_windows`)

将提取的时间序列数据分为两部分：
- **事件时间序列 (event_ts)**: `start_dt <= timestamp <= end_dt`
- **基线时间序列 (baseline_ts)**: `baseline_start <= timestamp < start_dt`

### 4. 特征聚合 (`_aggregate_timeseries`)

将每个时间桶的特征聚合成总体特征：
- 对计数类特征：求和
- 对路径长度：计算平均值、最大值、最小值
- 生成 `event_features` 和 `baseline_features` 两个聚合结果

### 5. 异常检测阶段 (`detect_anomalies_timeseries`)

#### 5.1 基线统计计算
对基线时间序列中的每个特征，计算：
- `mean`: 平均值
- `std`: 标准差

#### 5.2 Z-score计算
对事件时间序列中的每个时间点，计算每个特征的Z-score：
```python
z_score = (event_value - baseline_mean) / baseline_std
```

#### 5.3 异常判断
如果满足以下任一条件，标记为异常：
- `abs(z_score) >= 3.0` (默认阈值)
- `std == 0` 且 `event_value != baseline_mean` (基线无变化但事件有值)

每个异常记录包含：
- `timestamp`: 异常发生时间
- `feature`: 异常特征名称
- `value`: 事件值
- `baseline_mean`: 基线平均值
- `baseline_std`: 基线标准差
- `z_score`: Z分数
- `anomaly_type`: 'high_increase' 或 'high_decrease'
- `severity`: 'high'

### 6. 评分阶段 (`_score_outage`)

#### 6.1 比率计算
计算事件特征相对于基线特征的比率：
```python
ratio = event_value / baseline_value
```

#### 6.2 指标检测
检查以下指标，如果满足条件则添加相应指标：

1. **announcement_drop**: `announce_ratio < 0.5`
   - 宣告数量下降超过50%

2. **withdrawal_surge**: `withdraw_ratio > 4.0`
   - 撤销数量增长超过4倍

3. **flapping_spike**: `flapping_ratio > 3.0` 且 `flapping_prefix_count > 20`
   - 震荡前缀数量增长超过3倍且绝对值>20

4. **prefix_disappearance**: `unique_prefix_ratio < 0.6`
   - 唯一前缀数量下降超过40%

5. **message_drop**: `total_msg_ratio < 0.5`
   - 总消息数下降超过50%

6. **timeseries_anomaly**: 如果存在时间序列异常
   - 检查异常特征是否在以下列表中：
     - `announcement_count`, `withdrawal_count`, `flapping_prefix_count`
     - `unique_prefix_count`, `ori_change_rate`, `num_ori_change`
     - `path_change_rate`, `dup_A_rate`, `avg_arrival_interval`
     - `editDis_entropy`, `unique_as_count`

#### 6.3 评分计算
根据检测到的指标，加权计算outage分数：
```python
score = 0.0
if "announcement_drop" in indicators:
    score += 0.3
if "withdrawal_surge" in indicators:
    score += 0.25
if "flapping_spike" in indicators:
    score += 0.2
if "prefix_disappearance" in indicators:
    score += 0.15
if "timeseries_anomaly" in indicators:
    score += 0.2
if "message_drop" in indicators:
    score += 0.1
score = min(1.0, score)  # 最高1.0
```

### 7. 最终判断阶段

#### 7.1 基础判断
```python
is_outage = outage_score >= 0.25  # 阈值0.25
```

#### 7.2 补充判断（如果基础判断为否）
1. **高严重性异常检查**:
   ```python
   high_severity_anomalies = [a for a in anomalies if abs(a.get("z_score", 0)) >= 3.0]
   if len(high_severity_anomalies) >= 2:
       is_outage = True
       outage_score = max(outage_score, 0.4)
   ```

2. **多特征异常检查**:
   ```python
   unique_features = set(a.get("feature") for a in anomalies if abs(a.get("z_score", 0)) >= 2.5)
   if len(unique_features) >= 3:
       is_outage = True
       outage_score = max(outage_score, 0.35)
   ```

### 8. 输出结果

返回包含以下信息的字典：
- `success`: 是否成功
- `asn`: 目标AS号
- `analysis_period`: 分析时间段
- `event_features`: 事件聚合特征
- `baseline_features`: 基线聚合特征
- `timeseries_event`: 事件时间序列（原始桶数据）
- `timeseries_baseline`: 基线时间序列（原始桶数据）
- `anomalies`: 检测到的异常列表
- `outage_score`: Outage分数 (0.0-1.0)
- `indicators`: 检测到的指标列表（包含详细信息）
- `is_outage_suspected`: 是否怀疑有outage
- `anomaly_count`: 异常总数
- `high_severity_anomaly_count`: 高严重性异常数量（z-score >= 3.0）

## 关键参数

- `baseline_hours = 24`: 基线时间窗口（小时）
- `min_required_buckets = 6`: 事件窗口最少需要的时间桶数量
- `BUCKET_MINUTES = 5`: 每个时间桶的时长（分钟）
- `Z_SCORE_THRESHOLD = 3.0`: Z-score异常检测阈值
- `outage_score_threshold = 0.25`: Outage判断阈值

## 检测逻辑总结

1. **数据收集**: 从BGP更新文件中提取与目标AS相关的消息
2. **特征提取**: 按5分钟时间桶提取多维特征
3. **基线对比**: 使用事件前24小时作为基线，计算统计量
4. **异常检测**: 使用Z-score方法检测时间序列异常
5. **模式识别**: 检测特定的outage模式（宣告下降、撤销激增等）
6. **综合评分**: 根据多个指标加权评分
7. **智能判断**: 结合评分和异常数量进行综合判断

## 为什么可能检测不到Outage？

1. **基线数据不足**: 如果基线时间段内数据不足，统计量不准确
2. **阈值设置**: 如果异常不够明显（z-score < 3.0），可能检测不到
3. **特征选择**: 如果outage的特征不在检测的特征列表中，可能遗漏
4. **时间窗口**: 如果事件窗口太短，可能无法捕获完整的outage模式
5. **数据质量问题**: 如果BGP更新文件缺失或格式错误，可能影响检测

## 改进建议

1. **降低阈值**: 当前z-score阈值3.0可能过高，可以降低到2.5或2.0
2. **增加特征**: 可以添加更多特征，如路径稳定性、AS路径多样性等
3. **动态基线**: 可以根据历史数据动态调整基线窗口
4. **多时间尺度**: 可以同时检测不同时间尺度的异常（5分钟、15分钟、1小时等）

