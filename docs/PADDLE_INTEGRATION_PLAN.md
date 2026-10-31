# PADDLE 集成与评测缺陷修复计划

## 一、已发现的根因缺陷

### 缺陷 1（严重）：`traffic_events_full` 的 `mean` 字段是占位符
- **位置**：`agents/correlation_analyzer.py:201` — `"mean": a.get("mean") or 0.001`
- **现象**：缓存中的每条 traffic 事件都带 `mean=0.001`，而真实历史均值在
  `traffic.anomalies[i].historical_mean`（例如 Telia Finland：真实 0.1554，
  占位符 0.001）。
- **后果**：
  - `traffic_deviation()` 从 `traffic_events_full` 读 `value` + `mean`，
    算得 `-8.24`（把 0.207 与 0.001 比），而从 `anomalies` 读
    `current_value` + `historical_mean` 算得 `+0.332`。
  - **符号被颠倒**：占位符让每个观测都变成"巨大负偏离"，trough 被强行
    拉到 `z_score` 最大的那一点，与真实流量塌陷点无关。
  - 正在运行的 `scripts/eval_paddle_archive.py` 第 1 个事件就是错的：
    `trough_deviation=-73.33`、`trough=03:45`，而真值是 `06:45`、`-0.994`。
- **修复**：`traffic_deviation()` 必须以 `anomalies` 的
  `current_value`/`historical_mean` 为准；`correlation_analyzer` 必须写入
  真实 `historical_mean` 而不是 0.001。

### 缺陷 2：`traffic_points()` 优先取错误的源
`scripts/eval_paddle_archive.py:113` 与 4 个同类脚本都按
`traffic_events_full` → `anomalies` → `traffic_events` 取第一个非空。
由于缺陷 1，`traffic_events_full` 总是非空，于是**永远取不到**带真实
基线的 `anomalies`。

### 缺陷 3：`same_clock_baseline()` 用日历日差
`agents/control_plane.py:292` — `(window_start.date() - stamp.date()).days`
在跨午夜窗口（如 21:30 → 06:00）下会把一半的匹配桶丢掉。

### 缺陷 4：生产缓存缺 `own_announcement_count`
16 个 ground truth 事件里 **0 个** 的 `outage_analysis.timeseries_event`
带 `own_announcement_count`（提取器已加，缓存是旧的）。
→ PADDLE 的 `own_volume` 通道在生产路径上不可用，必须重算缓存，
  或在 runtime 里从 archive 直接测量。

### 缺陷 5：四个 legacy 因果模块仍与 PADDLE 并存
`agents/{causal_baselines,css_engine,edge_ownership,cdpr_attribution,
cdpr_runtime,causal_attribution,falsification_test,_segmentation}.py`
仍存在，生产代码 `workflow_engine.py` / `chief_agent.py` 还在调用
`run_aea`。

## 二、修复顺序（每步做完再下一步）

1. **修数据层**：`traffic_deviation()` 以 `anomalies` 为准；
   `correlation_analyzer` 写真实 `historical_mean`。
2. **修 `same_clock_baseline()`**：改用 elapsed-seconds 的 age 检查。
3. **接线 PADDLE**：`workflow_engine.compute_hcaf_attribution` 与
   `chief_agent.post_react_hcaf` 改调 `paddle_runtime.run_paddle`。
4. **补 `own_*` 通道**：让 `paddle_runtime` 在生产路径上能拿到
   `own_announcement_count`（archive 测量，与评测一致）。
5. **重跑评测**（控制面证据已缓存 11 份，无需重扫）。
6. **删 legacy 模块 + 改测试** → `pytest tests/` 0 回归。

## 三、资源约束

- 机器 32 核、628 GB 内存；archive 扫描单个事件约 6.5 min / 8.9 亿行。
- 控制面证据已缓存 11 份（`results/eval/control_evidence/`），评测重跑
  不需要再扫 archive。
- 保持并行度 ≤ 4，避免打满服务器导致对话框断开。
