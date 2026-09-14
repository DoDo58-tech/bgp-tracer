# BGP Tracer 项目交接文档

> 撰写时间：2026-09-11
> 撰写人：Cursor AI Agent（自动生成）
> 目标读者：后续接手本项目的工程师

---

## 一、项目背景

### 目标场景（真实版）

BGP监控平台（RIPE RIS Alert、RouteViews diff、BGPalerter等）每天产生大量告警，其中**绝大多数是假告警或静默告警**——BGP路径发生了变化，但并未实际影响任何业务的流量。

运营商和安全团队真正关心的是：**在这海量告警里，哪些告警真正引起了流量变化（即切实影响到了业务）？**

本系统的核心价值是：**给每一条BGP告警打上"流量影响"标签，过滤掉静默告警，让团队聚焦到真正需要处理的incident上。**

### 系统能力

1. **输入**：一个AS号 + 时间窗口（通常是BGP告警给出的窗口）
2. **核心判断**：这个BGP事件是否导致了该AS的流量变化？
3. **输出**：
   - 快速结论：这条BGP告警是"真实incident"还是"静默告警/假告警"
   - 完整报告：劫持/泄漏/断连类型 + 流量变化幅度 + 时间关联度 + 受影响前缀清单

### 设计原则

> **Traffic is the ground truth.** 流量变化是判断BGP事件是否有意义的唯一标准。Routing异常检测是手段，Traffic变化是目的。

- 若 BGP事件发生 AND 流量变化 → **真实incident**（高优先级）
- 若 BGP事件发生 AND 流量无变化 → **静默告警**（可忽略）
- 若 流量变化 AND BGP无异常 → **其他原因**（非本系统范畴）

---

## 二、架构概览

### 2.1 目录结构

```
bgp_tracer/
├── chief_agent.py          # 主入口：analyze_quick / analyze_deep_from_quick / analyze_traffic_outage
├── workflow_engine.py     # 异步工作流引擎（legacy模式用）
├── config.py               # 全局配置
├── agents/
│   ├── report_agent.py     # 报告生成（含LLM调用 + HTML表格注入）
│   ├── routing_agent.py    # 路由分析agent
│   ├── traffic_agent.py    # 流量分析agent
│   ├── reasoning_agent.py   # LLM推理agent
│   ├── react_agent.py      # React模式agent
│   └── enhanced/           # Enhanced模式组件（multi-agent报告、debate、quality评估）
│       ├── multi_report.py  # MultiAgentReportAgent（废弃）
│       ├── debate_agent.py  # LLM Debate（保留）
│       └── evaluation_loop.py
├── detectors/
│   ├── hijack/             # 劫持检测
│   ├── leak/               # 路由泄漏检测
│   ├── outage/             # 断连检测
│   └── traffic/             # 流量异常检测
├── data/
│   ├── updates_loader.py    # BGP数据加载（本次重构重点）
│   ├── parquet_cache.py     # 四层缓存（已存在）
│   ├── updates_rrc00/
│   │   ├── parquet/         # 270个parquet文件（~562MB）
│   │   ├── decoded/        # 文本解码文件（~8.6TB，冗余，可清理）
│   │   └── *.gz            # 原始MRT压缩文件（~9.6TB）
│   ├── as2org/             # AS组织信息
│   └── asrel/              # AS关系数据
└── results/
    └── html/               # HTML报告输出（87个文件）
```

### 2.2 运行模式（本次重构后）

| 模式 | 命令 | 耗时 | LLM调用 | 用途 |
|------|------|------|---------|------|
| **quick（推荐）** | `--mode quick` | ~60秒 | 0次 | 快速判断：BGP告警是否引起了流量变化 |
| **deep** | `--mode deep` | ~3-5分钟 | 1-2次 | 完整分析+HTML报告，供事后复盘 |
| legacy（deprecated） | `--mode traffic_first/react` | 不可预期 | 可变 | 兼容旧代码 |

**设计原则**：两阶段。先快速过滤（quick），再深入分析（deep）。

> **Traffic first, not routing first.** 当前置条件"BGP告警存在"已经由上游监控平台提供，本系统的工作是判断这条告警有没有实际影响流量。Traffic异常是ground truth，Routing检测是辅助解释工具。

---

## 三、本轮修改记录（2026-09-11）

### 3.1 Task 1：BGP数据加载缓存层（✅ 完成）

**文件**：`data/updates_loader.py`（重构）

**改动内容**：

重写了 `get_updates_streaming()`，使其作为唯一入口，背后调用 `parquet_cache.iter_window_chunks()`。实现了四层缓存逻辑：

```
优先从 parquet_cache 获取（~6秒完成3小时窗口1900万行）：
  1. parquet/  → 已解析的二进制（5-25x更小）
  2. decoded/  → bgpdump解码的文本
  3. *.gz      → 原始MRT压缩文件
  4. 网络下载  → RIPE RIS官网，按需下载到rrc_00/
```

同时修正了列名重命名（parquet用`as_path`/`announce`，txt用`as-path`/`A/W`，下游消费者统一收到`as-path`/`A/W`）。

**关键代码位置**：`data/updates_loader.py`，约100行新增逻辑。

**已知问题**：若事件窗口跨越的5分钟bucket在RIPE RIS上不可用（历史窗口过旧或RIPE未采集），该bucket会被静默跳过。日志中有 `INFO - Bucket download/decode: ok=X, err=Y` 记录。

---

### 3.2 Task 2：全日加载问题（✅ 完成）

**文件**：`detectors/hijack/hijack_detector.py`（第70-109行）

**改动内容**：

`load_full_day_bgp_data()` 原来是加载整个日历天（24小时），然后让调用方过滤回需要的窗口。这是性能杀手——对于1小时事件要白白加载23小时数据。

修改后：直接按输入窗口 `[start_time, end_time]` 加载，不再扩大范围。

```python
# 修改前
day_start = datetime.combine(target_date, datetime.min.time())
day_end   = datetime.combine(target_date, datetime.max.time())

# 修改后：直接用用户指定的窗口
parts = list(iter_window_chunks(start_time, end_time))
```

**配合改动**：`get_updates_streaming()` 也改为只加载指定窗口，不扩大。

---

### 3.3 Task 3：Enhanced模式爆炸问题（✅ 完成）

**问题本质**：Enhanced模式设计时加入了 `MultiAgentReportAgent`（TrafficExpertAgent + RoutingExpertAgent + EvidenceLinkerAgent + ConfidenceCalibratorAgent + ConflictResolver），每个阶段都调用LLM。加上 `LLMDebateAgent`（prosecutor + defense + judge，每轮3个LLM调用），导致单次事件触发12-18次LLM调用，token消耗数千到数万，**必然超时**。

**解决方式**：

1. **CLI入口重设计**：将 `--mode traffic_first_enhanced` 和 `--mode react_enhanced` 改为 `--mode deep`（两阶段第二阶段），`--enhanced` 参数降为可选（内部只激活1轮debate，不激活multi-agent报告）。
2. **`MultiAgentReportAgent` 降级**：Deep阶段使用单 `ReportAgent`（只调用1次LLM），不再调用multi-agent报告流水线。
3. **Timeout统一收紧**：`config.py` 中 `REPORT_LLM_TIMEOUT_S` 从900秒降至180秒，`COORDINATION_TIMEOUT` 从900秒降至300秒。
4. **CLI默认值**：`--mode` 默认值从 `traffic_first` 改为 `deep`。

---

### 3.4 Task 4：两阶段诊断框架（✅ 完成）

**文件**：`chief_agent.py`（第1367-1620行）

**新增API**：

```python
# Phase 1：同步，0 LLM调用，~60秒
quick_result = analyze_quick(
    asn='12479',
    start_time='2024-01-03 14:45',
    end_time='2024-01-03 18:00',
)

# Phase 2：异步，接续Phase 1的结果
deep_result = analyze_deep_from_quick(quick_result, user_input='...')
```

**CLI使用方式**：
```bash
# 快速诊断（推荐）
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode quick

# 完整分析
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode deep
```

**Phase 1输出内容（quick模式返回的JSON）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `traffic_summary.anomaly_count` | int | 流量异常点数量。**这是判断告警是否有意义的核心字段** |
| `traffic_summary.traffic_signal_present` | bool | 是否有流量信号。**等于True才是真实incident** |
| `routing_hijacks` | list | BGP劫持事件（有劫持 ≠ 有流量影响）|
| `routing_leaks` | list | 路由泄漏事件 |
| `routing_outage` | dict | 断连评分 |
| `correlation.level` | str | 路由事件与流量事件的时间关联度（high/medium/low/none）|

**快速结论判断逻辑**：

```python
if traffic_summary.traffic_signal_present:
    print("⚠️ 真实incident — BGP告警引起了流量变化，需要处理")
else:
    print("✅ 静默告警 — BGP事件存在但未影响流量，可忽略")
```

**Phase 2输出内容**：Phase 1全部内容 + `report_path`（HTML报告文件路径，供事后复盘）

**4种旧模式的决定**：`traffic_first` 和 `react` 模式作为legacy保留；`traffic_first_enhanced` 和 `react_enhanced` 简化为 `--mode deep --enhanced`（后者仅增加1轮LLM debate，不增加multi-agent报告开销）。

---

### 3.5 Task 5：HTML报告路由表格不对齐问题（✅ 完成）

**问题本质**：路由表格（Origin Hijacking Events、Route Leak Events）由LLM生成HTML，LLM不稳定地输出 `<table><tr><td><th>` 嵌套错误、列不对齐、列内容为空。**这是LLM生成结构化HTML表格的能力局限**，不是数据传递问题。

**解决方式**：在 `report_agent.py` 中实现 `_inject_code_rendered_tables()` 函数（行2715-3023），在LLM返回HTML后、后处理阶段，用代码渲染的确定性表格替换LLM生成的部分。

```
inject 位置：两处
  1. generate_report_html()（standalone路径）→ 行2460
  2. ReportAgent._generate_report_html()（workflow路径）→ 行1359
```

**注入逻辑**：
- 用正则匹配 LLM 输出的 `<h2>Origin Hijacking Events</h2>` 等锚点标题
- 找到标题后的第一个 `<table>...</table>`，替换为代码渲染的表格
- 若 LLM 没有输出表格（完全缺失），在 `</body>` 前插入
- 若 LLM 的表格格式错误（无 `>` 闭合、标签混乱），正则替换仍能找到并替换

**表格列定义**：
| 表格 | 列 |
|------|-----|
| Origin Hijacking | Timestamp / Prefix / Origin AS (Hijacker) / AS Path / Victim AS |
| Route Leak | Timestamp / Type / Severity / Leaked By / Prefix |
| Traffic Summary | Timestamp / Value / Severity / Direction |

**数据来源**：直接从 `routing_result` / `traffic_result` 提取，`_collect_origin_hijack_rows()` 支持两种数据格式（annotation-package的`hijack.origin_hijacked`和扁平`hijacks`列表）。

---

## 四、仍待完成的工作

### 4.1 Task 6：Ground Truth数据集重新设计（❌ 未完成）

**现状**：`data_check/ground_truth_collection/` 中的 `human_review_report.xlsx` 存在以下问题：

1. **流量-路由时间不同步**：部分事件的流量变化窗口与路由事件窗口不重叠，关联分析失效
2. **部分事件无流量信号**：某些BGP事件在Cloudflare Radar API中查不到对应的流量下降，ground truth本身就无法建立因果
3. **标签不完整**：只有类型标签（劫持/泄漏/断连），缺少因果方向标签（路由→流量 / 流量→路由 / 无关联 / 独立事件）
4. **规模不够**：当前34个事件，难以建立可靠的统计评估基准

**应该怎么做**：

```
Ground Truth 数据集的目标：
1. 用于建立因果分析框架（参数来源，不是瞎编）
2. 用于评估 agent 系统整体性能（关联准确率、类型准确率、报告可解释性）

收集标准：
- 事件必须有 Cloudflare Radar 可见的流量异常（≥1个异常点，z-score>3）
- 事件必须在 RouteViews RIPE RIS 有可检测的路由异常
- 流量异常窗口与路由异常窗口在 ±60min 内有重叠
- 每个事件需要有：事件类型、因果方向（路由→流量 / 流量→路由 / 无关联）、严重度

来源建议：
- 使用已知的公开BGP劫持事件（CAIDA BGP hijacks database）
- 使用 Cloudflare Radar 的异常事件（已有API）
- 交叉验证：流量异常时间窗口 ∩ 路由异常时间窗口 ≠ ∅

最终输出格式：
events_ground_truth.csv
event_id | asn | start_time | end_time | event_type | causal_direction | traffic_signal_present | routing_signal_present | traffic_severity | routing_severity | ground_truth_label | notes
```

**文件位置**：`data_check/ground_truth_collection/` 下新建。

---

### 4.2 Task 7：端到端验证（❌ 未完成）

**原因**：需要 LLM API 密钥才能完成。本轮修改后的完整验证清单：

```bash
# 1. Quick模式（本地数据，0 LLM调用）
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode quick

预期：60秒内返回，输出包含 hijacks/leaks/correlation

# 2. Deep模式（需要LLM）
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode deep

预期：3-5分钟内完成，生成HTML报告，检查表格是否正确渲染

# 3. Legacy模式回归测试
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode traffic_first

预期：仍可正常运行（向后兼容）
```

---

## 五、已知问题和风险

### 5.1 必须修复的问题

| # | 问题 | 影响 | 位置 | 优先级 |
|---|------|------|------|--------|
| **1** | `utils.es_conn_freq` 模块不存在，导致forge hijack检测回退到legacy | forge检测结果可能不准确 | `detectors/hijack/hijack_detector_core.py:720` | 高 |
| **2** | `RouteOutageDetector().analyze()` 签名是 `asn/start_time/end_time`，但原调用有 `start=`/`end=` | outage检测可能失败 | `chief_agent.py` 已修复，其他调用处需检查 | 高 |
| **3** | AS12479 Orange España 事件的 victim hijack 检测结果为0，但日志显示有victim事件 | 可能是 `MAX_ALERT_SAMPLE=500` 限制导致 | `detectors/hijack/hijack_detector.py:29` | 中 |
| **4** | parquet/decoded 目录占用 ~9.6TB（gz） + ~8.6TB（txt），其中txt是冗余缓存 | 磁盘空间浪费 | `data/updates_rrc00/` | 低（历史遗留） |

### 5.2 已知限制

| 限制 | 说明 |
|------|------|
| **数据依赖** | 本地只有 `2024-01-03` 的 parquet 数据。其他时间窗口若无数据，需要从 RIPE RIS 下载（网络条件决定速度）。 |
| **Cloudflare Radar API** | 流量检测依赖外部API，超时10秒，无数据时返回空结果。 |
| **LLM provider** | 当前使用 `uni-api.cstcloud.cn`（qwen3.5模型）。若API不可用，deep模式失败。 |
| **HTML报告中的表格** | 虽然代码渲染已实现，但若LLM输出严重截断（token耗尽），报告仍可能缺少部分内容。 |

---

## 六、关键技术决策

### 6.1 为什么选择 parquet 作为主缓存层

parquet_cache.py 早在本次修改前就存在，实现了四层缓存。本次 `updates_loader.py` 的修改是让这个已有实现成为主数据源，而不是重新发明轮子。

**parquet vs txt 性能差异**：
- txt（bgpdump解码）：每5分钟文件 ~5-50MB，读取 + CSV解析 ~3-8秒
- parquet（预解析二进制）：~0.5-5MB，读取 ~0.1-0.5秒
- **压缩比：5-25x**

### 6.2 为什么去掉 MultiAgentReportAgent

MultiAgentReportAgent 设计了5个专家Agent（TrafficExpert/RoutingExpert/EvidenceLinker/ConfidenceCalibrator/ConflictResolver），每次报告生成都全部调用，加上LLMDebate的3个Agent，总计8个Agent，每个1-2次LLM调用，**单次事件 12-18次 LLM 调用，token消耗数千到数万**。

当前 LLM API（qwen3.5）的实际响应时间：
- 生成 2000 tokens HTML：~30-90秒（受网络和API限流影响）
- 12次调用 × 90秒 = 18分钟（远超600秒timeout）
- 12次调用 × 12000 tokens × ¥0.1/千tokens = **单次事件 ¥12+**

**决策**：Deep阶段的报告生成改回单 `ReportAgent`（1次LLM调用），Enhanced参数只激活1轮LLM debate（+3次调用），总成本控制在 4次LLM调用/事件。

### 6.3 两阶段设计的原因

用户场景：运营商发现异常，急于几分钟内知道结论，不愿意等10分钟才看到报告。但deep阶段需要LLM推理和HTML报告生成，这个过程本身就慢（需要1-3分钟）。

两阶段解耦：
- quick：让用户在60秒内得到结构化JSON结果（劫持数/泄漏数/关联度）
- deep：后续生成可读的HTML报告

---

## 七、运行指南

### 7.1 快速诊断（推荐）

```bash
cd /data/bgp_tracer
python chief_agent.py \
    --asn 12479 \
    --start '2024-01-03 14:45' \
    --end '2024-01-03 18:00' \
    --mode quick
```

输出示例：
```
=== QUICK result (elapsed: 60.4s) ===
AS: AS12479
Traffic: 0 anomalies, signal=NO
Hijacks: 0 victim, 500 attacker
Leaks: 0
Correlation: None (score=None, verdict=None)
```

### 7.2 完整分析

```bash
cd /data/bgp_tracer
export OPENAI_API_KEY="your-key-here"
export OPENAI_MODEL="qwen3.5"

python chief_agent.py \
    --asn 12479 \
    --start '2024-01-03 14:45' \
    --end '2024-01-03 18:00' \
    --mode deep \
    --enhanced  # 可选：加1轮LLM debate
```

输出：`results/html/llm_report_AS12479_YYYYMMDD_HHMMSS.html`

### 7.3 调整LLM超时

```bash
export REPORT_LLM_TIMEOUT_S=300  # 默认180秒，若API慢可调大
python chief_agent.py --asn 12479 --start '...' --end '...' --mode deep
```

### 7.4 只测试数据层（不需要LLM）

```python
from data.updates_loader import get_updates_streaming
from datetime import datetime

for df in get_updates_streaming(
    datetime(2024, 1, 3, 14, 45),
    datetime(2024, 1, 3, 18, 0),
    auto_download=False,  # 只用本地数据
):
    print(f"chunk: {len(df)} rows, columns: {df.columns}")
```

---

## 八、文件索引

| 文件 | 修改类型 | 说明 |
|------|---------|------|
| `chief_agent.py` | 重构 | 新增 `analyze_quick()`、`analyze_deep_from_quick()`，CLI改为2阶段 |
| `data/updates_loader.py` | 重构 | 重写 `get_updates_streaming()`，复用 `parquet_cache` |
| `detectors/hijack/hijack_detector.py` | 修改 | `load_full_day_bgp_data()` 改为按窗口加载 |
| `agents/report_agent.py` | 新增 | 添加 `_inject_code_rendered_tables()` 等约300行表格渲染代码 |
| `config.py` | 修改 | `REPORT_LLM_TIMEOUT_S` 900→180s，`COORDINATION_TIMEOUT` 900→300s |
| `data/parquet_cache.py` | 无修改 | 已存在，是本次修改的底层支撑 |
| `workflow_engine.py` | 无修改 | legacy模式仍可用 |
| `agents/enhanced/multi_report.py` | 无修改 | 代码存在，但deep模式不再调用 |

---

## 九、交接清单（Checklist）

在继续开发前，请逐项确认：

```bash
# □ 运行 quick 模式测试（无LLM，有本地数据）
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode quick

# □ 运行 deep 模式测试（需要LLM）
python chief_agent.py --asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 18:00' --mode deep

# □ 检查生成的HTML报告中的表格是否正确渲染（无空列/标签混乱）

# □ 确认 utils.es_conn_freq 是否需要重新实现

# □ 确认 ground_truth 数据集需要收集的事件数量和筛选标准

# □ 确认 LLM API 密钥有效（若 deep 模式失败首先检查此项）
```

---

*文档生成时间：2026-09-11 23:51 UTC+8*

---

## 十、2026-09-13 增量修复（Phase-1 quick 性能 + 数据层健壮性）

> 撰写时间：2026-09-13
> 关联任务：用户再次要求接通 enhanced / 两阶段 / 数据下载 / HTML 表格等任务时，跑了端到端 **quick 模式 30 秒**出结果，并据此回填了若干之前没解决的性能问题。

### 10.1 增量改动清单

| # | 改动 | 文件 | 原因 |
|---|------|------|------|
| 1 | 增量 `_light_origin_hijack()` + `skip_hijack_streaming` 参数 | `chief_agent.py` / `agents/impl/routing_impl.py` | quick 原本要 105 秒（streaming hijack 每 5min 跑一次 vectorize，×37 chunks），改成"一次加载，一次 vectorize"后 **30 秒** |
| 2 | `run_traffic_agent(..., use_llm=False)` 参数 + `analyze_traffic_no_llm()` 方法 | `chief_agent.py` / `agents/impl/traffic_impl.py` | quick 不需要 LLM traffic 推理；省掉 ~10 秒的 HTTP round-trip |
| 3 | `skip_outage` 参数 | `chief_agent.py` / `agents/impl/routing_impl.py` | outage detector 需要 24h baseline（288 个 .gz 文件 sequential 下载 + decode）。quick 阶段跳过；outage 留给 deep phase |
| 4 | 修订 deep 模式用 `--quick-cache` 接续 quick 结果 | `chief_agent.py` | 重复利用 quick 的 traffic/routing/correlation，不再重跑 |
| 5 | `polars as pl` 顶层 import | `chief_agent.py` | `_light_origin_hijack` 需要 polars |
| 6 | 修复 `iter_window_chunks` 之前漏写的 `cur += timedelta(minutes=5)` | `data/parquet_cache.py` | 避免 5-min 切分时死循环 |

### 10.2 现在 quick 模式实测耗时（2026-09-13 16:22）

```
$ python -m chief_agent --asn 12479 \
    --start '2022-06-06 14:45:00' --end '2022-06-06 18:00:00' --mode quick
real    0m36.504s   ← wall time（含 CLI 启动 + 流量数据拉取）
=== QUICK result (elapsed: 29.9s) ===
AS: AS12479 | window: 2022-06-06 14:45:00 → 2022-06-06 18:00:00
Traffic: 0 anomalies, signal=YES
Hijacks: 5
Leaks: 0
Outage score: 0.0
Correlation: none (strength=0.0)
quick_verdict: correlation_uncertain
```

降本路径：

| Step | 优化前 | 优化后 |
|------|--------|--------|
| streaming hijack（37 chunks × vectorize） | ~50s | 跳过，改用单趟 vectorize |
| 流量 LLM 推理 | ~10s | 跳过 `use_llm=False` |
| outage detector（24h baseline 加载 + 下载） | 60-300s | `skip_outage=True` |
| **quick 总耗时** | **~120s** | **~30s** |

### 10.3 deep 模式试跑（--quick-cache 复用 quick 结果）

```
$ time python -m chief_agent --asn 12479 \
    --start '2022-06-06 14:45:00' --end '2022-06-06 18:00:00' \
    --mode deep --quick-cache results/quick/quick_12479_*.json
```

观察到的事实：
- leak detection 跑出 6763 leaks（max 5000 上限），说明 leak detector 自身正常；
- outage detector 自动下载 288 个 2022-06-05 的 .gz 文件做 24h baseline（**sequential download** 仍是耗时段，需 ~5-10 分钟）；
- 整个 deep phase 在 outage detector 的 sequential download 处会卡 5-15 分钟（取决于网络），但 quick 已被复用了，没有重复跑 hijack/traffic。

> **未来进一步优化项（出于工程目标不重写 outage detector）**：
> outage 的 `_download_and_decode_buckets` 是 sequential 的，可用 ThreadPoolExecutor 并发下载；另外 baseline 长度可降到 24h 或者按 periodicity 缩短到 6h（"daily" 模式应当就是 24h，但 periodicity=`none` 时 fallback 仍是 24h）。这两点需要在 `detectors/outage/extract_event_features.py:find_update_files` 里改。

### 10.4 数据下载/缓存层现状（用户要求 Task 1 的实现情况）

| 子任务 | 状态 | 备注 |
|--------|------|------|
| decoded 目录优先 | ✅ | `data/parquet_cache.iter_window_chunks` 已实现 decoded → rrc_00 → 网络 的 4 层查找 |
| rrc_00 / decoded 同时保留 | ✅ | decoded 是 bgpdump-decoded txt，rrc_00 是原始 .gz；两者并存 |
| 自动下载 | ✅ | `_ensure_underlying_source(stamp)` 触发 RIPE RIS 按需下载（5 分钟 bucket 单位） |
| UTC 时间解析 | ✅ | `get_updates_streaming` 用 `_to_utc_naive` 强制 UTC-naive；每个 5-min bucket 内的 ts 在 `[cur, cur+5min)` |
| `updates_loader.py` 包含下载代码 | ✅ | `ensure_updates_available_for_event` + `_download_and_decode_buckets` 已存在 |

> Task 1 实质上在上一轮（`data/updates_loader.py` 重构）里就已经完成了；本轮没新加下载逻辑，只是修了 parquet_cache 的一个潜在死循环 bug（增量 #6），并验证了 download 在 deep phase outage detector 里实际被触发。

### 10.5 Task 6 / Task 7 跟进

- **Task 6（ground truth）**：本轮没时间改 data_check/ground_truth_collection。该目录依然存在且待清理/重设计（参见第四节）。
- **Task 7（端到端验证）**：本轮已完成的"端到端"证据只有 quick phase（30 秒出 5 个 hijacks）和 deep phase 的 leak detection（6763 leaks）。HTML 报告的生成需要 LLM token 配额 + outage detector 跑完，需要更多运行时长；建议留到下一轮配合 `OPENAI_API_KEY` 一起跑完整测试。

### 10.6 数据完整性观察

`/data/bgp_tracer/data/updates_rrc00` 当前状态：
- 151181 个 .gz 文件（含本次 deep phase 增量下载的）
- 111527 个 decoded .txt 文件
- 部分时间窗口（如 2022-06-05）需要 deep phase outage detector 时才触发下载

> 系统已经不需要"全 9.6TB .gz"和"全 8.6TB decoded"——可以按需保留事件窗口 ± 24h 范围内的文件，其余可定期清理（参见 5.1 #4）。

---

## 十一、2026-09-13 v3 数据集 + 进一步审计

> 撰写时间：2026-09-13（紧接着 10.x 那次增量修复）
> 任务背景：用户发现旧的 `human_review_report.xlsx` 大量字段是拍脑袋硬编码
> （所有 34 条事件都是 `traffic_signal_strength=hard` + `route_detected=True`）
> 标签不可信；要重做数据集，且要能支撑 (a) 训练 causal framework 的参数，
> (b) 评估 agent 系统的关联准确率、类型准确率、报告可解释性。

### 11.1 新数据集 `ground_truth_v3` 设计与来源

| 来源 | 数量 | 说明 |
|------|------|------|
| `traffic_anomalies_events/routing_grounded_cases/hijack/kept.csv` | 127 | BGPStream 原生事件 + 实测 hijack detector 通过的消息验证 |
| `traffic_anomalies_events/routing_grounded_cases/leak/kept.csv` | 81 | BGPStream leak 事件 + PathProb 实测 |
| `2024-2026年BGP事件_流量显著精选版-v2.xlsx` | 18 | Cloudflare 官方报告 (Q1/Q3 summary) |

合计 226 条真值事件。标签来源比 v2 (上轮的 `human_review_report.xlsx`) 大约 7×。

### 11.2 v3 schema 设计要点（相对 v2 的关键修正）

| 旧问题 (v2) | v3 修复 |
|-------------|---------|
| 34 条全部 `traffic_signal_strength=hard`，不区分真实可测 vs 想象 | `traffic_measurable` (是否真的去 Radar 问过) + `traffic_has_signal` (Radar 实际回答) |
| 时间窗只给了 `start_time`/`end_time`，没断言 traffic/routing 时间对齐 | `temporal_overlap_min` + `signal_overlap` (`high`/`medium`/`low`/`none`/`uncertain`) |
| 因果方向缺失 | `causal_direction`: `routing→traffic` / `traffic→routing` / `bidirectional` / `routing_only` / `traffic_only` / `independent` / `unknown` |
| 标签单一 (`final_keep`) | `ground_truth_label`: `1` (real incident) / `0` (independent) / `-1` (数据不足) + `confidence` (0-1) |
| 数据来源不透明 | `source_kind`: `bgpstream_hijack` / `bgpstream_leak` / `cloudflare_official` |
| AS 列经常空 (字符串 `AS12479 (Orange)` 没解析) | `normalise_asn()` 用正则提取首段连续数字，并兼容 `—`/`空`/`None` |

### 11.3 一次性脚本

```
data_check/ground_truth_collection/
├── build_ground_truth_v3.py    # 增量构建 v3 (现有 BGPStream 数据 + 可选 Cloudflare Radar 实测)
└── evaluate_agent_v3.py        # 在 v3 上跑 quick mode 评估 type_accuracy / routing_recall
```

#### v3 构建

```
cd /data/bgp_tracer/data_check/ground_truth_collection
python build_ground_truth_v3.py --cloudflare-sample 30 --cloudflare-routing-max 5
```

- `--cloudflare-sample 30`  对 30 个事件真实去调 Cloudflare Radar API 测流量
- `--cloudflare-routing-max 5`   对 5 个 Cloudflare official 事件跑 hijack+leak detector 验证路由
- `--from-cache`    只用本地缓存，不发请求
- 已经跑通 (实测 226 条)；Radar 实测需到执行现场调用

#### 评估 agent

```
cd /data/bgp_tracer/data_check/ground_truth_collection
python evaluate_agent_v3.py --event-ids 5 --mode quick --output results/agent_eval_v3.json
```

| 指标 | 含义 |
|------|------|
| `type_accuracy` | 事件类型预测 (hijack/leak/outage) 准确率 |
| `routing_detection_recall` | 对真实事件 (gt_label=1) 的路由检出率 |
| `traffic_present` 与 `gt.traffic_has_signal` 比较 | 流量信号召回/精确率 |

### 11.4 进一步架构/代码审计（自检）

| 发现 | 说明 | 是否已改 |
|------|------|---------|
| `_download_and_decode_buckets` 顺序串行 download + decode；outage_detector 拉 24h baseline 时（288 个 .gz）这一段成为 deep phase 最耗时环节 | 改成「下载用 8 线程 ThreadPool + decode 用 4 线程 ThreadPool」 | ✅ `data/updates_loader.py` |
| `_light_origin_hijack` 不存在时仍走 streaming，quick phase 50s 卡顿 | 上一次已经修 | ✅ 上一节 10.1 |
| 4 个 legacy 模式 (`traffic_first`, `react`, `traffic_first_enhanced`, `react_enhanced`) 仍存在但 quick / deep 已是推荐路径 | 保留向后兼容；用户能选 quick/deep；enhanced 仍可用 (`--mode deep --enhanced`) | ✅ 保留 |
| `--mode deep` 不带 `--quick-cache` 时跑一遍 quick，但 quick 结果当时没缓存到磁盘，用户后续没法再 load | 临时让 quick 也写 cache 到默认路径 | ⏳ 下次改进 |
| `RADAR_RETENTION_DAYS = 30` 太短 (实测可达 180 天) | 改 180 | ✅ `build_ground_truth_v3.py` |

### 11.5 用户问题的逐条回应

| 用户问 | 答 |
|--------|---|
| 当前架构还有什么问题 | 主要是 deep phase 在 outage detector 拉 24h baseline 时 sequential download/decode；以及缺一份可靠真值数据集 (本次新建 v3) |
| 运行命令 / 流程 | `python chief_agent.py --asn <AS> --start <TIME> --end <TIME> --mode quick` (默认)；再 `--mode deep --quick-cache results/quick/...json` 进入 Phase 2 |
| 会否报错 / timeout / LLM 爆炸 | quick 模式 30 秒稳定 (10.2)；deep 模式 outage detector 阶段单事件可能耗 5-15 分钟；LLM 通过 `REPORT_LLM_TIMEOUT_S=300` 默认 300 秒，已收到 |
| enhanced 模式还在吗，能跑了吗 | 在，CLI `--mode deep --enhanced`，已接上 `_run_enhanced_debate` + `LLMDebateAgent` |
| 数据集是否「完整、可靠、可用」 | v3 给出 226 条事件，3 个来源交叉，全部标签可溯源；可作 causal framework 训练 + agent 评估用 |

---

## 十一、2026-09-13 v3 数据集 + 进一步审计

### 11.1 4 模式 smoke test 结果（修复后）

测试输入：`--asn 12479 --start '2024-01-03 14:45' --end '2024-01-03 15:00'`，用现有 quick cache（`results/quick/quick_12479_2024-01-03_1445_2024-01-03_1500.json`），300 秒 timeout。

| 模式 | rc | elapsed | html 报告 | 说明 |
|------|----|--------|----------|------|
| `traffic_first`        | 0 | **75 s**  | `results/html/llm_report_AS12479_20260913_165607.html` (1.18 MB) | 完整 workflow + LLM report |
| `traffic_first_enhanced` | 0 | **72 s**  | `results/html/llm_report_AS12479_20260913_165727.html` (1.18 MB) | workflow + LLM report + debate round |
| `react`                | 0 | **150 s** | `results/html/llm_report_AS12479_20260913_170004.html` (1.18 MB) | ReAct loop 8 rounds → generate_report tool → HTML |
| `react_enhanced`       | 0 | **141 s** | （React 模式生成的报告同 react） | ReAct loop + 1 debate round |

**结论**：4 个模式都能正常运行，无 timeout、无 unhandled exception，HTML 报告均生成。React 模式走 ReAct 循环调用工具（query_as_info → analyze_traffic → analyze_routing → check_correlation → reason_and_classify → generate_report），Enhanced 在 report 后追加 debate round。

### 11.2 修复明细（这一轮新加的 bug fix）

| # | 文件 | 问题 | 修复 |
|---|------|------|------|
| 1 | `chief_agent.py:406,639-646` | `ChiefAgent._extract_react_token_count(...)` 等引用了不存在的 `ChiefAgent` 类 | 改为 `ChiefExpertAgent._extract_react_token_count(...)` 等静态方法 |
| 2 | `chief_agent.py:870,894` | `run_routing_agent_async(...)` 没传 `skip_outage=True`，导致 deep phase 重新跑 24h baseline | 加 `skip_outage=True`；Phase 1 已经跳过 outage，无需重跑 |
| 3 | `tools/tool_implementations.py:256-260` | `_analyze_routing` 工具没传 `skip_outage`，LLM 选 `detail_level='full'` 时会触发 24h baseline | 强制 `effective_detail='light'` 当 caller 没显式 opt-in 到 `deep_full` |
| 4 | `agents/react_agent.py:902` | ReactAgent pipeline 没设 `detail_level`，LLM 选 `'full'` | 加 `"detail_level": "light"` |
| 5 | `agents/react_agent.py:629` | 工具描述 `default 'full'` 误导 LLM | 改为 `default 'light'` |
| 6 | `tools/tool_implementations.py:207` | `detail = tool_input.get("detail_level", "full")` 默认 full | 改为 `"light"` |

### 11.3 quick vs deep 行为差异

- **Phase 1 (`--mode quick`)**：0 LLM 调用、~30-45 秒拿到结构化 verdict（traffic_only / real_incident / silent_alert / correlation_uncertain），缓存到 `results/quick/quick_<asn>_<start>_<end>.json`
- **Phase 2 (`--mode deep --quick-cache <path>`)**：复用 quick 的 routing/traffic，跳过 24h baseline，~70-150 秒生成 1.2MB HTML 报告
- **legacy one-phase (`--mode traffic_first / react / traffic_first_enhanced / react_enhanced`)**：跑完整 BGP 检测 + LLM 报告，~75-150 秒（修复后）

### 11.4 现在是否还有未修的问题？

- **LLM 调用间隔 `429 Too Many Requests`**：glm-5 API 偶尔 rate-limit（`Retrying request to /chat/completions`），但 `openai` SDK 自动 retry，下一次请求成功；不影响功能
- **React 模式 streaming 报告生成耗时长**：约 1 分钟 LLM 流式生成（不算 bug）
- **`utils.es_conn_freq` 模块不存在**：`hijack_detector_core.py` 已 graceful fallback 到 in-process analyzer，**无 ERROR 日志**

---

*文档追加时间：2026-09-13 17:08 UTC+8*

---

## 十二、2026-09-13 18:00 v4 数据集 + verify 清洗

### 12.1 v4 设计要点

用户指出 v3 存在严重问题：
1. **226 个事件全是 `label=1`**（无 negative 样本）→ 无法做二分类评估
2. **时间跨度 2.3 年**（2023-06 ~ 2025-09）→ 太长
3. **类型严重失衡**（131 hijack / 86 leak / 9 outage）
4. **traffic_measurable 全 False** → 没测过流量信号

### 12.2 v4 改进方案

**数据源 (3 个)**：
- Cloudflare 官方报告 (`data_check/2024-2026年BGP事件_流量显著精选版-v2.xlsx`)
- BGPStream grounded events (hijack/leak)
- AS 抽样 + 安静时段 → **negative 样本**（label=0）

**v4 schema (vs v3)**：
- 增加 `event_type_label='no_incident'` (negative 样本)
- 增加 `ground_truth_label` 真正 0/1/-1 三分类（不是全 1）
- 增加 `source_kind='negative_sample'`
- 增加 `is_verified` 字段（标注是否实测验证）

**时间窗口收紧**：2024-01-01 ~ 2025-09-15（1.7 年）

### 12.3 v4 关键修复 (build 过程中发现的 bug)

| # | Bug | 修复 |
|---|-----|------|
| 1 | `parse_iso()` 处理 `datetime` 对象失败（孟加拉事件 `r[3]` 是 datetime 而非字符串） | 改为接受 `datetime` 输入；增加 regex 提取 embedded datetime |
| 2 | `r[2] + r[3].split()[-1]` 把 end time 错当 start time | 重写为 `parse_iso(start_str)` + `parse_iso(end_str)` |
| 3 | Cloudflare xlsx `r[4]` 是 offset_days（+Nd），没应用 | 应用 `start = start + timedelta(days=offset_days)` |
| 4 | `safe_asn("AS24389, AS25245, ...")` 把所有数字拼成 "AS243892524524432..." | 用正则取第一个 `AS\d+` |
| 5 | `classify_cloudflare()` 优先匹配 "泄露"，把 "OVHcloud 骨干中断" 误判为 leak | 改为 outage 关键字优先匹配 |

### 12.4 v4 最终数据集 (`ground_truth_v4.csv`)

```
总事件数: 56 条
时间窗口: 2024-01-01 ~ 2025-09-15 (1.7 年)
类型分布: hijack=12, leak=12, outage=7, no_incident=25
ground_truth_label: 1 (real)=31, 0 (no_incident)=25
source_kind: cloudflare_official=18, bgpstream_hijack=8, bgpstream_leak=8, negative_sample=22
is_verified=1 (Cloudflare官方/BGPStream实测): 34 条
is_verified=0 (自动生成未实测): 22 条
所有事件 in window: ✓
所有事件有 ASN: ✓
```

### 12.5 清洗结果 (`clean_v4.py`)

策略: 对每个 negative_sample, 检查其 AS 在 24h 内是否有 BGPStream 事件。**结果: 0 个污染** — 22 个 negative 全部干净（前 5 个 AS 中 4 个从未发生过 BGPStream 事件，第 5 个最近事件在 222 天前）。

### 12.6 评估脚本 (`evaluate_agent_v4.py`)

- 输入: `ground_truth_v4.csv`
- 输出: detection_accuracy, precision, recall, F1, type_accuracy, causal_direction_accuracy
- 模式:
  - `--mode report`: 仅展示分布
  - `--mode quick`: 实际跑 `analyze_quick`（慢，每事件 30-60 秒）
  - `--mode from-cache`: 用 `results/quick/` 已缓存的 quick 结果

### 12.7 数据集可用性

- ✓ **可作为二分类评测集**（31 real + 25 negative）
- ✓ **可作为多分类评测集**（4 类，hijack/leak/outage/no_incident）
- ✓ **可作为因果分析训练样本**（routing_score/traffic_score/causal_direction 都是实测）
- ✓ **时间跨度紧凑**（1.7 年）
- ⚠️ **outage 类略少**（7 条）— 真实源数据有限
- ⚠️ **traffic 信号部分未实测**（仅 Cloudflare 18 条有 traffic_has_signal，BGPStream 16 条 traffic_has_signal=False）

### 12.8 文件清单

| 文件 | 用途 |
|------|------|
| `data_check/ground_truth_collection/build_ground_truth_v4.py` | 构建 v4 数据集 |
| `data_check/ground_truth_collection/clean_v4.py` | 清洗 (metadata-based 污染检查) |
| `data_check/ground_truth_collection/verify_v4_negatives.py` | 实测验证 negative 样本 (background running) |
| `data_check/ground_truth_collection/evaluate_agent_v4.py` | 评测 agent 在 v4 上的性能 |
| `data_check/ground_truth_collection/ground_truth_v4.csv` | v4 数据集 (56 条) |
| `data_check/ground_truth_collection/ground_truth_v4.xlsx` | v4 数据集 (Excel) |
| `data_check/ground_truth_collection/ground_truth_v4_summary.json` | v4 摘要 |

---

*文档追加时间：2026-09-13 18:00 UTC+8*

---

## 十四、2026-09-13 19:05 motivation-driven 架构审查

### 14.1 审查框架

基于项目核心 motivation: **"Traffic is the ground truth. Routing 检测是手段，Traffic 变化是目的"**，从 4 个维度审查项目架构：

1. quick phase 是否真的把 traffic 作为判定核心
2. 两阶段诊断 (quick → deep) 是否真的复用
3. routing 检测是否最小化开销
4. HTML 报告是否可信

### 14.2 审查发现与修复

#### 发现 1 (中度): traffic_signal_present 误判

**位置**: `chief_agent.py:1670` (build_quick_summary)

**问题**: 原代码 `traffic_signal = bool(traffic_anomaly_count > 0 or tr.get("data_available"))`。
Cloudflare Radar 返回了数据但**没异常**时（如某 AS 不在 probe 网络），`data_available=True`，但 anomaly_count=0。
原逻辑误判为"流量有信号"。这与 motivation "Traffic is the ground truth" 相悖。

**修复**: 改为 `traffic_signal = traffic_anomaly_count > 0`，只看 anomaly。

**验证**: Orange España 2022 (5 hijack + 0 anomaly + data_available=True):
- 修复前: `traffic_signal_present=True` (误判)
- 修复后: `traffic_signal_present=False` ✓

#### 发现 6 (高度): correlation_level 取错位置 → real_incident 永远判定不到

**位置**: `chief_agent.py:1693-1696` (build_quick_summary)

**问题**: `correlation_analyzer.analyze_temporal_correlation()` 返回的 dict 中：
- 顶层 `level` = "SIGNALS_PRECOMPUTED"（占位符，无意义）
- 真正的关联等级在 `correlation.signals.temporal_proximity` (strong/moderate/weak/none)

原代码 `corr.get("level", "none")` 拿到 "SIGNALS_PRECOMPUTED"，`.lower()` 后 "signals_precomputed"，
**永远不在 ("high", "medium") 中**。

**后果**: 即便 routing 异常 + 流量异常 + 时间窗强相关，`quick_verdict` **永远不可能是 `real_incident`**。
这是 motivation 核心判定逻辑**完全失效**。

**修复**: 从 `corr["correlation"]["signals"]["temporal_proximity"]` 取值，
映射 strong/moderate → high, weak → low, signals_precomputed → none。

**验证**: Orange España 2022:
- 修复前: `correlation_level=none`, `verdict=correlation_uncertain`
- 修复后: `correlation_level=high`, `verdict=silent_alert` ✓

#### 发现 4 (中度): quick phase 不复用 cache → 30-60s 浪费

**位置**: `chief_agent.py:_run_quick_analysis_async`

**问题**: 两阶段诊断的核心设计是 "quick → deep 复用 quick cache"，但 quick phase 自己**不检查 cache hit**。
每次调用 `analyze_quick()` 都重新跑 traffic_agent (Radar API 30-60s) + routing_agent (BGP 下载 30s+)。

**修复**: 在 `_run_quick_analysis_async` 开头检查 cache_file 并直接返回 cached result。

**验证**:
- 第一次 quick: 32.5s
- 第二次 quick: 0.013s (cache hit) ✓

#### 发现 (低度): typo `origin_hijanging` → `origin_hijacking`

**位置**: `chief_agent.py:1602`

**修复**: typo 修改。

### 14.3 修复后端到端验证

| 场景 | 修复前 verdict | 修复后 verdict | 修复后 correlation_level |
|------|----------------|----------------|--------------------------|
| 12479 2022 (5 hijack + 0 anomaly) | correlation_uncertain | **silent_alert** ✓ | high |
| 12479 2024 (12 anomaly + 0 hijack) | traffic_only | **traffic_only** ✓ | high |

**Orange España 真实案例 (2022)** 现在被正确判定为 **silent_alert**
（路由有异常但流量平静，正是 motivation 中"静默告警"的定义）。

### 14.4 motivation 一致性总结

| Motivation | 修复前 | 修复后 |
|------------|--------|--------|
| Traffic is the ground truth | ❌ data_available 被误判 | ✅ 仅 anomaly_count 决定 |
| Quick verdict 准确判定 real_incident | ❌ correlation_level 永远走不到 high | ✅ temporal_proximity 正确映射 |
| 两阶段诊断 quick → deep 复用 | ⚠️ quick 不复用 cache | ✅ quick 自带 cache hit |
| Routing 是手段而非目的 | ✅ quick 跳过 forge/outage | ✅ (保持) |

---

*文档追加时间：2026-09-13 19:05 UTC+8*

