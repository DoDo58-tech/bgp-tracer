# BGP Tracer 项目进度汇报

---

## 1. 一句话总结

BGP Tracer 是一个**两阶段**的 BGP 异常归因系统：Phase 1 跑确定性检测器判定**是否真的有 BGP/流量异常**，Phase 2 在确认有异常后用 **HCAF（Hierarchical Causal Attribution Filter）** 综合 5 个证据通道判定**因果方向**（路由→流量 vs 流量→路由 vs 独立）。
---

## 2. 整体架构

```
用户输入 (ASN, start_time, end_time)
   ↓
┌────────────────────────────────────────────┐
│ Phase 1: 确定性检测（0 LLM）         │
│  ├─ TrafficAgent   → Cloudflare Radar 5min │
│  └─ RoutingAgent   → RIPE RIS / RouteViews│
│           ↓ chief_agent.compute_quick_verdict│
└────────────────────┬───────────────────────┘
                     ↓
              5 类 Phase-1 verdict:
       real_incident / silent_alert /
       traffic_only / correlation_uncertain /
       no_clear_anomaly
                     ↓
       (no_clear_anomaly → 直接返回，pipeline 短路)
                     ↓
┌────────────────────────────────────────────┐
│ Phase 2: CSS + HCAF + LLM 报告（带 LLM）   │
│  1. CorrelationAnalyzer  → 算 ΔT           │
│  2. CSS Engine          → Pearl-PNS 检验   │
│  3. HCAF Bayesian       → 综合 5 通道后验  │
│  4. ReportAgent         → HTML + LLM 叙述  │
└────────────────────────────────────────────┘
                     ↓
       用户看到的 final 报告:
       Phase-1 verdict + Phase-2 HCAF direction
```

### 2.1 Phase 1 输出空间（用户看到的 5 类 verdict）

| Verdict | 含义 | 是否进 Phase 2 |
|---|---|---|
| `real_incident` | 路由+流量都有异常且时间相关 | **是**（完整 HCAF） |
| `silent_alert` | 路由有，流量没 | 是（典型 abstention）|
| `traffic_only` | 流量有，路由没 | 是（典型 abstention）|
| `correlation_uncertain` | 都有但时间不重合 | 是（倾向 `independent`） |
| `no_clear_anomaly` | 都没事 | **否**（pipeline 短路，不消耗 LLM） |

### 2.2 Phase 2 输出空间（HCAF 4 选 1）

| HCAF 输出 | 含义 |
|---|---|
| `routing_to_traffic` (R→T) | 路由变 → 流量响应 |
| `traffic_to_routing` (T→R) | 流量变 → 路由响应 |
| `independent` | 都变但**无因果** |
| `unknown` (abstain) | **证据不足，不下结论** |

**重要**: `unknown` ≠ "没异常"。`unknown` 是 HCAF **没把握**——可能路由变了流量没动（silent_alert），可能流量变了路由没动（traffic_only），可能两者都没动但被 phase 1 误判进 phase 2。HCAF **不直接判定"没异常"**。

---

## 3. Phase 1 详解（chief_agent）

`chief_agent.py::compute_quick_verdict`（line ~1665）的判定逻辑：

```python
if not traffic_data_available:        # Cloudflare Radar 没数据
    verdict = "no_radar_data"          # 单独一类 (BUG-R145)
elif traffic_signal and routing_signal and correlation_level in ("high","medium","low"):
    verdict = "real_incident"
elif traffic_signal and routing_signal and correlation_level == "none":
    verdict = "correlation_uncertain"
elif routing_signal and not traffic_signal:
    verdict = "silent_alert"
elif traffic_signal and not routing_signal:
    verdict = "traffic_only"
elif not traffic_signal and not routing_signal:
    verdict = "no_clear_anomaly"
else:
    verdict = "unknown"
```

四个底层检测器:
- **MSBD** (Multi-Scale Breakpoint Detector): 流量突变点检测
- **CTPR** (Causal Time-Position Ratio): AS path 合法性
- **CIC** (Control-Plane Integrity Check): 控制面完整性
- **Origin hijack / Route leak / Outage detectors**: RIPE RIS / RouteViews

---

## 4. Phase 2 + HCAF 详解

### 4.1 CSS (Causal Sufficiency Score) 引擎

CSS 用 **Pearl-PNS (Probabilistic Neighborhood Selection)** 检验路由和流量两个时间序列之间的因果性：
- 路由先动 + 流量响应 → 倾向 **R→T**
- 流量先动 + 路由响应 → 倾向 **T→R**
- 时间错位 / 都不动 → `independent` 或 abstention

CSS 用 **bootstrap CI** 给 PNS 估计一个置信区间；CI 不跨 0 才认为有因果。

### 4.2 HCAF Bayesian 综合

HCAF 把 CSS 的方向作为**先验**，5 个 evidence channel 贡献**似然比**，最后输出 4 个假设的后验：

$$P_0(h) \propto \begin{cases} w_{\text{causal}}=10 & \text{if } h = \text{CSS.direction} \text{ and } \text{CSS.is\_causal} \\ w_{\text{soft}}=4 & \text{if } h = \text{CSS.direction} \text{ and not } \text{CSS.is\_causal} \\ 1 & \text{otherwise} \end{cases}$$

5 个 evidence channel:

| 通道 | 作用 | 
| **MSBD** (breakpoint) | 检测流量突变点 
| **CTPR + CIC** (path) | AS path 合法性 + 控制面完整性 
| **Pearson** (lag correlation) | 线性滞后相关 
| **Granger** (causality) | 线性 Granger 因果 
| **Transfer Entropy** (TE) | **非线性**方向信息流 

---