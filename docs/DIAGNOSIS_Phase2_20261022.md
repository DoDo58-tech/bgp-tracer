# BGP Tracer — Phase 2 失败根因诊断与修复方案

> 诊断日期：2026-10-22
> 证据来源：`agents/css_engine.py`、`agents/causal_attribution.py`、`agents/causal_baselines.py`、
> `scripts/eval_hcaf_vs_baselines.py`、`results/eval/per_event_30.csv`、
> `results/eval/hcaf_vs_baselines_30.jsonl`

---

## 0. 一句话结论

Phase 2 失败**不是**阈值太高，而是**四个独立缺陷叠加**：
置信度尺度错配（主因）、CSS 方向对称性被破坏、
评估指标选择偏差、`event_type` 先验的标签泄漏。
把 `HCAF_MIN_DIRECTION_CONFIDENCE` 从 0.55 调低只会把
"0/2 正确" 变成 "少量提交但仍全错"，不解决问题。

---

## 1. 根因分级

### 根因 A（代码 bug，致命）：置信度尺度错配 —— 0.55 的门槛在混合尺度上不可达

`causal_attribution.py:1128` 的弃权门读取的是
`compute_final_score` 返回的 **blended confidence**，
而 `compute_final_score`（`:1589`）定义为：

```
base      = 0.6*css_conf + 0.3*innovation_strength + 0.1*te_conf
confidence = base * (0.95 if css_is_causal else 0.7)
```

实测（复现该公式）：

| 场景 | final_conf | 是否过 0.55 门 |
|---|---:|---|
| 全通道取满 + css causal | 0.950 | PASS |
| css=0.7, innov=0.3, te=0.5, causal | 0.532 | **ABSTAIN** |
| css=0.5, innov=0.5, te=0.5, **非** causal | 0.350 | **ABSTAIN** |

要让 `final_conf ≥ 0.55`：
- css 必须 **causal**，否则 factor=0.7 封顶 0.7·base
- `css_conf ≥ 0.73`（典型 innov/te 下）
- 同时需要 MSBD/CTPR/CIC 三个 innovation 通道同时显著

三者叠加概率极低。数据完全吻合：
24 个弃权事件的 confidence 分布是
`[0.066, 0.069, 0.070×9, 0.071, 0.072, 0.073, 0.083, 0.087, 0.21, 0.28, 0.38, 0.407, 0.481, 0.49, 0.536]`
—— 全部 < 0.55，且大部分在 0.07 附近塌缩。

> **证据**：0.07 这个众数正是 `base ≈ 0.1` × `factor 0.7` 的结果，
> 说明 `css_conf ≈ 0.1`、`innovation ≈ 0.1`。门槛不是"偏高"，
> 而是**与被比较的量不在同一量纲**。

### 根因 B（代码 bug，致命）：CSS 的 R→T / T→R 不再对称，两个方向量纲不同

`css_engine.py:663-670`：

```python
# PNS(R → T): split at the *routing* breakpoint
rt = _pns_estimate(t_pre, t_post, ...)          # 变量 = traffic，分界 = routing bp
# PNS(T → R): split at the *traffic* breakpoint
t_bp_idx = _find_breakpoint(t_aligned)
tr_pre = r_aligned[:t_bp_idx]
tr_post = r_aligned[t_bp_idx:]
tr = _pns_estimate(tr_pre, tr_post, ...)        # 变量 = routing，分界 = traffic bp
```

后果：`rt` 恒以 **traffic 的方差** 归一化，`tr` 恒以 **routing 的方差** 归一化。
在 BGP 场景中 routing 是极度稀疏的尖峰序列（std 被单个尖峰主导），
traffic 是连续稠密序列。因此 `abs(css_rt)` 与 `abs(css_tr)`
**不是同一把尺子上的读数**，`:741` 处的 `abs_css_rt > abs_css_tr` 比较是无效的。

这不是理论问题——它正是两个 route-leak 事件出错的直接原因（见根因 E）。

### 根因 C（评估 bug，致命）：分母用被测方法自己的弃权过滤

`eval_hcaf_vs_baselines.py:819` 与 `:834`：

```python
evaluable = [r for r in per_row if r["hcaf_correct"] is not None]   # ← 按 HCAF 弃权过滤
...
correct = sum(1 for r in evaluable if r.get(key) == r["expected_direction"])
n = len(evaluable)                                                 # ← 分母也是它
```

这让 CSS / TE / Granger 等所有基线都在 **HCAF 自己愿意回答的子集** 上被计分。
`hcaf_4way_table.md` 中 "HCAF 29/29 = 100%" 的表格就是这么来的。

同一份数据在严格口径下（`per_event_30.csv`，26 real-cache）：

| 方法 | correct | wrong | abstain | coverage | selective acc |
|---|---:|---:|---:|---:|---:|
| HCAF | 0 | 2 | 24 | 7.7% | **0%** |
| TE | 19 | 4 | 2 | 92% | 82.6% |
| CSS | 14 | 10 | — | 96% | 58.3% |

### 根因 D（评估 bug，致命）：review 口径把 abstain 记为正确

`build_per_event_30_csv.py:25-26`：

```python
def is_review_correct(pred, expected):
    return pred == expected or pred == "unknown"   # ← abstain = correct
```

这正是"CSS/HCAF 全部正确"结论的来源。
在告警分流场景 "abstain = 未误报" 有意义，
但在**方向归因**场景把 abstain 记为正确是无效指标——因为方向任务的
全部价值就在于给出正确方向。
**论文 §5 目前引用的正是这个口径，必须全部作废重算。**

### 根因 E（标签泄漏，致命）：`event_type` 先验 = 答案

`causal_attribution.py:1282` 取 `_event_type`，
`css_engine.py:924-934` 把它直接映射成方向先验：

```python
elif event_type == "route_leak" or event_type == "roa_misconfig":
    prior = {"routing_to_traffic": 5.0, "traffic_to_routing": 1.0, ...}
```

但 `expected_direction` 的定义（`eval_hcaf_vs_baselines.py:87-90`）是：

```python
if cause in {"route_leak", "origin_hijack_victim", ..., "roa_misconfig"}:
    return "routing_to_traffic"
```

**两者是同义映射。** `event_type=route_leak` ⟹ 先验 R→T ⟹ 期望标签 R→T。
这不是先验，这是把标签抄了一遍。任何"高准确率"都只是回声。

`causal_attribution.py:1425-1451` 的 `routing_meta_says_rt`
（用 `evt in ("route_leak", ...)`）是同一泄漏的第二处，
且 `:1433` 还会主动 `pop` 掉反对的 MSBD 通道。

### 根因 F（代码 bug）：`_find_breakpoint` 在退化序列上返回 `half`，lead 恒为 0

实测（n=12）：

| 序列 | 返回 bp |
|---|---:|
| 全零 `[0]*12` | **3** |
| 常数 `[5]*12` | **3** |
| 小噪声 | 3 或 8（任意） |

全零序列所有 k 的 `diff` 都是 0，`best_diff` 初值 `-1.0` 使第一个候选
k=half 胜出。于是 `r_bp == t_bp == 3` ⟹ `lead = 0`，
落入 `else` 分支做幅值比较——而根因 B 已证明该比较无效。
**两个 flat 序列永远无法被正确定向。**

### 根因 G（TE 虚高，评估问题）：TE 优于 CSS 不真实

`causal_baselines.py:404-415` 的决策规则：

```python
if sig_rt and te_rt > te_tr and (not sig_tr or te_rt >= te_tr): ...
elif te_rt > te_tr * 1.2:  direction = "routing_to_traffic"   # ← 未要求 sig_rt
elif te_tr > te_rt * 1.2:  direction = "traffic_to_routing"
```

后两个分支**不检查 null 显著性**。20% 的相对差就敢提交方向。

同时 `:385-391` 的 surrogate 只 shuffle 了 **routing** 一侧，
却没有对应的 TE(T→R) null，因此 `sig_tr` 用的
`null_mean/null_std` **量纲上属于 TE(R→T)**，却拿去比较 `te_tr`——
这是明确的量纲错误，让 `sig_tr` 近乎恒真，间接喂给第一个分支。

**以及最重要的基线对照缺失**：real-cache 26 个事件里
18 个期望 R→T、8 个期望 T→R。**永远猜 R→T = 69.2%。**
TE 的 selective accuracy 82.6% 只比这个平凡基线高 13.4 pp。
样本量 25 上，69.2% → 82.6% 的差异不显著（见 §5）。

---

## 2. 五个通道"不独立"的证明

你问的"五通道是否实际上不独立"——**是的，而且证据就在你自己的敏感性实验里**：

> 单独删除 MSBD / CTPR / CIC / Granger / TE 时，direction flip rate = **0%**；
> 删除 CSS anchor 时 flip rate = **37.9%**，L1 shift 从 0.265 → 0.822。

零 flip 意味着这五个通道在真实数据上**从不独立地对结果投票**。
结合根因 E：MSBD/CTPR/CIC 三者实际上都由
`event_type` / routing metadata 驱动（`:1303-1310`、`:1425-1451`），
TE 只在 `_dom_dir` 一致时才贡献（`:1394`）——
**五个通道是同一条泄漏信号的五次复制**。
因此"删除任一通道无影响"不是稳健性证据，而是**它们不是独立信息的证据**。

---

## 3. 绝对不能写进论文的结论

以下论断目前**全部无证据支撑或已被证伪**：

| 论文现有表述 | 位置 | 处置 |
|---|---|---|
| "HCAF and CSS commit on all 29 and are correct on all 29" | §5 L63, L74-75 | **删除**。实为 0 正确 / 2 错误 |
| "HCAF 100% accuracy" / "Tier-1 100%" / "Large 100%" | §5 L130, L152-158 | **删除**。来自 review 口径 + HCAF 过滤分母 |
| "HCAF vs. TE +59pp, p<1e-5" | §5 L227 | **删除**。分母错误 + review 口径 |
| "only removing the CSS prior causes 37.9% flips" | §5 L267 | **删除**。该现象是泄漏的证据，不是 CSS 的价值 |
| "HCAF 100% Tier B accuracy **by abstention rather than by error**" | hcaf_4way_table.md L30 | **删除**。自相矛盾：弃权不是准确率 |
| 任何 PNS "synthesis 最优" 表述 | main.tex 摘要 | **必须改写** |

Phase 1 的数字（26/29 = 89.7%，消融 34.5%–79.3%）与告警回放
（10.8% precision，CI 6.5–17.3%）**不受本诊断影响，可以保留**，
但需注明 precision 定义为"分母仅含完成的 130 个"。

---

## 4. 修复方案（按优先级）

### P0 —— 修复会伪造结论的评估代码（先做，因为不依赖任何模型改动）

#### P0-1 删除 `review` 口径
`scripts/build_per_event_30_csv.py`：删除 `is_review_correct` 及所有 `*_review` 列。
论文若需保留"未误报率"，必须改名 `*_no_false_alarm` 并与准确率**分表呈现**。

#### P0-2 修复分母
`scripts/eval_hcaf_vs_baselines.py:819,834,849-863`：
分母固定为 `len(real_cache_rows)`，与被评方法无关。
新增四列输出：`correct / wrong / abstain / selective_accuracy`。

#### P0-3 移除标签泄漏
- `css_engine.py:924-934` 的 `event_type` 分支：**整体删除**。
- `causal_attribution.py:1425-1451` 的 `routing_meta_says_rt`：
  删除 `evt in ("route_leak", ...)` 部分，仅保留 `outage and has_wd`
  （这是**可从 BGP UPDATE 直接观测**的量，不是标签）。
- `causal_attribution.py:1303-1310`：删除 MSBD unknown 时的类型注入。

> 保留标准：**只有能从 BGP 流本身算出的量才能进先验。**
> withdrawal count、update 数量、AS path 变化可以；`cause_label` 不行。

#### P0-4 冻结 25/26 事件作为 test set
禁止在这 26 个事件上调任何阈值。调参只能在
`data/groundtruth_v19` 的其余事件 + 新采集事件上进行（见 §5）。

---

### P1 —— 修复置信度尺度（核心 bug）

`causal_attribution.py:1128` 的弃权门**不应**读 blended confidence。

**建议新规则**（分离两个概念）：

```
# 门 1：统计显著性门（不可绕过）
direction 可提交  ⟺  CSS_p < 0.05 且 CI 不含 0     [已有]

# 门 2：先验后验门（读 posterior，不读 blended）
direction 可提交  ⟺  max(posterior) ≥ τ

# 报告用强度（不参与决策）
strength = f(css_conf, innovation, te)   ← 保留原公式，仅用于展示
```

具体修改：

```python
# causal_attribution.py evaluate_convergence 的返回值里已有 posterior
# :1128 处改为：
posterior = convergence.get("posterior", {}) or {}
max_post = max(posterior.values()) if posterior else 0.0
if max_post < HCAF_MIN_POSTERIOR:      # 新常量，默认 0.50
    abstained = True
```

`config.py` 新增：
```python
HCAF_MIN_POSTERIOR = float(os.environ.get("BGP_TRACER_HCAF_MIN_POSTERIOR", "0.50"))
# 旧的 HCAF_MIN_DIRECTION_CONFIDENCE 保留但不再用于弃权门（标 deprecated）
```

`causal_attribution.py:1598-1602` 的 `is_causal` 保持不变（它已经额外要求 `base≥0.4`）。

> 保留原有 blended confidence 用于报告分档是合理的；
> 问题是**把"展示强度"当成"决策置信度"**。

---

### P2 —— 让 CSS 双向对称

`css_engine.py:663-670` 改为**同尺度双向估计**：

```python
# 两个方向都归一化到 [0,1] 的效应量，而不是原始均值差
rt = _pns_estimate(t_pre, t_post, ...)     # effect = |Δmean| / pooled_sd
tr = _pns_estimate(tr_pre, tr_post, ...)   # effect = |Δmean| / pooled_sd
```

在 `_pns_estimate` 内把 `point` 改为标准化效应量
（Cohen's d 或 pooled-SD 归一化），**两个方向共用同一把尺子**。
这样 `abs_css_rt > abs_css_tr` 才有意义。

同时修复 `_find_breakpoint`（根因 F）：

```python
def _find_breakpoint(series, half_window=None):
    ...
    best_diff = 0.0          # 原为 -1.0
    best_idx = -1            # 原为 n//2
    for k in range(half, n - half):
        ...
    return best_idx if best_idx > 0 else -1   # -1 = "no detectable break"
```

`_split_at_breakpoint` 收到 `-1` 时**返回 abstain**，
而不是静默退化成 midpoint 切分。
flat 序列必须显式弃权，不能靠任意切点假装有断点。

---

### P3 —— 修 TE baseline（否则它会一直是假的"最优基线"）

`causal_baselines.py`：
1. **两个方向各算各的 null**：`te_null_rt` 与 `te_null_tr`。
2. 删除 `:411-415` 两个不检查显著性的 1.2× 分支。
3. 决策规则统一为：
   ```
   commit ⟺ TE(d) > μ_null_d + 2σ_null_d  AND  TE(d) > TE(¬d) · 1.2
   ```
4. 增加 majority-class baseline 行：`always_R→T`（= 69.2%）。

修完后 TE 大概率会掉到和 CSS 同量级。
**这是好事**——它让"联合方法优于单通道"成为可辩护的论点。

---

## 5. 重新评估协议（防止 25 事件过拟合）

### 5.1 划分
| 集合 | 来源 | 用途 |
|---|---|---|
| **Tuning** | `groundtruth_v19` 中未进入 per_event_30 的事件（≥20 个） | 调阈值 |
| **Test** | 26 real-cache（当前冻结） | **只跑一次**，报告最终数字 |
| **Hold-out** | 后续新采集事件 | 确认泛化 |

### 5.2 必报指标（四个，不多不少）
```
coverage        = (correct + wrong) / N
selective_acc   = correct / (correct + wrong)
risk_coverage   = wrong / N
AURC            = 面积（用于阈值选择，但**不在 test 上选阈值**）
```
> 绝不再报单一 "accuracy"。
> 弃权不是正确，也不是错误——它是**成本**。

### 5.3 显著性
TE 82.6% vs 平凡基线 69.2%，在 N=25 上：
Wilson 95% CI of selective acc 约 [0.62, 0.92]，
与 base rate 的 CI **重叠**。必须报告 CI，不得只报点估计。

---

## 6. 两条论文策略

### 策略 A —— 若 P0–P3 后 HCAF 仍不优于 TE

**不要继续修 Phase 2。** 27 个月后再投入产出比极低，且当前 26 个事件的
统计功效根本不足以支撑任何因果方向结论。转策略 B。

### 策略 B —— 重定位主线（推荐）

**新主线**：*"在真实 BGP 告警洪流中，用联合控制面/数据面证据做低成本事件
判别与业务影响筛查"*。

Phase 1 的数字直接支撑这个主线，且它们是**你唯一稳固的实验结果**：

| 现有资产 | 数值 | 可直接用 |
|---|---|---|
| 29 事件 cause classification | 26/29 = 89.7% | ✅ |
| 4-detector 全消融 | 10/29 = 34.5% | ✅ 证明多信号必要 |
| Traffic-only 消融 | 15/29 = 51.7% | ✅ |
| 告警回放 precision | 10.8%, CI [6.5, 17.3] | ✅（需注明分母） |
| Review-set reduction | 9.3:1 | ✅ |
| 延迟 p95 | 783.5 s | ✅ |

#### 必须删除/改写
1. **摘要**：删除 "two-phase causal attribution"、"fuses ... to attribute
   causal direction"。改为 "joint control/data-plane arbitration"。
2. **Contribution 3**（若存在 PNS synthesis 贡献）：删除。
3. **Table `tab:hcaf-4way`**：整表删除或降级为 §"Limitations" 中的负结果表
   （这反而是审稿人喜欢的诚实度）。
4. **`fig_hcaf_decomp.pdf`、`fig_causal_channels.pdf`**：删除。
5. **§5 L63/L74-79/L130/L152-158/L227/L267**：全部重写。
6. **保留并强化**：detector ablation、live replay precision、
   latency、9.3:1 reduction、case study。

#### 需要新增的实验（支撑新主线）
1. **人工标注 50–100 个告警**，给出 real_incident 的人工 ground truth，
   把 precision 10.8% 的分母争议（"完成的 130 个" vs "提交的 192 个"）彻底解决。
2. **失败模式分析**：14 个 real_incident 的 116 个 FN，分类归因。
3. **Phase 2 作为 optional deep-dive**：诚实报告它在稀疏流量数据上弃权，
   并说明适用边界（"需要多 vantage point + 密集流量采样"）。

---

## 7. 1–3 天执行计划

### Day 1 —— 止损（不碰模型，只改评估）
- [ ] 删除 `is_review_correct` 及所有 `*_review` 列
- [ ] 修 `eval_hcaf_vs_baselines.py` 分母，加 4 列输出
- [ ] 删 `css_engine.py` 的 `event_type` 先验分支
- [ ] 删 `causal_attribution.py` 的 `routing_meta_says_rt` 标签分支
- [ ] 重跑 26 real-cache，产出**诚实版表格**（预期：HCAF 大幅弃权）
- [ ] 用新表格重写 §5 相关段落，删除所有已证伪论断

> **Day 1 结束时论文必须是可投稿的诚实版本。**

### Day 2 —— 核心修复
- [ ] 新增 `HCAF_MIN_POSTERIOR`，弃权门改读 posterior
- [ ] `_find_breakpoint` 返回 `-1` 表示无断点，flat 序列显式弃权
- [ ] `_pns_estimate` 标准化为 Cohen's d，双向同尺度
- [ ] **在 Tuning 集上**（不是 26 个 test 事件）选 τ
- [ ] 加一个 assert 自检：flat 序列必须返回 unknown

### Day 3 —— 基线与复评
- [ ] 修 TE 的双向 null + 删除非显著分支
- [ ] 加 `always_R→T` 平凡基线
- [ ] 在 **Tuning 集**跑完整消融 + 灵敏度
- [ ] 在 Test 集（26 事件）跑**一次**，报 CI
- [ ] 决定策略 A 还是 B，据数据

---

## 8. 长期方向

1. **补数据密度，而不是补模型**。当前 CSS 失败的根本原因是
   real-cache 事件的中位桶数太少。Cloudflare Radar 5-min 粒度 +
   单一 vantage 无法支撑 PNS。引入多 vantage（多个 AS 的 RTT）后
   流量序列密度可提升一个量级。
2. **把方向归因从 point estimate 改成 cost-sensitive 决策**。
   对运营商来说 `abstain` 的成本远低于 `wrong`（错误方向会误导排查）。
   用 selective risk 框架取代 accuracy 框架。
3. **用 vantage 数量做样本量规划**，在收集 ground truth 前
   先算清楚需要多少事件才能在 80% power 下检出 75% vs 69% 的差异。
   当前 N=26 无论如何都不够。
4. **建立 leak-proof 的评估契约**：任何进入 `prior` 的量，
   必须能从 `traffic/routing timeline` 字段白名单里取到，

---

## 9. 修复实施记录（2026-10-22/23）

本节记录上述缺陷在代码中的落地情况，便于复核。所有修改都不使用测试集调参：
没有任何阈值是根据 25/26 个真实缓存事件选出来的。

### 9.1 逐条状态

| # | 缺陷 | 修复位置 | 状态 |
|---|---|---|---|
| 1 | blended confidence 被用作方向弃权门槛 | `config.py` 新增 `HCAF_MIN_POSTERIOR=0.50`；`causal_attribution.py` 弃权门改为「CSS 统计显著（`is_causal`）+ `max(posterior) ≥ 0.50`」，`HCAF_MIN_DIRECTION_CONFIDENCE` 标记 deprecated 且不再参与决策 | 已修复 |
| 2 | R→T 与 T→R 尺度不同 | `css_engine._pns_estimate` / `_scarcity_aware_pns` 全部改为 pooled-SD 标准化效应量（Cohen's d），点估计、CI、置换检验、`sufficiency` 同一量纲；新增尺度不变性回归测试 | 已修复 |
| 3 | unknown 被计为正确 | `scripts/build_per_event_30_csv.py` 删除 `is_review_correct` 与全部 `*_review` 列，改为 `correct/wrong/abstain`；`tests/test_hcaf_consistency.py` 的评分口径同步改为严格口径 | 已修复 |
| 4 | 分母由 HCAF 弃权决定 | `scripts/eval_hcaf_vs_baselines.py` 分母固定为全部有 `expected_direction` 的事件，输出 correct/wrong/abstain/coverage/selective accuracy/Wilson CI/risk，并按真实缓存与 synthetic 分表 | 已修复 |
| 5 | `event_type` 先验 = 标签泄漏 | 删除 `bayesian_synthesize` 的 `event_type` 先验分支（参数保留但显式忽略）；删除 `routing_event_type` 注入、TE 的 `_dom_dir` 门控；`routing_meta_says_rt` 仅保留 `outage && has_routing_withdrawal` 这一可观测量，且以 1.5:1 弱通道进入、不再 `pop` 反向证据 | 已修复 |
| 6 | flat 序列返回中点 | `_find_breakpoint` 无可检测断点返回 `-1`（含常数/全零/过短/无 numpy）；`_split_at_breakpoint` 返回空窗口；`css_score` 显式弃权；`lead` 在任一侧无断点时为 `None` | 已修复 |
| 7 | TE 双向 null 与显著性 | 每个方向各自 shuffle 源序列构造 null；经验置换 p 值（加一校正）；提交需 `p<0.05`、`TE > μ_null + 2σ` 且 `TE(d) > 1.2·TE(¬d)`；删除无显著性检查的 1.2× 分支；评估新增 `Always R→T` 多数类基线 | 已修复 |
| 8 | 五通道不独立 | 合成改为均匀先验；CSS 作为普通通道（有界 LR，仅显著时加入）；同向通道按 cluster 取几何平均，重复通道不再累乘；输出 `n_channels / n_clusters / redundancy` 诊断；论文 §5 的 37.9% 解读改写为「依赖诊断，不是稳健性证据」 | 已修复 |

### 9.2 严格口径下的结果（未重新调参）

以 `results/eval/per_event_30.csv`（由既有 JSONL 重算，未改动事件集）为准，
26 个真实缓存事件：

| 方法 | correct | wrong | abstain | coverage | selective acc |
|---|---:|---:|---:|---:|---:|
| HCAF / synthesis | 0 | 2 | 24 | 7.7% | 0.0% |
| CSS alone | 15 | 9 | 2 | 92.3% | 62.5% |
| Transfer Entropy | 20 | 4 | 2 | 92.3% | 83.3% |
| Always R→T | 18 | 8 | 0 | 100% | 69.2% |

25 个非对照事件上的严格重算为 synthesis 0/2/23、CSS 14/10/1、TE 19/4/2。
29 个非对照事件中有 4 个使用 synthetic timeline，已在评估输出中单独成表，
不与真实缓存结果混算。

### 9.3 告警回放

`results/cloudflare_alerts/replay_summary.json` 现在完全由
`per_alert_verdict.jsonl` 重算，不再硬编码：

- 提交 192，完成 130，失败 62（coverage 67.7%）；
- `real_incident` 14；
- 完成集 precision 14/130 = 10.8%，Wilson 95% CI [6.5, 17.3]%；
- 完成集压缩比 130/14 = 9.3:1（提交集为 192/14 = 13.7:1，必须注明分母）；
- 延迟中位数 225.6 s，p95 783.7 s（不是 60 s）。

### 9.4 已撤回的论文表述

- 摘要：删除 "two-phase causal attribution"、"fuses ... to attribute causal
  direction"、"within 60 seconds"、ML 基线 +16.4 pp、"10:1"；
  改为 joint control/data-plane arbitration、192/130/62/14、9.3:1、225.6 s，
  并明确写出 Phase-2 在真实缓存上的负结果。
- Introduction：C3 撤回 PNS-anchored 有效性主张；S1 撤回「两个低成本统计量 /
  32.7% 放行」；S3 与 Contribution 3 改为 evidence arbitration + 显式弃权，
  并声明方向归因的负结果。
- §5：删除 `tab:hcaf-4way` 的 29/29=100%；删除 +59 pp / +97 pp / ML-oracle
  显著性行；37.9% 翻转的解读改为通道依赖证据；延迟表改为实测回放数字；
  候选漏斗表删除（筛查阶段是占位实现）。

### 9.5 回归测试

`tests/test_phase2_honesty.py` 对上述 8 条逐条加了断言（19 个用例）；
`tests/test_hcaf_consistency.py` 的评分契约同步改为「abstain 不计入正确」。

### 9.6 仍未解决（诚实边界）

1. 真实缓存事件只有 25–26 个，任何方向结论都不具备统计功效；本记录不提出新的
   「最优方法」主张。
2. 五个通道仍然读取同两条时间序列，几何平均只是阻止「重复即置信」，
   并不能把它们变成独立证据。
3. 筛查阶段仍是占位实现；若要恢复「两阶段成本非对称」的主张，需要先实现并
   在 Tuning 集上验证真正的粗筛。
4. `AURC` 未实现：需要阈值扫描，而当前测试集规模不足以支持阈值选择。


## 10. 第二轮排查（2026-10-23）：引擎在「线上形态」输入上的缺陷

第 9 节修的是*评估口径*；这一轮修的是**引擎本身**。核心发现：评估脚本喂给 CSS 的
是「预分桶序列」（等间隔、每桶一个 score），而 `workflow_engine.build_hcaf_timelines`
喂的是**原始事件日志**（每个检测到的事件一条、时间戳不规则、score 恒为 0.9/0.7）。
引擎用「时间戳是否互不相同」判断输入形态，而原始事件日志天然满足该条件，于是被
当成预分桶序列直接透传，得到一条**恒等于 0.9 的平序列**——`_find_breakpoint` 正确
地判定「无断点」，CSS **在线上永远弃权**。评估与线上因此跑的是两个不同的模型。

### 10.1 修复清单

| # | 缺陷 | 影响 | 修复 |
|---|------|------|------|
| 1 | `_to_score_series` 以「时间戳互异」判形态 | 原始事件日志被透传 → 平序列 → 线上永远弃权 | 改为**网格均匀性**判据（`_is_prequantised`）；原始日志走 `_bucketize_pair` |
| 2 | 两条序列**各自**分桶、按索引对齐、短序列补零 | 两序列覆盖不同时间区间；补零伪造「无异常」桶，压低 post 均值 | 共享一个 `t0/桶宽`（`_bucketize_pair`）；`_align_series` / `_to_aligned_series` 改**截断**到共同窗口 |
| 3 | `single_sided_result` 在 `event_type ∈ {hijack,outage,withdrawal}` 且 drop>10% 时直接判 R→T | 用**真值标签**产出方向；且该分支在弃权门之前 return，绕过门控 | 方向恒为 `unknown`；强度/跌幅仅作诊断 |
| 4 | `evaluate_convergence` 里 `evt == "outage" and has_wd` 触发 1.5:1 R→T 通道 | 评估路径无 `event_type`（从不触发）、线上路径恒触发 → 两个模型；线上有无条件 R→T 偏置 | 通道删除，调用恒传 `None` |
| 5 | `estimate_counterfactual_cascade` 硬编码 `direction="routing_to_traffic"` | 传播模型**按构造**就是 R→T，却作为 `cic_scope` 通道给出 1+log1p(N) 的 R→T 似然——把假设当证据 | 方向改为 `unknown`，只报告影响范围 |
| 6 | 排列检验 `p = mean(|perm| ≥ |point|)` | 有限次重采样可得 `p = 0`，不是可取的概率值 | 加一校正 `(1+hits)/(1+B)`；稀缺路径同样处理 |
| 7 | `css_score` 等效应分支返回 `independent` | 「分不清方向」被表述为「无因果」——过度断言 | 改为 `unknown`（弃权） |
| 8 | `sufficiency/necessity` 恒取 R→T 的 PNS | T→R 判定时报告的是反方向的量 | 按最终方向取 |
| 9 | `split_merged_timeline` 退化分支：两条同时间戳、traffic 用 routing 的计数 | traffic 序列成为 routing 的副本；重复时间戳破坏网格判据 | 两条桶相隔 1 秒，各用各自计数 |
| 10 | 评估脚本 `css_direction` 用 `if r2t > 0.34 ... elif t2r > 0.34` | 先比较的键获胜：`{R→T:0.35, T→R:0.40}` 报 R→T（错误方向） | 严格 argmax（`posterior_to_css_direction`），阈值提为命名常量 |
| 11 | `hcaf_4way_table.py` 的 CSS 行用 `css_is_causal` 布尔 × 未门控 `css_direction` | 显著性与方向来自不同量；`tier` 缺失时 KeyError；majority 的 Tier-A 准确率硬编码 0 | 用 `css_direction_engine`；缺失字段的基线整行跳过；majority 分层由数据计算 |
| 12 | `build_per_event_csv.py` 与 `build_per_event_30_csv.py` 各存一份评分契约、写同一个 CSV | 审计时同一处要改两遍，已出现漂移 | 前者改为委托后者（单一实现） |
| 13 | `evaluate_convergence` 读取 `scale_results[*]["breakpoint_idx"]`，但该键**没有任何生产者** | 「MSBD 为 CSS 提供干预起点」从未生效；`msbd_breakpoint_idx` 恒为 None（CSS 一直用自己的均值漂移断点，行为正确，但注释/契约是假的） | 删除死代码，明确记录「MSBD 只提供 scale-sync 通道，断点由 CSS 自检」 |
| 14 | 弃权原因一律记 `no_supported_direction` | 掩盖了「后验低于 0.50 门限」这一主因（真实缓存 141/145） | 无后验→`no_supported_direction`；有后验但低于门限→`posterior_below_floor` |
| 15 | 无缓存时无条件调用 `synth_timeline`，而 30 事件 CSV 的 `routing_origin_count`/`routing_withdrawal_count` **全为空** | 合成回退必然生成**平路由**序列 → 所有方法按构造弃权；这张「SYNTHETIC」表看似测量、实则必然全零；且 `"synthetic" not in cache_source` 的分类会把新的 no-data 行误算进真实集 | 无路由信号时标为 `no data`、不生成假时间线；汇总分 real / synthetic / no-data 三类，no-data 不进任何分母 |
| 16 | `synth_timeline` 用 f-string 拼 `00:{i+10:02d}:00` | i ≥ 50 时生成非法分钟数 60–69；时间戳开始被解析后，会静默丢掉最后 10 个交通点 | 改用 `timedelta(minutes=i+10)` |

### 10.2 行为验证（不依赖丢失的缓存）

原始事件日志（10 条 routing，事件间隔 7±2 min，score 恒 0.9；10 条 traffic 滞后
75 min，score 恒 0.5）：

- 修复前：透传序列恒为 0.9 → `breakpoint = -1` → 弃权；
- 修复后：共享网格 26 桶 → `breakpoint = 13`，CSS(R→T)=+2.04 [+1.36,+2.72]，
  p=0.007，`is_causal=True`，方向 R→T。

预分桶输入（评估路径）在上述改动前后**逐方法完全一致**（同一份 30 事件结果重跑，
表格数值不变），说明修复只影响线上形态，不改变已发表的评估数字。

**真实缓存全量扫描（无标签）**：对工作区中仍存在的 145 个 `results/quick/*.json`
逐个跑引擎（`split_merged_timeline` → `CausalAttributionEngine.analyze`）：
143 个弃权、1 个判定 T→R、1 个无时间线，**0 个崩溃**；弃权原因 141 个
`posterior_below_floor`、2 个 `css_not_significant`；路由序列中位桶数 120。
这说明：(a) 修复后的引擎能处理真实缓存形态而不异常；(b) 在均匀先验 + 0.50 后验
门限下，系统在真实数据上几乎不承诺方向——这与论文的负结果一致，也说明论文中
「合成器承诺 2 个」是**上界**而非现测值（见论文 §5 新增的 provenance 说明）。

### 10.3 「CSS alone」这一行的敏感性（必须在正文披露）

该行是「后验 argmax、不加弃权门」，其阈值是报告口径而非决策规则。26 个真实缓存
事件上的计数对阈值极敏感：

| 阈值 | 正确/错误/弃权 | 选择性准确率 |
|------|----------------|--------------|
| 0.34（论文采用） | 15 / 9 / 2 | 62.5% |
| 1/3（均匀基线） | 15 / 11 / 0 | 57.7% |
| 0.40 | 2 / 7 / 17 | 22.2% |

即：后验大多落在 0.33–0.36 的弱证据带。任何「CSS 单通道选择性准确率」的解读都
必须同时给出该阈值，且不能与多数类基线（18/8/0 = 69.2%）比较后宣称优势。

### 10.4 仍未解决

1. **真实缓存丢失（阻塞项）**：`results/quick` 被并发的
   `scripts/cloudflare_alerts/full_pipeline.py` 重写，论文 26 个真实缓存事件的
   `quick_AS*.json` 已不在工作区；本轮无法重跑真实数据评估。`hcaf_vs_baselines_30.jsonl`
   与 `per_event_30.csv` 是仅存记录，未覆盖。
2. 因此 `hcaf_4way_table.{csv,md}` 的 canonical（非 `_pre_audit`）版本仍无法从当前
   代码重建；重建后必须与第 9.2 节逐格比对。
3. 粗筛阶段仍是占位实现（第 9.6 节第 3 条）。
