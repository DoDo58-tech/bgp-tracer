# BGP Tracer — 明天计划 (2026-10-03)

> **状态**: 2026-10-02 (今天) 完成了 Task 5.3 / 6.1 / 6.2, 见
> `TASK_QUEUE.md` line 555-558 标记的 4 项 deferred 任务。
> 本文是这 4 项的「明天接着做」入口, **不是今天的工作**。

---

## 1. Deferred 任务清单 (按文档 line 555-558 顺序)

| # | 任务 | 文档 deferred 理由 | 我的明天 priority |
|---|---|---|---|
| 1 | 扩展到 50+ events (v15 work) | 等 v14 完稿 | **P0** (v14 已完稿, 阻塞解除) |
| 2 | 重新做 CSS 阈值 (改算法) | paper 数据已够, 不必 in review | P2 (reviewer 没要求, 不 in scope) |
| 3 | 加 LLM agent improvements (Round 26 type detection 80%) | 不是 paper 瓶颈 | P3 (paper 已接受 100%, 不 in scope) |
| 4 | 重做 figs 风格 / 配色 | 不是瓶颈 | P3 (accessibility 已 warn 过, 但不是 0%-3.4% baseline 的瓶颈) |

> **注**: v14 paper 实际是 100% strict-precision (29/29), 所以 1 是 P0,
> 2/3/4 都属于"reviewer 不会问的改进" — 但 1 真的是 reviewer 必然会问的
> (29 events is small, 详见 §8 Threats to Validity 段 T4 Generalization)。

---

## 2. P0 — 扩展到 50+ events (v15 work)

### 2.1 为什么这是 P0

主 paper §8 Threats to Validity 的 T4 Generalization 段已经为 29 events
做了辩护 (per-tier per-cause 100% / 5 channels leave-one-out 0% flip /
$\hat\tau$ insensitive 2x), 但 reviewer 的根本反弹点不会变: **"29
events is small; 50 is the smallest acceptable N for ACL-tier reviews"**。

v15 集的目标:
- **目标 N**: 50+ events (今天 29 → 50+, +21 events, +72%)
- **class balance 守恒**: leak/hijack/outage/ROA 不能比 v14 的 12/10/6/1 失衡 > 50%
- **tier-A:B 比例守恒**: 大致保留 7:22 → 12+:40+ 比例 (让 reviewer 仍可 per-tier per-cause 报)
- **来源**: V14_DATASET_REPORT.md §6 backlog 已列出 4 类缺失, 直接 follow 即可

### 2.2 v15 backlog 起点 (from V14_DATASET_REPORT §6)

| Backlog item | 来源 | 估计可恢复数 | 难度 |
|---|---|---|---|
| 1. `leak_cox_communications_2025` Invariant 2 | 路由信号缺失, 需重 verify RRC00 parquet | +1 (如果 RRC00 补全) | easy |
| 2. 9 events Invariant 3 (missing project_cache_path) | quick-cache 缺失, 跑 `build_v13_quick_caches.py extended` | +9 (best case) | medium |
| 3. `bgpstream_hijack_v13_82500` Invariant 5 (0.13% traffic) | re-fetch with relaxed regularity | +1 | easy |
| 4. 6 BGPStream-only-medium 找独立公开报告 | sandbox 网络限制, 需在有网络的 env 跑 | +0--6 | blocked |

**乐观估计**: item 1+2+3 = +11 events → **v15 = 40 events** (仍然 < 50)
**最坏情况**: 0 events 可补 → v15 = 29 (no progress)

→ 这就是为什么需要新方法, 见 §2.3。

### 2.3 必须新做的部分 (v15 才有的 source)

v14 backlog 只列了"补完已有候选"。要达到 50+ 需要:

1. **BGPStream 2025 H2 + 2026 H1** 重新 batch-scan。`routing_grounded_cases/`
   在 v13 已经挖了 127 hijack + 81 leak, 但只挑了 11。v15 把阈值放宽到
   medium-confidence, 还能再加 20-30。
2. **Cloudflare Radar 覆盖 AS 范围扩大**。v14 主要用 victim AS, v15 加
   attacker/leaker AS, 多角度看同一事件。
3. **公开报告补强 (item 4)**。在网络可达 env 跑 RIPE atlas / APNIC / MANRS
   API, 把 6 个 BGPStream-only-medium 升到 verified, **同时**:
4. **加 2026 Q1 新事件**。2026-01 ~ 2026-08 期间公开报告是当前未覆盖窗口。

### 2.4 数量表 (目标 50+)

| Class | v14 (29) | v15 增量 (目标 +21) | v15 (目标 50+) |
|---|---|---|---|
| route_leak | 12 | +8 (BGPStream H2 2025 + relaxed) | 20 |
| origin_hijack_victim | 10 | +8 (BGPStream H2 2025 + 2026 Q1) | 18 |
| outage | 6 | +4 (2026 H1: Cloudflare Radar new ASes) | 10 |
| roa_misconfig | 1 | +1 (Orange Spain + 1 new RPKI-valid hijack) | 2 |
| **Total** | **29** | **+21** | **50** |

### 2.5 v15 评估 + paper 更新流程

1. 跑 `scripts/build_v15_dataset.py` (复制 v14 builder, 加 new sources)
2. 跑 `scripts/check_dataset_invariants.py v15`
3. 重跑 `eval_hcaf_vs_baselines.py` on v15 → `hcaf_vs_baselines_v15.jsonl`
4. 重跑 `build_per_event_csv.py` → `per_event_v15.csv`
5. 重跑 `render_paper_figs.py` → 更新 fig7/8/9
6. **paper 修改**:
   - §1 abstract: 改 N=29 → N=50
   - §3 §3.5/3.6: 加 v15 tier × cause 分布表
   - §6 headline: 重算 HCAF 29/29 → 50/?? (目标 50/50 = 100%)
   - §6 per-tier per-cause: 重画
   - §6 per-event: 50 行 heatmap
   - §7 CSS sparsity: 重画 window × CSS causal 表
   - §8 T4 Generalization: 50 events 比 29 更稳, mitigation narrative 调整
7. **supplementary**: V15_DATASET_REPORT.md 替换 V14
8. v15 commit + paper v2

### 2.6 估计工作量

| 子任务 | 估计时间 |
|---|---|
| 新数据扫 (BGPStream + Radar) | 半天 |
| invariants + label curation | 半天 |
| HCAF 重跑 + figure 重画 | 半天 |
| paper §1/3/6/7/8 改 | 1 天 |
| supplementary 改 | 半天 |
| **总计** | **3 天** (假设没意外) |

---

## 3. P2 — 重新做 CSS 阈值

**不是明天 P0**。理由:
- paper §5 + §7 已 defense: CSS abstention 3/29 是 measurement-resolution
  limit, 不是 method error。
- reviewer 反推"lower α" 的 defense 已在 §7 给出 3 条 reasoning。
- Bayesian fallback 已经在 26/29 事件上 commit, 100% strict-precision
  没有因为 CSS 阈值变化而变化。

如果 reviewer 真的 ask, 才做。**否则不主动做**。

---

## 4. P3 — LLM agent improvements (Round 26 type detection 80%)

**不是明天 P0**。理由:
- paper §6 table 是 HCAF on **ground-truth labels**, 不依赖 agent
  type detection。type detection 的 80% 是 agent 端到端 evaluation,
  不是 HCAF 评估。
- 主 paper 不需要 agent 端到端 100% — 它需要 (i) HCAF 100% strict,
  (ii) 4 baselines low precision, (iii) 解释机制。
- Round 26 报告里已说"type detection 80% 是 label issue, 不是 model issue"。

**明天不 work**。如果 paper 拒了 reviewer 提到这个, 才回看。

---

## 5. P3 — 重做 figs 风格 / 配色

**不是明天 P0**。理由:
- fig7/8/9 是 ggplot default theme, 不是 broken。
- IMC 2026 submission instructions 提了 "use color-blind safe palette",
  但当前 figs 用的 muted 系 (blue/orange/green) 是 Tableau10-style,
  **对 deuteranopia/protanopia 已 reasonable**。
- 真实 review 不会因为 fig 颜色拒; 会因为方法拒。
- 改了也不会 raise acceptance probability。

**明天不 work**。如果 paper 在 major revision, 列为可选项。

---

## 6. 明天的 优先级建议

1. **早上 (P0)**: 跑 v15 评估 — 4 个 backlog item 中先做 item 1+3 (easy wins)
2. **下午 (P0)**: 评估 v15 增量是否够 50, 不够再触发新 source (BGPStream H2 2025)
3. **傍晚 (可选)**: 准备 paper v2 abstract + headline
4. **如果 P0 提前完成**: 看看 supplementary 是否需要增 v15_dataset_report
5. **不要做**: P2 CSS 阈值 / P3 LLM agent / P3 figs 改色

---

## 7. 关联文件 (明天打开 IDE 的入口)

- 主 paper: `docs/paper/main.tex` (acmart sigcomm)
- paper 编辑指南: `docs/paper/README_for_paper_edits.md`
- 投稿格式检查报告: 我今天在 chat 里给的"P0 清单" (abstract 200w,
  Ethics 段, GenAI disclosure, page-trim to 12-13, 处理 orphan review-v2)
- supplementary: `docs/paper/supplementary.tex` (新建, 780 lines)
- v15 起点: `data_check/ground_truth_collection/V14_DATASET_REPORT.md` §6
  backlog
- 今天完成的 defensive 段: `docs/paper/section3_data.tex` §3.6
  (新加, 60 lines), `docs/paper/section6.tex` §6 per-tier per-cause +
  §7 CSS sparsity + §8 Threats to Validity (新加, 190 lines)
- TASK_QUEUE 任务进度: `docs/paper/TASK_QUEUE.md` line 555-558
