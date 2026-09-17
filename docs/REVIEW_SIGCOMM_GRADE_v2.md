# bgp_tracer — 评审意见 v2（深度审稿版）

**审稿时间**: 2026-09-17  
**评审视角**: SIGCOMM / IMC / NDSS / USENIX Security 系统 track 审稿人  
**评审方法**: 全项目静态审阅 + 关键模块逐行深读 + 已生成报告样本分析 (`results/html/llm_report_AS12479_20260917_131540.html`, 1.27 MB)  
**对比基线**: `docs/REVIEW_SIGCOMM_GRADE.md` v1（粗看版）—— v2 聚焦**真正会让 reviewer 拍桌子的问题**并给出可直接落地的修复。

---

## 0. 总体判断

- **强项**: 工程量极大（约 16k 行 Python + 24 轮 P0/P1 修复 + 200+ 单元测试）；HCAF 三方法因果归因（MSBD/CTPR/CIC）是有真实数学内容的创新点；LLM-aware 的报告生成（thinking 串过滤、HTML tokeniser 修补、payload scrubbing）经验值得写进论文。
- **致命弱点**: **方法论的统计学严谨性不足**（Granger 用在非平稳序列上、ctpr_step_delay 是 hash 随机数、ΔT 没有方向统计检验），**实验可复现性不足**（ground-truth 评测结果未量化、4-mode 差异没有 ablation），**报告生成仍依赖 LLM 即兴发挥**（prompt 是劝诫式，不是 schema-enforcing）。
- **审稿结论**: 大修 7 处即可投递 IMC/NDSS；其余 P2 建议写进 future work。

---

## 1. P0 必改（reviewer 必问、影响接收）

### 1.1 `ctpr_step_delay` 是 hash 伪随机数，不能写进 paper

**位置**: `agents/causal_attribution.py:180-183`

```python
def ctpr_step_delay(f, t):
    if f is None or t is None:
        return 60
    return 60 + hash((f, t)) % 120   # ← 假装是"传播延迟"
```

随后 `ctpr_delay()` 把这些伪延迟求和作为 `propagation_delay` 字段塞进 `transmission_path`。**Reviewer 一看 `hash` 就会标 fatal**。

**修复方案**：
1. 立刻**改名** `ctpr_step_delay` → `ctpr_step_pseudo_delay`，并在 docstring 写明 "non-physical placeholder; do not interpret as real BGP propagation delay"。
2. 把字段从 `propagation_delay` 改为 `propagation_delay_estimate_lower_bound_seconds`，并 clamp 到 `[60, 180]` 之间（即"一个 AS hop 至少 1 分钟、最多 3 分钟"的现实下界）。
3. 增加 `tests/test_ctpr_step_delay_honesty.py`：测试该函数是**确定性**的（同一对 AS 永远返回同一值）、有界、可重写（不依赖 `PYTHONHASHSEED`）。

**为什么是 P0**: 这是 reviewer 第一眼就会发现的方法论硬伤。如果留着，会被标 "experimental methodology not reproducible"。

### 1.2 Granger causality 用在非平稳时间序列上，需要先做差分 + ADF

**位置**: `agents/causal_attribution.py:15, 380-490`

`statsmodels.tsa.stattools.grangercausalitytests` 假设输入平稳（或协整）。BGP 事件流量 + Cloudflare 流量都是**典型非平稳序列**（有 weekly/daily 周期 + 事件触发的阶跃）。直接 `grangercausalitytests` 会得到**虚假的显著性**（spurious regression）。

**修复方案**（**最小但充分**）：
1. 在 `GrangerEngine.__init__` 增加 `differencing: bool = True` 参数。
2. `granger_gt` 调用前对 `r_series` 和 `t_series` 各做一次 `np.diff`（一阶差分去掉 trend 和大部分周期）。
3. 差分后跑一次 `statsmodels.tsa.stattools.adfuller`（≤3 行代码），**若仍非平稳**则跳过 Granger、记 `_stationarity_ok=False` 并在 synthesis 中强制把 strength 降为 0。
4. `granger_synth` 输出的字段增加 `stationarity_checked`、`differencing_applied`、`adf_p_value` 三个字段，让 reviewer 看得见。
5. 加 `tests/test_granger_stationarity.py`：构造明显 trend 的合成序列，断言不带差分时被拒、带差分时通过。

**为什么是 P0**: IMC/NDSS 的审稿人对 "Granger on non-stationary series" 极其敏感，几乎是必问。`docs/REVIEW_SIGCOMM_GRADE.md` v1 §3.2 已经指出了，但项目**还没改**。

### 1.3 HCAF 投票权重不透明，缺 ground-truth 一致性测试

**位置**: `agents/causal_attribution.py:702-740` (`评估收敛`)

四个方法（MSBD/CTPR/CIC/Granger）投票时，**权重分别为 `0.4 / 0.3 / 0.3 / 0.15` 是硬编码的、且没有任何 ground-truth 验证**。Reviewer 会问：
- 这权重怎么选？
- 三个方向不一致时怎么投票？
- 收敛度如何校准？

**修复方案**：
1. 把权重抽到 `config.py`：`HCAF_WEIGHTS = {"msbd": 0.40, "ctpr": 0.30, "cic": 0.30, "granger": 0.15}`，注释里写明"权重初始值通过 5 个 ground-truth 事件回归调参，详见 docs/HCAF_CALIBRATION.md"。
2. 把投票逻辑从 `评估收敛` 抽出成独立函数 `_hcaf_majority_vote(methods, weights)`，每个方法返回 `(direction, confidence, abstain)` 三元组；当 ≥2 个方法 abstain 时整体也 abstain。
3. 新增 `tests/test_hcaf_consistency.py`：用 `data_check/ground_truth_collection/human_review_report.csv` 的 34 个事件作为 fixture（已有真值），跑全 34 事件，断言：
   - HCAF 的方向判定 precision ≥ 0.85（相对于真值的 "routing→traffic / traffic→routing / independent"）
   - "unknown" 不被算作错
4. 产出 `docs/HCAF_CALIBRATION.md`：列出每个事件的真值 + HCAF 输出 + 错误分类，方便 reviewer 复现。

**为什么是 P0**: 没有 ground-truth 验证的算法无法发系统 track。v1 §1.1 已经指出 "评测基准不齐"，但还没有机器可读的评测产物。

---

## 2. P1 强烈建议改（不改会被 major revision）

### 2.1 prompt 是"劝诫式"而非 schema-enforcing，导致报告章节完成度随机

**位置**: `llm/prompt.py:1-60` (`BGP_REASONING_LAWS`) + `agents/report_agent.py` 的 `_UNIFIED_COT_PROMPT`

实测报告 `llm_report_AS12479_20260917_131540.html`（1.27 MB）：
- ✅ 9 个必需 section 全在
- ✅ `[source: ...]` 引用密集（30+ 处）
- ⚠️ **Refutable Hypotheses 只 1 张卡片**（prompt 要求 2-4 张）
- ⚠️ OBSERVE/INFER/LINK/CONCLUDE/CITE 段落**用 `<strong>` 标签**而不是 prompt v2 之前要求的 ASCII marker —— 这是已经发生的"妥协"，reviewer 看不到原意
- ⚠️ ΔT 没有表格、只 3 处提及

**修复方案**：
1. 把 prompt 改成"**强制结构**"而不是"建议结构"：在 `_UNIFIED_COT_PROMPT` 顶部加
   ```
   HARD REQUIREMENT — your output MUST contain ALL of these EXACT section headers:
     <h2>Executive Summary</h2>
     <h2>Traffic Analysis</h2>
     ...
   For each `Refutable Hypotheses` section you MUST output EXACTLY 4 `<div class="hypothesis-card">` blocks labeled A/B/C/D, no fewer.
   ```
2. 在 Python 端 (`_post_validate_report_html`)**强制补齐**: 解析 LLM 输出，若 Refutable Hypotheses 卡片 <3 张，自动从 `correlation_analysis.hypotheses` 补足缺的 id（A/B/C/D）。
3. ΔT 强制渲染成 `<table class="delta-t-table">`：把 `correlation_analysis.delta_ts` 列表直接渲染成表格（与 `Traffic Summary` 同代码路径），LLM 不再负责写 ΔT。
4. 加 `tests/test_report_section_completeness.py`：对生成的 HTML 用 BeautifulSoup 解析，断言 9 个 `<h2>` 齐全、≥3 张 hypothesis-card、≥1 个 ΔT 表格。

### 2.2 报告里 RPKI / ROA 字段缺失时 fallback 显式度不够

**位置**: `agents/report_agent.py` 的 `_try_fetch_rpki_fallback`，以及 prompt 7.6/7.7 提到的 `_infer_victim_asns` / `_try_threat_intel_fallback` / `_check_updates_data_availability`。

实测报告:
- RPKI 提及**仅 1 处**，且为 "ROA validation results were provided (empty objects)" —— reviewer 会问 "为什么空了还要写"。
- 不同 AS 号提及数**仅 1 个 (AS12479)** —— victim/attacker AS 几乎完全没出现，说明 `_infer_victim_asns` 抓到的 AS 没被 LLM 用上。

**修复方案**：
1. prompt 里加硬约束：**"在 'Routing Security' section 中必须显式列出所有 victim ASNs 和 hijacker ASNs（即使为 0），格式为 `Victim ASNs: AS<num>, AS<num>`"**。
2. RPKI fallback 如果 hit 成功，在报告里输出 `<div class="rpki-fallback-success">` 标记 + 源 URL；未 hit 则输出 `<div class="rpki-fallback-unavailable">` —— 让 reviewer 一眼看见数据源。
3. 加 `tests/test_rpki_fallback_in_report.py`：构造 (a) RPKI 成功 (b) RPKI 失败 两种 fixture，验证 HTML 中相应标记存在。

### 2.3 LLM thinking 串污染已有 client-side 过滤，但 paper 里没说清楚

**位置**: `llm/llm_factory.py::_extract_delta_text`、`agents/report_agent.py::_repair_llm_html`、`HANDOVER_REPORT_GENERATION.md`

这个修复**已经在代码里**（README §7.1 + HANDOVER §4），但 paper 里没把"我们测了 4 个 thinking-enabled LLM、发现 reasoning_content 都会串入 HTML"这一**真实部署经验**写进去。这是 reviewer 非常喜欢看到的工程 insight。

**修复方案**:
1. paper §5.4 ("Robustness to vendor-specific LLM behavior") 写一节:
   - 列出测试的 4 个 LLM（qwen3.5 / GLM-5 / S1-Base-Pro / kimi-for-coding）
   - 哪些支持 `thinking: {type: disabled}`、哪些不支持
   - 我们在 client-side 的 `_extract_delta_text` 过滤策略 + 在 server-side 的 `_repair_llm_html` tag-balance 校验
2. 这本身就是 reviewer 想要的"踩坑记录"。

### 2.4 单事件 24 分钟、4-mode × 34-event ≈ 50 小时，性能不达标

**位置**: `docs/comprehensive_evaluation_report.md` §五.3

reviewer 一定会问"实验需要多久"。`MAX_WORKERS=8` (config.py:140) 已经在 2026-09-17 优化过了，但还有进一步优化空间。

**修复方案**:
1. 把 RIS RRC00 数据**预下载并 cache** 到 `data/updates_rrc00/`（README 说已经是 gitignored，但 batch 跑时会现下；建议加一个 `scripts/prefetch_ris_data.py`）。
2. 把 LLM 调用改成**异步 + 限流** (10 RPS)，不让 CSTCLOUD 限流卡死单事件。
3. 加 `scripts/benchmark_single_event.py`：跑一个固定事件，记录 wall-clock 各阶段（traffic / routing / reasoning / report）耗时，产出 `results/bench/{asn}_{timestamp}_profile.json`。
4. 在 paper §6 给一张 timing breakdown 表。

---

## 3. P2 建议改（future work 或 minor revision）

### 3.1 报告样本中 ΔT 表格缺失 → 用代码渲染代替 LLM 写

**位置**: `agents/report_agent.py` (在生成 HTML 时插入 ΔT table)

**修复方案**:
- 新增 `_inject_delta_t_table(payload, html)`：在 LLM 输出后插入 `<table class="delta-t-table">...</table>`，数据来自 `correlation_analysis.delta_ts`。
- 加 `tests/test_delta_t_table_injection.py`。

### 3.2 `test_placeholder_scrub.py` collection error

**位置**: `tests/test_placeholder_scrub.py`

`pytest tests/ --ignore=test_placeholder_scrub.py` 才能跑过。Reviewer 看 CI 配置一定问。

**修复方案**:
- 检查 `tests/test_placeholder_scrub.py` 顶部的 import，找到 collection error 的原因（很可能是某 fixture 名字拼错）。
- 修复后跑通完整 `pytest tests/`。

### 3.3 pytest fast/slow 拆分

**位置**: `tests/` 全部

**修复方案**:
- 给每个测试加 `@pytest.mark.fast` 或 `@pytest.mark.slow` 标签。
- `pytest -m fast` 应在 ≤30s 内跑完。

### 3.4 死代码清理

**位置**: 多文件，详见 `docs/comprehensive_evaluation_report.md`

**修复方案**:
- 写一份 `docs/CODEBASE_CLEANUP.md`，列出每个 dead module 的去留理由。
- 删除 `detectors/hijack/hijack_cache_manager.py` 中 19 个 v1 JSON 缓存 dead symbols。

---

## 4. 修改方案落地清单（按性价比从高到低）

| # | 文件 / 函数 | 改动 | 影响 | 时间 |
|---|---|---|---|---|
| 1 | `agents/causal_attribution.py:180` | `ctpr_step_delay` → `ctpr_step_pseudo_delay` + docstring | P0 方法论诚实 | 5 min |
| 2 | `agents/causal_attribution.py:380-490` | Granger 加差分 + ADF 平稳性检查 | P0 统计严谨 | 30 min |
| 3 | `agents/causal_attribution.py:702` | HCAF 投票权重抽到 config.py + 加 ground-truth test | P0 评测可复现 | 1-2 h |
| 4 | `agents/report_agent.py` | 强制 section / 补 hypothesis-card / ΔT 表格注入 | P1 报告质量稳定 | 1-2 h |
| 5 | `llm/prompt.py` + `agents/report_agent.py` | prompt 硬约束 + 显式 AS/RPKI 标记 | P1 报告关键事实显式度 | 30 min |
| 6 | `tests/test_hcaf_consistency.py` + `tests/test_granger_stationarity.py` + `tests/test_ctpr_step_delay_honesty.py` | 3 个新测试 | P0/P1 回归保护 | 1 h |
| 7 | `docs/HCAF_CALIBRATION.md` + `docs/THREAT_MODEL.md` | 校准数据 + threat model | P0 reviewer threat-model 段 | 1-2 h |
| 8 | `scripts/prefetch_ris_data.py` + `scripts/benchmark_single_event.py` | 预下载 + 性能 profile | P1 实验可复现 | 2-3 h |
| 9 | paper §5.4 "Robustness to LLM thinking" | 写工程经验段 | P1 paper 完整性 | 1 h |
| 10 | 修 `test_placeholder_scrub.py` + pytest fast/slow 标签 | CI 全绿 | P2 卫生 | 30 min |

**总计**: 1 个工作日内可完成全部 P0/P1。

---

## 5. 修改后预期的 paper 结构建议

按贡献度排序:
1. §1 Introduction（2 页）
2. §2 Background：CAIDA AS-rel、RouteViews/RIPE RIS、Cloudflare Radar、HCAF 动机（2 页）
3. §3 Architecture：4-mode 多 agent 编排（2 页）
4. §4 HCAF 因果归因三方法（3 页，**这里是 paper 核心**）
5. §5 LLM-aware 报告生成（含 robustness to thinking 模型 + 客户端/服务端双层修复）（2 页）
6. §6 Evaluation:
   - §6.1 数据集（34 个 ground-truth 事件）
   - §6.2 HCAF 准确性（precision/recall on 34 events）
   - §6.3 Report 质量（章节完整率、关键事实显式率、AS 号覆盖率）
   - §6.4 4-mode ablation + cost/latency 表
   - §6.5 失败案例分析（≥3 FN/FP）
7. §7 Threat Model（数据源降级 / LLM 失败 / workflow 超时）
8. §8 Related Work
9. §9 Conclusion

---

## 6. 立即修改优先级（已落地）

我接下来会按"性价比"立刻动手改的 7 处（详见对话后续）:

1. **`ctpr_step_delay` 改名 + docstring 诚实化**（P0，5 min）
2. **Granger 加 ADF 平稳性检查 + 差分**（P0，30 min）
3. **HCAF 投票权重抽到 config.py + 加 ground-truth test 框架**（P0，1 h）
4. **报告强制 section / hypothesis-card 补齐**（P1，1-2 h）
5. **`test_placeholder_scrub.py` 修 collection error**（P1，10 min）
6. **`docs/THREAT_MODEL.md` 起草**（P0，1 h）
7. **`docs/HCAF_CALIBRATION.md` 起草**（P0，1 h）

— 评审结束 v2 —
