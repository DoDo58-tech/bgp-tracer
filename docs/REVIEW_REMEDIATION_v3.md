# Top-Tier Conference Review (v3)

**审稿人**: Cursor Agent
**审稿时间**: 2026-09-18
**评审视角**: USENIX Security / IMC / NDSS / SIGCOMM 系统 track 审稿人
**评分参考**: ACM CCS (A*), NDSS (A), USENIX Security (A*), IMC (A), SIGCOMM (A*)
**方法**: 全项目静态审阅 + 运行 v2 三个 P0 测试 + 真实 HCAF pipeline 测试 + Granger 在 leak 数据上跑出新 bug

---

## 0. 总体判断

| 项目 | 评分 |
|------|------|
| 工程完整度 | A (16k 行 Python + 24 轮 P0/P1 修复 + 364 测试) |
| 方法论严谨度 | **B-** (v2 评审的 P0 项已修，但**真实数据上 Granger 仍有 silent bug**) |
| 评测完整性 | **C+** (34 事件 GT 已存在但 HCAF 精度未量化) |
| 可复现性 | **B** (config.py + .env 良好，但缺 deterministic seed 文档) |
| 写作清晰度 | **C+** (15+ eval doc 散乱，缺 unified API doc) |
| 综合审稿结论 | **Major revision** → 补 4 个 P0 + 6 个 P1 后可达 Accept |

**重要发现（本次审稿独有）**: 在真实 leak detection CSV 上跑 HCAF，发现 v2 评审的 Granger 差分修复**仍然有 silent bug** ——当只有一路时间序列被差分时，`np.column_stack` 失败并被 `try/except` 吞掉，导致输出虚假 "significant=True"。这个 bug v2 评审没发现。

---

## 1. P0 必改（reviewer 必问、影响接收）

### 1.1 [已修] `ctpr_step_delay` 是 hash 伪随机数

**位置**: `agents/causal_attribution.py:222` (`ctpr_step_pseudo_delay`)

**修复 (v2 评审已做)**: 改名 + docstring + clamp `[60, 180]` + env override。

**本次审稿新增**:
- `tests/test_ctpr_step_delay_honesty.py` (7 tests): deterministic / bounded / no-NaN / jitter-env

**状态**: ✅ **完成**

---

### 1.2 [已修, 但仍漏 bug] Granger causality 加 ADF 检验

**位置**: `agents/causal_attribution.py:448` (`GrangerEngine`)

**修复 (v2 评审已做)**: `enforce_stationarity=True` + ADF + `granger_stationary_check_and_diff`。

**v2 漏掉的 bug**（**本次审稿发现**）:
- 在真实 leak detection CSV (`leak_251326_*`, 6064 行) 上跑 HCAF 时，触发 warning:
  ```
  Granger failed: all the input array dimensions except for the concatenation axis
  must match exactly, but along dimension 0, the array at index 0 has size 247
  and the array at index 1 has size 246
  ```
- **根因**: `granger_stationary_check_and_diff` 对一路序列做 np.diff → 长度减 1。如果只对一路做了差分（routing 趋势 + traffic 平稳），两路长度不一致，`column_stack` 失败。
- **更糟的是**: 被 `try/except` 吞掉，输出虚假 `significant=True + strength≈1.0` verdict！**这是审稿人最怕的 silent bug**。

**修复 (本次新增)**:
```python
# agents/causal_attribution.py:494-505 (after differencing)
common_n = min(len(r_series), len(t_series))
r_series = r_series[-common_n:]
t_series = t_series[-common_n:]
n = common_n
```

**本次审稿新增测试**:
- `tests/test_granger_stationarity.py` (8 tests):
  - `test_differencing_size_mismatch_regression` 双向验证（fix 在 → PASS，fix 不在 → FAIL + warning）
  - 其余 7 个覆盖 ADF、differencing、short series、schema

**状态**: ✅ **完成**（修复 + regression test + 真数据验证）

---

### 1.3 [已修] HCAF 投票权重不透明

**位置**: `config.py:152-155` (`HCAF_WEIGHTS_*`)

**修复 (v2 评审已做)**: 4 个权重抽到 config.py + env override。

**本次审稿新增**:
- `tests/test_hcaf_consistency.py` (8 tests): 跑 34-event GT CSV + 真实检测 CSV (5 hijack + 4 leak = 9 files)
  - `test_hcaf_detection_coverage`: ≥ 50% of 34 events get a known verdict
  - `test_hcaf_directions_distribute_across_event_types`: 不是所有 event type 都 collapse 成同一方向
  - `test_hcaf_high_correlation_events_match_direction_proxy`: 高相关性事件 ≥ 25% 命中 proxy direction (hijack → routing→traffic)
  - `test_hcaf_is_deterministic`: 同一事件重跑 direction + strength 一致
  - `test_hcaf_outputs_创新发现_list`: 4 种方法 (MSBD/CTPR/CIC/Granger) 都在
  - 其余覆盖 confidence [0,1]、verdict enum、CSV load

**状态**: ✅ **完成**

---

### 1.4 [本次新增] 真实数据 HCAF 一致性测试

**位置**: `tests/test_hcaf_real_detection.py` (新文件)

**为什么 v2 没做**: v2 评审的 `test_hcaf_consistency.py` 不存在；本次审稿创建。

**做法**:
- 加载 `data_check/hijack/*.csv` + `data_check/leak/*.csv` (9 个真实 detection 输出)
- 构造 routing timeline (5-min buckets) + 合成 traffic timeline (routing 后 50% drop)
- 跑 HCAF：必须给出合法 verdict、`置信度 ∈ [0, 1]`、4 个方法都在
- **副产物**: 9 个文件全部通过，**真实捕获了 v2 漏掉的 Granger bug**

**状态**: ✅ **完成**（同时修了 bug + 加了真数据测试覆盖）

---

## 2. P1 强烈建议改

### 2.1 报告 section 完整性 / hypothesis-card / ΔT 表格

**v2 提及**；现状：report_agent.py:5076 行，但 section/hypothesis-card 已部分修。

**本次审稿未触碰**: 这块属于大改动，留给后续 PR。

### 2.2 prompt 硬约束

**v2 提及**；现状：`_UNIFIED_COT_PROMPT` 是劝诫式 + post-validate HTML balance。

**本次审稿未触碰**: 见 `_post_validate_report_html`。

### 2.3 LLM thinking 串污染

**v2 提及**：值得写进 paper §5.4 "Robustness to LLM thinking"。

**本次审稿未触碰**: 需要 paper 写作。

### 2.4 数据源降级 / graceful degradation

**v2 提及**；现状：`_check_updates_data_availability` 已实现，但 `_check_cloudflare_availability` 未做。

**本次审稿未触碰**: 已记为 future work。

### 2.5 [本次新增] Granger silent bug 修复的 paper 记录

**本次审稿建议**: 在 paper §4 "HCAF Method" 的 "Granger baseline" 段落写出:

> Granger causality requires stationary inputs. We add an ADF
> pre-check (significance level α=0.05) and 1st-order differencing
> when needed. During testing we discovered a silent bug:
> when only one of two series is differenced, the series lengths
> diverge by 1 (np.diff drops the first element). We now
> re-align to the shortest after differencing to prevent
> column_stack failures inside statsmodels.

**为什么 review 喜爱这种 honesty 段**: 揭示你"踩过的坑"+ 测试覆盖。

---

## 3. P2 建议改（future work）

### 3.1 缺 deterministic seed（每次跑结果不同）
**位置**: `agents/causal_attribution.py` 多处用了 `hash()`，没有 `random.seed(...)` 设置。
**建议**: 加 `--seed 42` CLI 入口 + 验证两次跑结果 byte-identical。

### 3.2 缺 baseline 对比（pure detector vs bgp_tracer）
**v2 提及**；建议 ablation table: bgp_tracer vs pure Cloudflare vs pure RouteViews。

### 3.3 缺 reliability diagram + ECE
**本次审稿建议**: 在 `tests/test_confidence_calibration.py` 加 Expected Calibration Error + reliability diagram。

### 3.4 死代码清理
**v2 提及**；本次审稿未触碰。

### 3.5 fast/slow 标签
**v2 提及**；本次新增测试已用 `@pytest.mark.fast` / `@pytest.mark.slow` 标注，但**未触碰**既有测试。

### 3.6 [本次新增] 多文件冗余的 report_agent.py 拆分

**位置**: `agents/report_agent.py` (5076 行单文件)
**问题**: 拆分为 `report_agent/{sections,correlation,scrub,inject,html_validate}.py` 子模块。
**本次审稿未触碰**: 4-6h 工作量。

---

## 4. 当前已落地修改清单

| 文件 | 类型 | 行数 | 内容 |
|------|------|------|------|
| `tests/test_granger_stationarity.py` | NEW | 158 | 8 Granger stationarity + differencing + 真实 bug regression 测试 |
| `tests/test_ctpr_step_delay_honesty.py` | NEW | 137 | 7 CTPR pseudo-delay 诚实化测试 |
| `tests/test_hcaf_consistency.py` | NEW | 247 | 8 HCAF 在 34 事件 GT CSV 上的 sanity 测试 |
| `tests/test_hcaf_real_detection.py` | NEW | 197 | 5 在真实 detection CSV 上跑 HCAF 的端到端测试 |
| `agents/causal_attribution.py` | FIX | +11 | 修复 Granger size-mismatch silent bug |

**测试数变化**: 336 → **364** (净增 28)
**测试时间**: ≤ 30s 快测 + ≤ 90s 慢测 / 全套 2 分钟

---

## 5. 修改后预期的 paper §4 "HCAF Method" 新增段

```latex
\subsection{Granger Baseline with Stationarity Pre-Check}

The Granger causality test requires stationary inputs to avoid spurious
significance from trending series. We add an ADF pre-check at significance
level $\alpha = 0.05$, and apply 1st-order differencing when the raw
series fails the test. We also discovered (during testing) that when
only one of two series is differenced, the two series can diverge in
length by one element ($\texttt{np.diff}$ drops the first element),
which broke $\texttt{statsmodels.grangercausalitytests}$ via
$\texttt{np.column\_stack}$. We re-align to the shortest of the two
after differencing. Without this fix, the resulting silent
\texttt{try/except} path returned a spuriously-confident verdict,
which we caught via the regression test in
\texttt{tests/test\_granger\_stationarity.py::test\_differencing\_size\_mismatch\_regression}.
```

---

## 6. 立即修改优先级（本次会话已落地）

1. ✅ **3 个 P0 测试文件** — `test_granger_stationarity.py`, `test_ctpr_step_delay_honesty.py`, `test_hcaf_consistency.py` + `test_hcaf_real_detection.py`
2. ✅ **真实 Granger bug 修复** — `agents/causal_attribution.py:494-505`
3. ✅ **回归测试覆盖** — 双向验证（fix 在 → PASS，fix 不在 → FAIL）

**未完成（建议留给后续 PR）**:
- ❌ report section 强制补齐（v2 §2.1）
- ❌ prompt 硬约束（v2 §2.2）
- ❌ baseline 对比 ablation（v2 §2.3）
- ❌ reliability diagram + ECE
- ❌ pytest fast/slow 全量标注
- ❌ 报告 agent 单文件拆分
