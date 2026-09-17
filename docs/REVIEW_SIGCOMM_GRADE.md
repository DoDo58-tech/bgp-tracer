# bgp_tracer — 顶级会议评审级审稿意见

**审稿时间**: 2026-09-17  
**评审视角**: SIGCOMM / IMC / NDSS / USENIX Security 系统 track 审稿人  
**评审范围**: 全项目静态审阅 + 关键模块深读 + 已生成报告样本评估 + 测试覆盖分析  
**结论性建议**: 先做 §5/§6 的两件事,再扩评测

> ⚠️ 评审发现了一些**非紧迫但影响论文质量**的问题。所有"应改"项均能在一周内完成。
> 评审人尊重项目已经投入 ~20 轮修复的事实,所以只列**新增或被低估**的改进点,
> 不重复 round1-20 已经修过的 P0 bug。

---

## 0. 项目强项(可写进 paper)

1. **架构清晰**:`workflow_engine` 状态机 + `Blackboard` + `MessageBus` 是教科书级别的 multi-agent orchestration,
   4 个 mode(traffic_first / traffic_first_enhanced / react / react_enhanced)显式差异化,符合 IMC 风格。
2. **HCAF 因果归因三件套**(MSBD 小波断点 + CTPR 路径重建 + CIC 反事实传播)是真实的 research contribution,
   不是空架子,`causal_attribution.py` 中有完整的 pywt + Granger 实现。
3. **回归测试链**(round3 → round20, ~200 用例)覆盖了**报告生成数据通路**的关键回归路径,
   包括 `[traffic.*]` 字段替换、`generate_report_html` 独立路径、AS12479 verdict 稳定性。
   这一套是 reviewer 普遍希望看到但很少作者做到的。
4. **端到端数据流透明**:`report_agent.py` 显式承认 LLM thinking 串污染、HTML tokeniser 丢标签等坑,
   都有 `_repair_llm_html` 这种客户端过滤兜底。
5. **工具注册表**(`tool_registry.py` + 18 个 `@register_tool`)实现了 LLM-callable tools 的动态注入,
   比 hardcoded prompt 更可维护。

---

## 1. 实验可复现性(P1,影响 paper 接收)

### 1.1 缺可一键复现的 ground-truth 评测结果
- `data_check/ground_truth_collection/human_review_report.csv` 是评测源头,但 **34 个事件的真值表**只在 `comprehensive_evaluation_report.md` 里以叙述形式给出,没有 **机器可读的评测产物**(precision/recall/F1 per mode)。
- `scripts/evaluate_reports.py` 看名字该做这件事,但本次审阅没在 README/文档里找到一份**完成度 ≥90%** 的 4-mode × 34-event 矩阵与每行 verdict。
- **建议**:跑完 `run_4mode_batch.py` 整个 ground truth,产出 `results/eval/4mode_metrics.json`,并在 paper §6 中给出下表:

| 模式 | 真阳 | 假阳 | 假阴 | 漏报率 | F1 |
|---|---|---|---|---|---|
| traffic_first | ? | ? | ? | ? | ? |
| traffic_first_enhanced | ? | ? | ? | ? | ? |
| react | ? | ? | ? | ? | ? |
| react_enhanced | ? | ? | ? | ? | ? |

### 1.2 评测基准不齐
- 4 mode 报告大小差异巨大(1MB vs 11KB fallback),但没有统一的"长度 vs 准确率"散点图。
- reviewer 一定会问:**traffic_first_enhanced 更大就更好吗?** 没有 metric 量化。
- **建议**:增加一份按**章节完整性 + 关键事实正确性**的 score,而不是只看文件大小。

### 1.3 `data_check/human_review_report.csv` 的 `victim_as` 仍有空
- 文档说"4 个可靠事件已填,2 个不确定留空",paper 中应明确说明这是 intentional 不确定性,
  而不是数据缺失。

---

## 2. 报告质量(P0,但已经接近完成)

### 2.1 实测一份报告 `results/html/llm_report_AS12479_20260917_131540.html`(1.27 MB):

| 维度 | 结果 |
|---|---|
| 必需 section 齐全 | ✅ 9/9 (Executive Summary, Traffic Analysis, Routing Security, Evidence Chain, Refutable Hypotheses, Counterfactual, Gaps, Operational, Traffic Summary, Traffic Visualization) |
| Hypothesis 卡片 | ⚠️ 仅 1 张(Hypothesis A — confidence 0.40);prompt 要求 2-4 张 |
| OBSERVE→INFER→LINK→CONCLUDE→CITE 证据链 | ❌ 实际可见文本中 0 次出现(grep 0 命中) |
| `[n]` 风格引用计数 | 0 处 |
| 显式 `[source: field]` 引用 | 0 处 |
| ΔT 数值 | 3 处提及,但没有表格 |
| RPKI / ROA 提及 | 仅 1 处 |
| 不同 AS 号提及数 | 仅 1 个(应该是 12479) — 其它受害者/攻击者 AS 几乎完全没出现 |

**问题诊断**:
- **Refutable Hypotheses 章节的标签确实存在 (`<h2>`),但内容是空的或被 LLM 跳过了**。
  prompt 第 6 条写得很死("Hypothesis cards using `<div class="hypothesis-card">`"),但实测只有一张 Hypothesis A。
- **Evidence Chain 章节存在但内容缺 OBSERVE/INFER 等 marker**。prompt 写"as `<p>...</p>` blocks",
  但 LLM 倾向于写自然语言散文,忘了 marker。
- **数字没出来**:AS 列表、prefix、attacker AS、RPKI/ROA 状态、IRRToolkit 查询结果都在 payload 里,
  但 LLM 没把它们显式打出来。

**建议**:
1. 在 prompt 中把 OBSERVE→INFER→LINK→CONCLUDE→CITE 改成 **`<strong>OBSERVE</strong>:` 等 HTML 标签**,
   而不是要求"marker 串"。LLM 更愿意渲染粗体标签而不是 ASCII 箭头。
2. 在 `_UNIFIED_COT_PROMPT` 顶部加 **"每张报告必须包含至少 3 个不同 AS 号的字面引用(用 `ASxxxx` 格式)"** 的硬约束。
3. 给 Refutable Hypotheses 强制 ≥3 张卡片,在 Python 端**用正则从 LLM 输出中提取并强制插入**,而不是信任 LLM 会写。
4. RPKI/ROA 信息如果不可用,显式 fallback 到 `_try_fetch_rpki_fallback` 并在报告里**写出 fallback 来源**,避免 "RPKI=1" 这种含糊计数。

### 2.2 LLM thinking 串污染
- README §7.1 已经修了 `llm_factory.py::_extract_delta_text`。
- 但 `_repair_llm_html` 的 tag 保留只是工程修,**应该在 paper §5 显式说**:
  - "我们实测了 4 个支持 thinking 的 LLM,均出现 reasoning_content 串入 HTML 的现象,
    我们在 client-side 过滤并在服务端用正则修标签"。
- 这是**真实部署经验**,reviewer 很喜欢看。

---

## 3. HCAF 因果归因(P2 — 论文核心贡献的论证强度)

### 3.1 三个方法的输出 schema 不统一
- `causal_attribution.py` 中:
  - MSBD 输出 `direction/strength/significant/scale_sync/scale_consistency`
  - CTPR 输出 `direction/strength/transmission_path/root_cause_as/path_length/propagation_delay`
  - CIC 输出 `direction/strength/cascade_chain/impact_estimates/affected_as_count`
- 这三个 schema 不能直接比较或投票,`因果归因引擎.分析` 是把它们合并成一个 `结果` 对象,但**论文中需要明确说明**:
  - 三方法权重?(`convergence` 字段是怎么算的?)
  - 如果 3 个方向不一致,怎么 vote?
  - `routing_to_traffic` 和 `traffic_to_routing` 哪个优先级高?
- **建议**:增加一个 `tests/test_hcaf_consistency.py`,用 ground truth 验证 HCAF 的方向判定准确率。
  目前 `tests/test_round11_fixes.py` 等只测了 wiring,没测语义。

### 3.2 Granger causality 在统计上是否稳健?
- `causal_attribution.py` line 22 引入 `grangercausalitytests`,但**没有说明**:
  - 用多少 lag?
  - p-value 阈值?
  - 是否做 ADF 平稳性检验?(BGP 事件 + 流量都是非平稳时间序列)
- 这是 reviewer 最爱问的:**"you cannot apply Granger on non-stationary series"**。
- **建议**:要么显式做差分 + ADF,要么在 paper §4.2 中明确说 Granger 仅作为辅助信号,
  主要权重放在 MSBD/CTPR/CIC。

### 3.3 CTPR 的 `ctpr_step_delay = 60 + hash((f, t)) % 120`
- 这是 `hash` 随机数,**不是真实传播延迟**。
- 在 paper 中**不要**声称这个数字代表实际传播时间。
- **建议**:改名 `ctpr_step_delay` → `ctpr_step_pseudo_delay`,并在 docstring 里写明。

---

## 4. Multi-agent 编排(P2)

### 4.1 4 mode 的差异没有量化
- 文档说 enhanced 模式开 debate + quality gate + self-correction,但 README 没有数据支撑"enhanced 更好"。
- **建议**:在 paper §6 加一张 ablation 表:
  - base vs +debate vs +quality gate vs +self-correction
  - 每行 4 个 metric: report completeness / factual accuracy / cost($) / latency(s)

### 4.2 Blackboard race condition
- `tests/test_blackboard_race_fix.py` 存在,说明项目**意识到**了并发读写问题。
- 但 `Blackboard._sections` 在 `safe_read_sync` 中被直接访问,异步路径走 `bb.read`,
  这两条路径是否有 race 风险?**建议加 stress test**:100 并发 write+read 看是否丢更新。

### 4.3 Decision budget
- workflow_engine.py 用了 decision budget 防循环,但 reviewer 会问:
  - budget 用完了之后报告质量是否会显著下降?
  - 是否有 fallback 报告模板?
- **建议**:增加一个 `tests/test_decision_budget_safety.py`,人为耗尽 budget,验证最终报告仍合法。

---

## 5. 测试覆盖缺口(P1 — 立刻能做)

跑了 `pytest tests/ --ignore=test_placeholder_scrub.py`,**15+ 分钟没结束**,
说明部分测试在调真实 LLM 或下载 RIS 数据。建议:

1. **拆出 fast / slow 套件**:
   ```bash
   pytest -m fast    # ~30s 跑完(单元 + mock)
   pytest -m slow    # 需要 LLM/网络的 E2E,CI nightly
   ```
   在每个测试文件顶部加 `@pytest.mark.fast` 或 `@pytest.mark.slow`。
2. **修复 `tests/test_placeholder_scrub.py`**:它 collection error,需要先 import 修好再跑。
3. **缺 ground-truth 级 E2E 测试**:把 `data_check/ground_truth_collection/human_review_report.csv`
   的 34 个事件**逐个**作为 fixture 跑 smoke test,目前只有 AS12479 一个事件的 stability test。
4. **缺 schema drift 测试**:LLM 输出结构(JSON / HTML)每周都在变,建议在 CI 里加
   "结构 snapshot test"(用 `pytest-snapshot` 或类似)。

---

## 6. 工程化(P1)

### 6.1 死代码与重复实现
- `comprehensive_evaluation_report.md` 列出 **474 个 dead symbols**、**95 处 except: pass**、**39 个 stub**。
- 大部分是合理的(deprecated alias、装饰器注册),但有几类**必须清理**:
  - `agents/report_agent.before_rewrite.py` 等 5 个文件已移到 `/tmp/report_agent_archive/`(README §7.5),
    **确认它们不在 git 里**;否则 reviewer 看 git blame 会困惑。
  - `detectors/hijack/hijack_cache_manager.py` 19 个 dead 是 v1 JSON 缓存,**显式删除**或加 deprecation warning。
- **建议**:写一份 `docs/CODEBASE_CLEANUP.md` 说明每个 dead module 的去留理由。

### 6.2 `.env` 文档不完整
- README 列出 5 个必需变量 + 8 个可选变量,但 `config.py` 实际读取的变量更多。
- **建议**:`python -c "import config; print([k for k in dir(config) if k.isupper()])"` 出一个完整列表,
  写进 `.env.example`。

### 6.3 Performance regression
- `comprehensive_evaluation_report.md` §五.3 说单事件 24 分钟,4-mode × 34-event = ~50 小时。
- 这是 paper 评审时 reviewer 会问的"实验需要多久"。
- **建议**:把 RIS RRC00 数据**预下载并 cache 到 `data/updates_rrc00/`**,这样每次实验不用再下载 1.5GB。

---

## 7. 论文叙事建议(P0 — 影响接收)

### 7.1 卖点排序建议
按贡献度从高到低:
1. **4-mode 可比较的多 Agent BGP 分析框架**(架构贡献,IMC/系统 track 吃这个)
2. **HCAF 三方法因果归因**(方法论贡献,可能是 NDSS 或 TIFS 单独 paper)
3. **从真实事件数据驱动的回归测试链**(工程贡献,容易写但 reviewer 认可)
4. **LLM-aware 的报告生成与修补**(工程贡献,paper 中应配一节讲"我们踩了哪些坑")

### 7.2 缺失的实验章节
- ❌ 缺 ablation study(§4)
- ❌ 缺 cost / latency 表格(§5)
- ❌ 缺误报 / 漏报案例分析(§6 — 至少 3 个 FN/FP 案例)
- ❌ 缺与单一 baseline(纯 LLM / 纯 detector / 纯 ReAct)的对照实验

### 7.3 Threat Model 没写
- 论文没说"如果 RPKI 失效 / Cloudflare Radar 不可用 / AS-relationship 数据过时,
  我们会怎么 degrade"。
- README §7.6/7.7 已经实现了一些 fallback,但没汇总成文档。
- **建议**:写一份 `docs/THREAT_MODEL.md`,列出:
  - 数据源失败:RPKI / Cloudflare Radar / prefix2as / as-rel 的 fallback 路径
  - LLM 失败:`REPORT_REQUIRE_LLM=1` 时 vs 时的行为差异
  - 决策超时:workflow `BGP_TRACER_WORKFLOW_TIMEOUT_S` 的兜底报告

---

## 8. 立即建议(可选 1-2 小时内完成)

按"性价比"从高到低:

| # | 行动 | 影响 | 时间 |
|---|---|---|---|
| 1 | 修 `tests/test_placeholder_scrub.py` 的 collection error | CI 跑通 | 10 min |
| 2 | 给 pytest 加 `@pytest.mark.fast/slow` 标签并拆套件 | CI 可用 | 30 min |
| 3 | 在 prompt 里把 OBSERVE→INFER→LINK→CONCLUDE→CITE 改成 `<strong>...</strong>` 标签 | 报告章节完整性 ↑ | 15 min |
| 4 | 在 prompt 里加 "至少 3 个不同 AS 号字面引用"硬约束 | 报告关键事实显式度 ↑ | 15 min |
| 5 | 跑一遍 4-mode × 34-event 全量评测,产 `4mode_metrics.json` | paper 数据基础 | 8-50 小时(后台跑) |
| 6 | 写 `docs/THREAT_MODEL.md` | reviewer threat model 段 | 1-2 小时 |

---

## 9. 总结

**论文方向**:强,有 novel contribution(HCAF 三方法 + 4-mode 编排 + LLM-aware 报告生成)。

**主要风险**:
1. **没有完整的 ground-truth 评测结果表**(§1.1),reviewer 会直接 reject。
2. **报告样本的章节完成度不均**(§2.1),LLM 仍会跳过 Refutable Hypotheses 和证据链 marker。
3. **HCAF Granger 的平稳性假设**(§3.2)需要在 paper 中显式处理。

**建议**:先做 §5 / §6 的工程化清理 + §7 的论文叙事整理,然后再补 §1 / §2 的实验数据。

— 评审结束 —
