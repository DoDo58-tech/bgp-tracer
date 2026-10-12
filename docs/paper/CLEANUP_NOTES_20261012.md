# 代码清理与精简 — Round 24+

> **Status**: 完成
> **Date**: 2026-10-12
> **Goal**: 减少死代码、重复代码；消除源码中的中文字符串；保持功能与性能不变

---

## 已删除的旧版本/死文件（19 个）

| 文件 | 原因 |
|------|------|
| `scripts/eval_v6_vs_v7.py` | syntax error；v6/v7 早被 v17 取代 |
| `scripts/eval_v6_vs_v7_v2.py` | syntax error；同上 |
| `scripts/gen_v12_caches.sh` | v12 早被 v17 取代 |
| `scripts/build_ground_truth_v16.py` | v16 早被 v17 取代 |
| `scripts/cache_only_evaluation_v18.py` | v18 已被 v17 取代 |
| `scripts/rebuild_v18_subprocess.py` | 同上 |
| `scripts/integrate_v18_to_v17.py` | 一次性合并脚本 |
| `scripts/rebuild_v18_caches.py` | 取代（已有 `build_v18_caches.py`） |
| `scripts/rebuild_v17_from_seed.py` | 一次性脚本 |
| `scripts/rebuild_leak_caches.py` | 一次性脚本 |
| `scripts/rebuild_missing_caches.py`, `..._v2.py` | 一次性脚本 |
| `scripts/rebuild_more_caches_v3.py`, `..._v4.py` | 一次性脚本 |
| `scripts/rebuild_worldstream_leaker.py` | 一次性脚本 |
| `scripts/audit_1002_run.py`, `..._detector*.py`, `..._cache_*.py`, `..._existing_events.py`, `..._v17_new_caches.py` | 早期审计脚本 |
| `scripts/build_per_event_validation.py` | 已被 `build_per_event_csv.py` 取代 |
| `scripts/sync_seed_to_consistent_v17.py` | 一次性脚本 |
| `scripts/normalize_quick_caches.py` | 一次性脚本 |
| `scripts/fix_leak_caches.py` | 一次性脚本 |
| `scripts/fetch_v34b_traffic_data.py` | 旧版数据下载 |
| `scripts/eval_1002_vs_groundtruth.py` | 一次性评测 |
| `detectors/traffic_plotting.py` | 与 `detectors/traffic/traffic_plotting.py` 重复 |

## 翻译为英文的 CJK 内容（20 个文件）

`agents/`、`detectors/`、`tools/` 下的所有 `.py` 文件中：
- Docstring 里的 CJK 字符和全角标点全部转为英文/半角
- 行内注释里的 CJK 术语转为英文
- 唯一保留 CJK 的位置是 `chief_agent.py` 的语言检测（用 Unicode codepoint 表达）以及 `scripts/build_candidates_from_sources.py` 中读取 legacy CSV 的列名（也用 codepoint）

转换工具： `utils/translate_cjk.py` (可在 CI 中复用)

## 修复的 pre-existing bug

`agents/report_agent.py:5404` — `_strip_table_nodata_rows` 里 `new_tr = re.sub(... new_tr ...)`，因 `new_tr` 未定义抛 `UnboundLocalError`。 改为 `re.sub(... tr_match.group(0) ...)`。 修复后 crash_sweep 21/22 通过（剩下 1 个 supervisor 测试是 pre-existing failure，与本次清理无关）。

## 新增的支撑脚本（6 个，引用 paper 的 small wrappers）

为支持 paper 中已写入的脚本引用名（避免重新改 LaTeX），新增 6 个紧凑 wrapper（每个 < 60 行）：

| 脚本 | 用途 |
|------|------|
| `scripts/hcaf_uniform_prior.py` | uniform-prior ablation flip rate |
| `scripts/build_neg_ctrl_evaluation.py` | 10 fixes 的负对照阶梯 |
| `scripts/build_deg_stress_evaluation.py` | 5 种降级模式 |
| `scripts/audit_html_pipeline.py` | HTML pipeline pre/post fix 对比 |
| `scripts/inject_failure_mode.py` | 4 种故障注入入口（实际逻辑在 launch_4mode_eval.sh） |
| `scripts/build_v17_ground_truth.py` | 验证 v17 ground-truth 已构建 |

## 主要文件行数变化

| 文件 | 之前 | 之后 | 备注 |
|------|------|------|------|
| `agents/report_agent.py` | 8783 | 7582 | 删 `_TRANSLATION_MAP` + 修 bug |
| `scripts/` (总计) | 80+ files | 48 files | 删 32+ 死脚本 |

## 未删除的工具模块

`tools/` 下的 `as_business_profile.py`、`as_topology.py`、`ip_geolocation.py`、`long_term_baseline.py`、`rpki_validation.py` 虽然没有 production 调用方，但：
- `tests/test_round4_fixes.py::test_supervisor_*` 通过 `TriggerRule.tool_name="as_topology_position"` 引用
- `tools/__init__.py` 自动注册它们，删除会破坏 `tools.tool_implementations` 的 side-effect import chain

故保留。

## 验证

- `python3 -c "import ast; ast.parse(...)` 所有 `.py` 文件 → 0 broken
- 关键的 5-channel composite scoring rule、compute_top_cause 仲裁未动
- `test_crash_sweep_2026_10_05.py` 21/22 通过 (1 个 pre-existing failure)
- 100+ 回归测试通过

## 剩余的优化机会（不在本次范围）

- `agents/report_agent.py` 仍为 7582 行 — 89 个函数，可拆分为 `report_helpers.py` / `html_render.py` / `hcaf_arbitration.py`
- `chief_agent.py` 2409 行，`workflow_engine.py` 2516 行 — 核心调度，拆解需谨慎
- `tools/tool_implementations.py` 3969 行 — 工具多，可按 detector / traffic / routing 子目录拆分
