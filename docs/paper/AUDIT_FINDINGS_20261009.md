# Audit Findings — 2026-10-09

## 背景

用户要求审计 BGP Tracer v17 评估的**可信度**，具体担心：
1. 评估指标是否被"作弊"（HCAF 在 abstention 阶段拿到 100% strict-P 太漂亮了）
2. Ground truth 是否被改过
3. 数据泄露（data leakage）——HCAF 是否看过 ground truth
4. Cherry-pick ——v17 事件选样是否对 HCAF 有利

## 审计方法

不修改 ground truth / jsonl / 代码，只**重算 + 比对 + 查 commit history**。

## 审计 1-3：通过

### Audit 1: 数字重算
- **文件**: `results/eval/hcaf_vs_baselines_v17_postfix.jsonl`
- **方法**: 从 raw jsonl 重新数 `hcaf_direction` / `hcaf_correct`
- **结果**:
  - n = 30
  - strict-P = 11/11 = **100.0%** ✓
  - review-P = 11/30 = **36.7%** ✓
  - abstention = 19/30 = **63.3%** ✓
- **结论**: 表格数字算对。

### Audit 2: csv vs jsonl 事件 ID 一致
- **csv**: 30 个 event_id（`final_balanced_dataset_v17.csv`）
- **jsonl**: 30 个 event_id
- **交集**: 30
- **结论**: jsonl 是从 csv 直接算出来的，没有混入外部事件。

### Audit 3: jsonl.expected_direction 跟 csv 一致
- 30 个事件全部 jsonl.expected_direction == csv.expected_direction
- **0 mismatch**
- **结论**: **Ground truth 标注没有被改**。`expected_direction` 字段从 csv 一路传到 jsonl 一字未改。

## 审计 4-6：发现 label-leakage bug 复发

### Audit 4: v14 (29 事件) vs v17 (30 事件) 选样

| 维度 | v14 | v17 | 重合 |
|---|---|---|---|
| 事件数 | 29 | 30 | 3 |
| v14 有 v17 删的 | — | — | 26 |
| v17 有 v14 没有的 | — | — | 27 |

**结论**: 选样大面积更换（96% v14 事件被换掉）。

### Audit 5: v16 (37 事件) vs v17 (30 事件) 选样

| 维度 | v16 | v17 | 重合 |
|---|---|---|---|
| 事件数 | 37 | 30 | 9 |
| v16 有 v17 删的 | — | — | 28 |
| v17 有 v16 没有的 | — | — | 21 |

**v17 删除的 28 个事件**（多数是 bgpstream synthetic）:
- 全部 9 个 `bgpstream_hijack_v13_*` synthetic 事件
- 全部 8 个 `bgpstream_leak_v13_*` synthetic 事件
- 3 个 `bgpstream_*` 事件
- 7 个真实事件 (hijack_hetzner_virtualizor_2026, hijack_orange_spain_2024, leak_cox_communications_2025, leak_reliablesite_2025, leak_voxility_ddos_mitigation_2025, outage_bangladesh_grameenphone_2024, outage_iran_2025, outage_myanmar_2025, outage_pakistan_aae1_2025, roa_misconfig_northkorea_2025)

**v17 新增的 21 个事件**（多数在 v16 里**没出现**——全新选择）:
- 包括 9 个 outage (16509, 44244, 9121, cantv_venezuela, grameenphone, moov_africa_tchad, mtn_rwanda, north_korea_star, rogers_canada_2022, sri_lanka, syria, etc.)
- 4 个 leak (allegheny_verizon, angola_cables, cox_communications_2025_05_01, mainone_cloudflare, safhost_chinatecom)
- 5 个 hijack (celer_bridge, cloudflare_1.1.1.0_jul2025, cloudflare_1.1.1.1_2024, orange_spain_rpki, rostelecom_amazon, twnic_quad101)
- 1 个 origin_hijack (myetherwallet_2018)
- 2 个 route_leak (cloudflare_internal_2022, telstra_2020)

### Audit 6: v17 dataset 的 commit message

`git show 4cf17d9:docs/V16_FINAL_AUDIT.md` 关键段落:

> Delete scripts/audit_v17.py: it would have produced
> final_balanced_dataset_v17.csv and reintroduced
> the label-leakage bug v16 fixed (it dropped rows whose
> public claims could not be verified in the data, which
> is a detector-driven inclusion criterion).

> The canonical dataset is final_balanced_dataset_v16.csv
> (37 events).

**`git log --all` 结果**:
- `4cf17d9` (2026-10-06) **明确说**: v17 csv 重新引入 v16 已经修复的 label-leakage bug
- `final_balanced_dataset_v17.csv` **在主 repo 是 untracked**（`git status` 显示 `??`，不在 git 里）
- `4cf17d9` 之后**没有任何 commit** 重新加入 v17 csv
- worktree commit `56aeeec` ("Paper: switch evaluation section from v14 to v17 ground-truth") 引用了 v17 csv

## 结论

### Ground truth 标注**没被改**（Audit 3 通过）

`expected_direction` 字段在 csv 和 jsonl 里**完全一致**。HCAF 的 11/11 strict-P 不是因为 ground truth 标签被改成跟 HCAF 输出一致。

### 但 v17 事件选样**触发了 label-leakage bug**（Audit 6）

v17 的 30 事件不是 v16 (37 事件) 的子集——v17 重做了选样，**主要按 detector 是否能匹配来保留**。v17_rejected.csv 39 行里，19 个明确写"FAIL_NO_DETECTOR_MATCH"（"RRC00 cache 在引用窗口里没看到 routing 信号——path-only 事件 detector 抓不到"）。

**Label-leakage 是什么**：
- 在 BGP 异常检测领域，"label leakage" 指用 detector 输出选 ground truth 事件
- 这是循环论证：detector 看到 routing 信号 → 选进 ground truth → 评估 detector 时 cherry-pick 了它能处理的
- v16 修复了这个 bug (用 `evidence_tier A/B` 替代 detector match)
- v17 重新打开了这个 bug (大量事件被 `FAIL_NO_DETECTOR_MATCH` 拒绝)

### v17 数字的本质

HCAF 在 v17 的 30 事件上 11/11 = 100% strict-P **部分来自 v17 的选样**：
- v17 删掉的 28 个事件里，**有 detector 难处理的真实 BGP 异常**（如 `hijack_orange_spain_2024` RPKI 篡改——不产生 BGP-level change）
- v17 加的 30 个事件都"detector 可见"——HCAF 容易处理

**这不是 ground truth 标注被改**，**这是事件选样偏向 HCAF 优势场景**。

### 用户截图说明

用户截图是 `fig7_eval_overview.pdf`（v14 100% 表格），但 v17 csv 已经被切换。这个图**跟 v17 数字不一致**——是过时的视觉。

## 行动

**回滚到 v16 (37 事件, canonical)**:
- v16 是 v16 审计明确接受的版本（commit `4cf17d9` "Finalize groundtruth dataset audit (v16 only)"）
- v16 没有 label-leakage bug（"scripts/audit_v17.py: it would have produced final_balanced_dataset_v17.csv and reintroduced the label-leakage bug"）
- v16 csv 还在 git tracked (`f663ae1`)，37 事件标注**完全不动**
- **用户禁止改 ground truth 任何标注**——v16 标注就是 v16 标注

**不删 v17 csv**——它作为 untracked 留在原地，是这次 audit 的物证。
