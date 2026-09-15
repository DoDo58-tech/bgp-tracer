# 项目彻底诊断报告 (2026-09-15)

## 背景
用户反馈：从 8.15 调到 9.15（一个月）反复出现小 bug。本次彻底诊断，发现并修复了 7 个关键 bug。

## 7 个根本原因

### Bug 1: `JSON_OUTPUT_ENABLED` 只认 "true" 不认 "1" (P0)
- **症状**: results.jsonl 所有指标都是 `N/A` (verdict/conf/quality/tokens)
- **根因**: batch 脚本传 `JSON_OUTPUT_ENABLED="1"`，但 config.py 只认 `"true"`
- **修复**: `config.py:172` - 改为 `in ("true", "1", "yes")`
- **验证**: ✅ JSON 输出已正确捕获

### Bug 2: JSON Parser 无法匹配嵌套对象 (P0)
- **症状**: 即使 JSON 输出存在，batch 也无法解析
- **根因**: `re.findall(r'\{[^{}]*"success"...')` 遇到嵌套 `{` 就停止
- **修复**: `scripts/run_4mode_batch.py:179` - 改用括号匹配算法
- **验证**: ✅ AS17557 输出完整解析

### Bug 3: `_strip_table_nodata_rows` 破坏 `<table>` 标签 (P0)
- **症状**: 所有 `<table>` 变成 `<table<table>` 双重表
- **根因**: `split(">", 1)` 碰到无 attrs 的 `<table>` 时损坏
- **修复**: `agents/report_agent.py:2267` - 从 `m.group(0)` 提取 opener
- **验证**: ✅ 表格结构完整

### Bug 4: `_sub_one` 合并所有 `<td>` 成一个 (P0)
- **症状**: `<td>A</td><td>B</td>` 变成 `<td>AB</td>`
- **根因**: `replace(m.group(0)[len(attrs):], cleaned)` 替换整个标签而非内容
- **修复**: `agents/report_agent.py:2241` - `f"<td{attrs}>{cleaned}</td>"`
- **验证**: ✅ 多列表格正确

### Bug 5: `_repair_llm_html` 吃掉 `<` 字符 (P0) **【最严重】**
- **症状**: 整个文档显示为源码（用户最常投诉的"乱码"）
- **根因**: token regex `(?:(?!<).)+` 在 pos=0 遇到 `<` 时跳过
- **修复**: `agents/report_agent.py:2078` - 改用 `<table>|<tr>|...` 扫描+纯文本段
- **验证**: ✅ `<div`、`<h1`、`<p` 等所有非表格标签保留

### Bug 6: standalone 路径无视 `REPORT_REQUIRE_LLM=1` (P1)
- **症状**: 即使设置 REQUIRE_LLM=1，仍 fallback 到 deterministic 模板
- **根因**: HTML balance 失败时无条件 fallback，不检查 should_use_fallback()
- **修复**: `agents/report_agent.py:3897` - 先 check，禁止时返回 failure banner
- **验证**: ✅ Fallback 仅在 LLM 真失败时触发

### Bug 7: `routing_impl.py` json.dumps 不支持 dataclass (P1)
- **症状**: prompt 构建时 `Object of type AnomalyDetail is not JSON serializable`
- **根因**: LLM routing 增强路径用 json.dumps 序列化 AnomalyDetail (dataclass)
- **修复**: `agents/impl/routing_impl.py:77` - 用 `asdict` fallback
- **验证**: ✅ AnomalyDetail 正确序列化

## 验证结果
- ✅ 24 个 test_report_html_safety 测试通过
- ✅ 19 个 round3/round6/round17/round18/round19 测试通过
- ✅ 7 个修复的独立单元验证通过
- ✅ Batch 已重启，使用所有修复
