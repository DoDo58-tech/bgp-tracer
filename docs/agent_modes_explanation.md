# Agent 协调模式说明

## 概述

系统支持两种协调模式来执行 BGP 流量中断分析：
1. **Direct Mode（直接模式）**：确定性顺序执行
2. **ReAct Mode（ReAct 模式）**：LLM 自主决策（当前被禁用）

---

## 为什么 ReAct 模式被禁用？

根据代码注释（`chief_agent.py` 第 716-722 行）：

```python
"""
Streaming coordination path (ReAct-style agent).

To simplify this build and avoid complex async event handling bugs,
we currently do not support the streaming coordination mode.
The project is configured to use direct mode (USE_DIRECT_MODE=True),
so this function should not be invoked in normal workflows.
"""
```

**原因：**
1. **简化构建**：避免复杂的异步事件处理逻辑
2. **避免 bug**：streaming 模式涉及复杂的 async/await 事件流处理，容易出现难以调试的问题
3. **稳定性优先**：直接模式更稳定、可预测，适合生产环境

---

## Direct Mode（直接模式）流程

### 执行流程

```
Chief Agent
    ↓
_direct_analysis_flow()
    ↓
Step 1: 直接调用 run_reasoning_agent()
    ├─→ Traffic Agent（流量分析）
    ├─→ Routing Agent（路由分析）
    │   ├─→ Hijack Detection（劫持检测）
    │   ├─→ Route Leak Detection（路由泄露检测）
    │   └─→ Outage Detection（中断检测）✅
    └─→ 返回 reasoning_result
    ↓
Step 2: 查询 AS 组织信息
    ├─→ query_as_organization()
    ├─→ query_as_relationships()
    └─→ query_as_prefixes()
    ↓
Step 3: LLM 分析结果并生成报告
    └─→ _generate_integrated_report()
```

### 特点

✅ **确定性**：执行顺序固定，可预测  
✅ **稳定性**：无复杂的异步事件处理  
✅ **完整性**：确保所有检测（包括 outage）都被执行  
✅ **简单**：易于调试和维护  

### 代码位置

- 入口：`chief_agent.py` 第 480 行 `_direct_analysis_flow()`
- 调用链：
  - `_direct_analysis_flow()` → `run_reasoning_agent()` (第 486 行)
  - `run_reasoning_agent()` → `run_routing_agent()` (reasoning_agent.py)
  - `run_routing_agent()` → `OUTAGE_DETECTOR.analyze()` (routing_agent.py)

---

## ReAct Mode（ReAct 模式）流程

### 设计理念

ReAct（Reasoning + Acting）模式让 LLM **自主决策**调用哪些工具、以什么顺序调用。

### 执行流程

```
Chief Agent
    ↓
_react_agent_flow()
    ↓
创建 ReActAgent（LLM 驱动的智能体）
    ↓
提供工具集（Tools）：
    ├─→ invoke_reasoning_expert
    ├─→ invoke_analysis_expert
    ├─→ query_as_organization
    ├─→ query_as_relationships
    ├─→ query_as_prefixes
    └─→ generate_final_report
    ↓
LLM 根据 mission_prompt 自主决策：
    ├─→ 思考（Reasoning）：分析当前状态
    ├─→ 行动（Acting）：选择并调用工具
    ├─→ 观察（Observing）：获取工具执行结果
    └─→ 循环（最多 25 次迭代）
    ↓
_coordinate_with_streaming() ❌ 被禁用
```

### 特点

🤖 **自主性**：LLM 可以灵活决定执行顺序  
🔄 **迭代性**：可以多轮推理，根据结果调整策略  
📊 **Streaming**：需要实时处理 LLM 的逐步输出  
⚠️ **复杂性**：需要处理异步事件流、工具调用、状态管理等  

### 为什么需要 Streaming？

ReAct 模式中，LLM 会逐步输出：
1. **思考过程**：`Thought: 我需要先分析流量...`
2. **工具调用**：`Action: invoke_reasoning_expert(...)`
3. **观察结果**：`Observation: 检测到异常...`
4. **最终答案**：`Final Answer: ...`

Streaming 模式可以实时处理这些输出，但实现复杂，容易出现：
- 异步事件处理 bug
- 状态同步问题
- 错误恢复困难

### 当前状态

❌ **被禁用**：`_coordinate_with_streaming()` 直接抛出异常（第 728-730 行）

---

## 配置

在 `config.py` 中：

```python
USE_DIRECT_MODE = False  # 当前配置
```

**注意**：即使 `USE_DIRECT_MODE=False`，由于 ReAct 模式被禁用，系统会自动回退到 Direct 模式（见 `chief_agent.py` 第 445-459 行的修复）。

---

## 对比总结

| 特性 | Direct Mode | ReAct Mode |
|------|-------------|------------|
| **执行方式** | 确定性顺序执行 | LLM 自主决策 |
| **复杂度** | 低 | 高 |
| **稳定性** | 高 | 中（streaming 有 bug） |
| **灵活性** | 低 | 高 |
| **可预测性** | 高 | 中 |
| **当前状态** | ✅ 可用 | ❌ 被禁用 |
| **Outage 检测** | ✅ 确保执行 | ⚠️ 依赖 LLM 决策 |

---

## 修复后的行为

修复后（`chief_agent.py` 第 445-459 行），系统会：

1. 如果 `USE_DIRECT_MODE=True`：直接使用 Direct 模式
2. 如果 `USE_DIRECT_MODE=False`：
   - 先尝试 ReAct 模式
   - 如果遇到 "Streaming coordination mode is disabled" 错误
   - **自动回退到 Direct 模式**

这确保了：
- ✅ Outage 检测总是被执行
- ✅ 系统不会因为 ReAct 模式被禁用而崩溃
- ✅ 向后兼容（如果将来启用 ReAct 模式）

