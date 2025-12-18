# PathProb_AE 工作原理说明

## 重要概念：PathProb_AE 不需要训练！

PathProb_AE **不是机器学习模型**，而是一个**统计推断方法**。它不需要训练过程。

## 工作流程

### 传统机器学习 vs PathProb_AE

| 特性 | 传统机器学习 | PathProb_AE |
|------|------------|-------------|
| 训练阶段 | ✅ 需要（训练集） | ❌ 不需要 |
| 模型参数 | ✅ 需要优化 | ❌ 无模型参数 |
| 推理阶段 | ✅ 使用训练好的模型 | ✅ 直接从数据计算 |
| 数据要求 | 训练集 + 测试集 | 只需要 AS 路径数据 |

### PathProb_AE 的工作过程

```
输入：AS 路径数据
  ↓
步骤1：提取核心路径（Core Paths）
  ↓
步骤2：求解初始 AS 关系（ASRelSolver）
  ↓
步骤3：Gibbs 采样推断（1000 次迭代）
  ↓
步骤4：推断边缘链接（Edge Links）
  ↓
输出：pathprob.txt（AS 关系概率）
```

### 详细说明

#### 1. 输入数据
- **AS 路径文件**：包含从 BGP 更新中提取的 AS 路径
- 格式：`AS1|AS2|AS3 5`（路径和出现次数）

#### 2. 处理过程（这是推理，不是训练）

**步骤 1：提取核心路径**
```python
asrel_prob.get_core_path()  # 从路径中提取核心链接
```

**步骤 2：求解初始 AS 关系**
```python
asrel_solver = ASRelSolver(self.corepaths)
init_asrel = asrel_solver.solute_asrel_for_clinks()  # 求解初始关系
```

**步骤 3：Gibbs 采样推断**
```python
gibbs_sampling = GibbsSampling(self.corepaths, init_asrel)
self.clinks = gibbs_sampling.infer_asrel_prob(1000)  # 1000 次迭代
```

**步骤 4：推断边缘链接**
```python
asrel_prob.infer_edge_link()  # 推断边缘 AS 对的关系
```

#### 3. 输出结果
- **pathprob.txt**：每个 AS 对的关系概率
- 格式：`AS1|AS2|p2c|p2p|c2p`
  - p2c: Provider-to-Customer 概率
  - p2p: Peer-to-Peer 概率
  - c2p: Customer-to-Provider 概率

## 为什么不需要训练？

### 1. 基于统计推断
PathProb_AE 使用 **Gibbs 采样**（一种马尔可夫链蒙特卡洛方法）来推断概率。这是：
- ✅ **无监督方法**：不需要标注数据
- ✅ **统计方法**：基于路径频率和上下文信息
- ✅ **确定性算法**：给定相同输入，结果可重现

### 2. 每次运行都重新计算
- 每次运行 `asrel_prob.py` 都会：
  - 读取新的 AS 路径数据
  - 重新计算所有概率
  - 生成新的 pathprob.txt

### 3. 没有模型参数
- 不像神经网络需要训练权重
- 不像传统 ML 需要优化超参数
- 算法参数是固定的（如 Gibbs 采样迭代次数 1000）

## 实际使用

### 一次性运行（推荐）

```bash
# 1. 提取 AS 路径（从你的 BGP 数据）
cd /data/bgp_tracer
python3 tools/extract_as_paths_for_pathprob.py \
  --start_time "2025-12-04 11:00" \
  --end_time "2025-12-04 12:00" \
  --output_dir /data/PathProb_AE/test_data/prob_inference/paths/202506

# 2. 运行推理（这就是"训练"的等价操作）
cd /data/PathProb_AE
python3 infer_prob/asrel_prob.py \
  --path_dir test_data/prob_inference/paths/202506 \
  --print_dir test_data/prob_inference/result/202506

# 完成！pathprob.txt 已生成
```

### 定期更新（可选）

如果你想使用最新的 BGP 数据：

```bash
# 每周/每月重新运行一次
# 1. 提取新的 AS 路径
# 2. 重新运行推理
# 3. 生成新的 pathprob.txt
```

## 常见误解

### ❌ 误解 1：需要训练模型
**正确理解**：PathProb_AE 是统计推断方法，不是 ML 模型，不需要训练。

### ❌ 误解 2：需要预训练模型
**正确理解**：每次运行都从零开始计算，不需要预训练模型。

### ❌ 误解 3：需要训练集和测试集
**正确理解**：只需要 AS 路径数据，不需要标注的训练/测试集。

### ✅ 正确理解
- PathProb_AE 是**统计推断工具**
- 从 AS 路径数据中**直接计算**关系概率
- 每次运行都是**独立的推理过程**
- 类似于"计算"而不是"训练"

## 性能说明

### 计算时间
- **小数据集**（< 100K 路径）：5-10 分钟
- **中等数据集**（100K - 1M 路径）：10-30 分钟
- **大数据集**（> 1M 路径）：30 分钟 - 2 小时

### 内存占用
- 取决于 AS 路径数量和唯一 AS 对数量
- 通常需要 4-16 GB RAM

## 总结

1. ✅ **不需要训练**：PathProb_AE 是统计推断方法
2. ✅ **直接计算**：从 AS 路径数据直接计算概率
3. ✅ **每次独立**：每次运行都是完整的推理过程
4. ✅ **简单使用**：提供 AS 路径数据，运行脚本即可

**类比**：就像计算平均值一样，不需要"训练"，只需要数据就能计算！

