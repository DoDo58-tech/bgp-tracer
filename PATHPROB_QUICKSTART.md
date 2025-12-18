# PathProb_AE 快速开始指南

## ⚠️ 重要说明：PathProb_AE 不需要训练！

PathProb_AE **不是机器学习模型**，而是一个**统计推断方法**。它：
- ❌ **不需要训练**：没有训练阶段
- ❌ **不需要预训练模型**：每次运行都从零开始计算
- ✅ **直接计算**：从 AS 路径数据直接推断概率
- ✅ **简单使用**：提供数据，运行脚本即可

**类比**：就像计算平均值一样，不需要"训练"，只需要数据就能计算！

## 问题：AS 路径数据是什么？

**AS 路径（AS Path）** 是 BGP 路由中从源 AS 到目标 AS 经过的所有 AS 编号序列。

例如：`AS1|AS2|AS3|AS4` 表示数据包从 AS1 → AS2 → AS3 → AS4。

PathProb_AE 需要这些 AS 路径数据来推断 AS 之间的关系概率。

## 解决方案：从 BGP 数据中提取 AS 路径

我们提供了一个工具，可以从 bgp_tracer 的 BGP 更新数据中自动提取 AS 路径。

### 方法 1：使用提取工具（推荐）

#### 步骤 1: 提取 AS 路径

```bash
cd /data/bgp_tracer

# 从指定时间段的 BGP 数据中提取 AS 路径
python3 tools/extract_as_paths_for_pathprob.py \
  --start_time "2025-12-04 11:00" \
  --end_time "2025-12-04 12:00" \
  --output_dir /data/PathProb_AE/test_data/prob_inference/paths/202506
```

**参数说明：**
- `--start_time`: 开始时间（格式：YYYY-MM-DD HH:MM）
- `--end_time`: 结束时间（格式：YYYY-MM-DD HH:MM）
- `--output_dir`: 输出目录（PathProb_AE 期望的路径格式）
- `--min_path_length`: 最小路径长度（可选，默认 2）

**输出格式：**
工具会生成 `as_paths.txt` 文件，格式如下：
```
AS1|AS2|AS3 5
AS4|AS5|AS6|AS7 2
AS8|AS9
```

每行表示一个 AS 路径，可选地后面跟出现次数。

#### 步骤 2: 运行 PathProb_AE 推理（这就是全部！不需要训练）

```bash
cd /data/PathProb_AE

# 激活 Python 环境（如果使用虚拟环境）
# source .python_venv/bin/activate

# 运行推理（这不是训练，而是统计推断）
python3 infer_prob/asrel_prob.py \
  --path_dir test_data/prob_inference/paths/202506 \
  --print_dir test_data/prob_inference/result/202506
```

**参数说明：**
- `--path_dir`: AS 路径文件所在目录（步骤1的输出目录）
- `--print_dir`: 输出目录（pathprob.txt 将保存在这里）

**注意**：这个过程会：
1. 提取核心路径
2. 使用 Gibbs 采样推断 AS 关系概率（1000 次迭代）
3. 生成 pathprob.txt 文件

**这不是训练**，而是基于统计推断的概率计算！

#### 步骤 3: 验证生成的文件

```bash
# 检查生成的文件
ls -lh /data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt

# 查看文件前几行
head -5 /data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt
```

文件格式应该是：
```
AS1|AS2|0.85|0.10|0.05
AS3|AS4|0.90|0.05|0.05
```

每行格式：`AS1|AS2|p2c|p2p|c2p`
- p2c: Provider-to-Customer 概率
- p2p: Peer-to-Peer 概率  
- c2p: Customer-to-Provider 概率

### 方法 2：手动准备 AS 路径数据

如果你已经有 AS 路径数据，可以手动创建文件。

#### 文件格式要求

创建文本文件，每行一个 AS 路径：

**格式 1：不带计数（默认计数为 1）**
```
AS1|AS2|AS3
AS4|AS5|AS6|AS7
```

**格式 2：带计数（推荐，更高效）**
```
AS1|AS2|AS3 100
AS4|AS5|AS6|AS7 50
```

#### 示例：从 BGP 更新数据手动提取

如果你有 BGP 更新数据（如 MRT 文件），可以手动提取：

```bash
# 使用 bgpdump 提取 AS 路径（如果已安装）
bgpdump -m your_bgp_data.mrt | \
  grep "|A|" | \
  awk -F'|' '{print $6}' | \
  sed 's/ /|/g' > as_paths.txt
```

### 方法 3：使用现有数据

如果你已经有 PathProb_AE 的测试数据：

```bash
# 下载测试数据（如果还没有）
cd /data/PathProb_AE
wget https://github.com/hyq8868/PathProb_AE/releases/download/v1.1/test_data.tar.zst
zstd -d test_data.tar.zst -c | tar -xf -

# 直接运行推理
python3 infer_prob/asrel_prob.py \
  --path_dir test_data/prob_inference/paths/202506 \
  --print_dir test_data/prob_inference/result/202506
```

## 完整工作流程示例

```bash
# 1. 提取 AS 路径（从你的 BGP 数据）
cd /data/bgp_tracer
python3 tools/extract_as_paths_for_pathprob.py \
  --start_time "2025-12-04 11:00" \
  --end_time "2025-12-04 12:00" \
  --output_dir /data/PathProb_AE/test_data/prob_inference/paths/202506

# 2. 运行 PathProb_AE 推理
cd /data/PathProb_AE
python3 infer_prob/asrel_prob.py \
  --path_dir test_data/prob_inference/paths/202506 \
  --print_dir test_data/prob_inference/result/202506

# 3. 验证集成
cd /data/bgp_tracer
python3 tools/check_pathprob.py

# 4. 现在可以使用路由泄露检测了！
```

## 常见问题

### Q1: 需要多少数据？

**A:** 建议至少提取 1-2 小时的 BGP 数据，包含至少 10,000 条不同的 AS 路径。数据越多，推理结果越准确。

### Q2: 推理需要多长时间？

**A:** 根据数据量：
- 小数据集（< 100K 路径）：5-10 分钟
- 中等数据集（100K - 1M 路径）：10-30 分钟
- 大数据集（> 1M 路径）：30 分钟 - 2 小时

### Q3: 如何选择时间段？

**A:** 
- 选择网络相对稳定的时间段（避免重大事件）
- 建议选择工作日正常时段
- 至少包含 1 小时的数据

### Q4: 输出文件在哪里？

**A:** 根据 `--print_dir` 参数，文件会在：
```
/data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt
```

### Q5: 如何验证文件是否正确？

**A:** 
```bash
# 检查文件是否存在
ls -lh /data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt

# 检查文件格式
head -3 /data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt

# 应该看到类似：
# AS1|AS2|0.85|0.10|0.05
# AS3|AS4|0.90|0.05|0.05
```

## 下一步

生成 `pathprob.txt` 后，路由泄露检测模块就可以正常工作了！

```python
from tools.leak_detector import analyze_leak_surface

result = analyze_leak_surface(
    asn="16010",
    start_time="2025-12-04 11:00",
    end_time="2025-12-04 12:00"
)
```

## 需要帮助？

- 查看详细集成文档：`/data/bgp_tracer/PATHPROB_INTEGRATION.md`
- 运行检查工具：`python3 tools/check_pathprob.py`
- 查看 PathProb_AE README：`/data/PathProb_AE/README.md`

