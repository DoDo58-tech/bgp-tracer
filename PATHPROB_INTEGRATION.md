# PathProb_AE 集成指南

本文档说明如何将 PathProb_AE 项目集成到 bgp_tracer 的路由泄露检测模块中。

## 问题描述

如果遇到 `Error: PathProb file not found` 错误，说明系统找不到 `pathprob.txt` 文件。这个文件是 PathProb_AE 项目生成的 AS 关系概率文件，用于路由泄露检测。

## 快速检查

运行检查脚本查看当前集成状态：

```bash
cd /data/bgp_tracer
python3 tools/check_pathprob.py
```

## 解决方案

### 方案 1: 使用 PathProb_AE 生成 pathprob.txt（推荐）

1. **准备 AS 路径数据**

   确保你有 BGP 路径数据文件。这些文件应该包含 AS 路径，格式为：
   ```
   AS1|AS2|AS3|AS4 1
   AS5|AS6|AS7 2
   ```

2. **运行 PathProb_AE 推理**

   ```bash
   cd /data/PathProb_AE
   
   # 激活 Python 环境（如果使用虚拟环境）
   source .python_venv/bin/activate  # 如果存在
   
   # 运行推理
   python3 infer_prob/asrel_prob.py \
     --path_dir <你的AS路径数据目录> \
     --print_dir <输出目录>
   ```

   例如：
   ```bash
   python3 infer_prob/asrel_prob.py \
     --path_dir test_data/prob_inference/paths/202506 \
     --print_dir test_data/prob_inference/result/202506
   ```

3. **验证生成的文件**

   推理完成后，会在 `--print_dir` 指定的目录下生成 `pathprob.txt` 文件。

### 方案 2: 使用环境变量指定路径

如果你已经有 `pathprob.txt` 文件，可以通过环境变量指定：

```bash
export PATHPROB_FILE=/path/to/your/pathprob.txt
```

然后在运行 bgp_tracer 时，系统会自动使用这个路径。

### 方案 3: 放置到默认位置

将 `pathprob.txt` 文件复制到 bgp_tracer 的默认数据目录：

```bash
mkdir -p /data/bgp_tracer/data/pathprob
cp /path/to/pathprob.txt /data/bgp_tracer/data/pathprob/pathprob.txt
```

## 系统搜索路径

系统会按以下顺序搜索 `pathprob.txt` 文件：

1. 环境变量 `PATHPROB_FILE` 指定的路径（如果存在）
2. `/data/bgp_tracer/data/pathprob/pathprob.txt`
3. `/data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt`
4. `/data/PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt`（绝对路径）
5. `../PathProb_AE/test_data/prob_inference/result/202506/pathprob.txt`（相对路径）

## 配置选项

在 `config.py` 中可以配置以下选项：

- `PATHPROB_AE_ROOT`: PathProb_AE 项目的根目录（默认：`/data/PathProb_AE`）
- `PATHPROB_FILE`: 直接指定 pathprob.txt 文件的路径（通过环境变量设置）

## 验证集成

运行检查脚本验证集成是否成功：

```bash
python3 tools/check_pathprob.py
```

如果看到 "Integration Status: ✓ READY"，说明集成成功。

## 使用路由泄露检测

集成成功后，可以在代码中使用路由泄露检测功能：

```python
from tools.leak_detector import analyze_leak_surface

# 分析指定 AS 的路由泄露
result = analyze_leak_surface(
    asn="16010",
    start_time="2025-12-04 11:00",
    end_time="2025-12-04 12:00",
    threshold=0.4  # 可选，默认 0.4
)

if result["success"]:
    print(f"检测到 {result['leak_count']} 个路由泄露")
    for leak in result["route_leaks"]:
        print(f"  前缀: {leak['prefix']}, 概率: {leak['leak_probability']:.3f}")
else:
    print(f"错误: {result['error']}")
```

## 故障排除

### 问题 1: 找不到 pathprob.txt

**解决方案**:
- 运行 `python3 tools/check_pathprob.py` 查看搜索路径
- 确保文件存在于其中一个搜索路径中
- 检查文件权限

### 问题 2: 文件格式错误

**症状**: 加载 AS 关系概率失败

**解决方案**:
- 确保 `pathprob.txt` 格式正确，每行格式为：`AS1|AS2|p2c|p2p|c2p`
- 检查文件编码（应为 UTF-8）
- 重新生成 pathprob.txt 文件

### 问题 3: PathProb_AE 推理失败

**解决方案**:
- 检查输入路径数据格式是否正确
- 确保有足够的磁盘空间
- 查看 PathProb_AE 的日志文件

## 相关文件

- `tools/leak_detector.py`: 路由泄露检测模块
- `tools/check_pathprob.py`: 集成检查工具
- `config.py`: 配置文件
- `/data/PathProb_AE/`: PathProb_AE 项目目录

## 更多信息

- PathProb_AE README: `/data/PathProb_AE/README.md`
- bgp_tracer README: `/data/bgp_tracer/README.md`

