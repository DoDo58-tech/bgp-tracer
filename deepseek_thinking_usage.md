# DeepSeek思考模式使用指南

## 🎯 概述
BGP Tracer现在支持DeepSeek的思考模式，能够为复杂网络安全分析提供更深入的推理能力。

## ⚙️ 配置说明

### 默认配置
- **思考模式**: 默认启用 (`DEEPSEEK_THINKING_ENABLED=true`)
- **思考模型**: `deepseek-reasoner`
- **普通模型**: `deepseek-chat`

### 环境变量控制

#### 启用思考模式
```bash
export DEEPSEEK_THINKING_ENABLED=true
# 自动使用 deepseek-reasoner 模型
```

#### 关闭思考模式  
```bash
export DEEPSEEK_THINKING_ENABLED=false
# 自动使用 deepseek-chat 模型
```

#### 自定义模型
```bash
export DEEPSEEK_THINKING_MODEL=deepseek-reasoner  # 思考模式模型
export DEEPSEEK_CHAT_MODEL=deepseek-chat         # 普通聊天模型
```

## 🧠 思考模式特点

### 适用场景
- ✅ 复杂网络安全事件分析
- ✅ 多模态数据关联推理  
- ✅ 因果关系判断
- ✅ 攻击链分析
- ✅ 影响评估

### 输出特点
- 📝 结构化思考过程
- 🔍 深入的推理步骤
- ⚖️ 置信度评估
- 🎯 可操作性建议

## 🚀 使用方法

### 1. 启动思考模式（推荐用于复杂分析）
```bash
export DEEPSEEK_THINKING_ENABLED=true
python3 chief_agent.py --analyze-asn 17557 --start "2024-01-01 10:00" --end "2024-01-01 12:00"
```

### 2. 普通模式（快速响应）
```bash
export DEEPSEEK_THINKING_ENABLED=false  
python3 chief_agent.py --analyze-asn 17557 --start "2024-01-01 10:00" --end "2024-01-01 12:00"
```

### 3. 检查当前配置
```bash
python3 -c "from config import MODEL, DEEPSEEK_THINKING_ENABLED; print(f'模型: {MODEL}, 思考模式: {DEEPSEEK_THINKING_ENABLED}')"
```

## 📊 性能对比

| 模式 | 模型 | 响应速度 | 推理深度 | 适用场景 |
|------|------|----------|----------|----------|
| 思考模式 | deepseek-reasoner | 较慢 | 深度推理 | 复杂分析 |
| 普通模式 | deepseek-chat | 较快 | 基础分析 | 简单查询 |

## 💡 最佳实践

1. **复杂事件分析**: 启用思考模式，获得详细推理过程
2. **实时监控**: 使用普通模式，提高响应速度  
3. **批量处理**: 根据任务复杂度选择相应模式
4. **资源管理**: 思考模式消耗更多token，注意API费用

## 🔧 故障排除

### 问题: 模型切换不生效
```bash
# 强制重新加载配置
unset DEEPSEEK_THINKING_ENABLED
export DEEPSEEK_THINKING_ENABLED=true
```

### 问题: API调用失败
```bash
# 检查API密钥和网络连接
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.deepseek.com/models
```

## 📈 未来扩展

- 支持更多思考模型
- 动态模型切换
- 推理质量评估
- 多模型集成

---

**DeepSeek思考模式已就绪，为您的网络安全分析提供强大的推理能力！** 🚀
