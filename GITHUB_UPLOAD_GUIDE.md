# GitHub上传指南

本指南将帮助您将BGP Tracer项目代码上传到GitHub，同时排除所有数据文件和敏感信息。

## 📋 准备工作

### 1. 检查Git状态

首先检查当前目录是否已经是Git仓库：

```bash
cd /data/bgp_tracer
git status
```

如果显示"not a git repository"，需要初始化Git仓库。

### 2. 初始化Git仓库（如果还没有）

```bash
cd /data/bgp_tracer
git init
```

---

## 🔒 配置Git忽略文件

项目已经包含了`.gitignore`文件，它会自动排除：
- 所有数据文件（`data/updates_rrc00/`, `data/event_features/`等）
- 缓存文件（`cache/`, `__pycache__/`）
- 日志文件（`logs/`）
- 结果文件（`results/`）
- 配置文件中的敏感信息（`config.py`）

**重要**: `config.py`会被忽略，请使用`config.py.example`作为模板。

---

## 📝 配置步骤

### 步骤1: 创建配置文件模板

如果您还没有`config.py.example`，请从`config.py`复制并移除敏感信息：

```bash
# 如果config.py包含敏感信息，请手动编辑config.py.example
# 确保所有API密钥、令牌等都替换为占位符
```

### 步骤2: 检查要提交的文件

查看哪些文件会被Git跟踪：

```bash
git status
```

应该只显示代码文件，不应该包含：
- ❌ `data/updates_rrc00/`
- ❌ `data/event_features/`
- ❌ `cache/`
- ❌ `logs/`
- ❌ `results/`
- ❌ `config.py`（包含敏感信息）

### 步骤3: 添加文件到Git

```bash
# 添加所有代码文件
git add .

# 检查将要提交的文件
git status
```

### 步骤4: 提交代码

```bash
git commit -m "Initial commit: BGP Tracer project code

- BGP异常检测系统
- 特征提取和可视化模块
- 路由劫持/泄露检测
- LLM增强分析
- PathProb集成"
```

---

## 🚀 上传到GitHub

### 方法1: 使用GitHub CLI（推荐）

#### 1. 安装GitHub CLI（如果还没有）

```bash
# Ubuntu/Debian
sudo apt install gh

# 或使用官方安装脚本
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh
```

#### 2. 登录GitHub

```bash
gh auth login
```

按照提示完成登录。

#### 3. 创建仓库并推送

```bash
# 创建新的GitHub仓库（私有或公开）
gh repo create bgp-tracer --public --source=. --remote=origin --push

# 或者如果仓库已存在，只设置远程并推送
git remote add origin https://github.com/YOUR_USERNAME/bgp-tracer.git
git branch -M main
git push -u origin main
```

### 方法2: 使用Git命令（传统方式）

#### 1. 在GitHub上创建新仓库

1. 访问 https://github.com/new
2. 填写仓库名称（例如：`bgp-tracer`）
3. 选择公开（Public）或私有（Private）
4. **不要**初始化README、.gitignore或license（我们已经有了）
5. 点击"Create repository"

#### 2. 添加远程仓库

```bash
# 替换YOUR_USERNAME为您的GitHub用户名
git remote add origin https://github.com/YOUR_USERNAME/bgp-tracer.git

# 或者使用SSH（如果您配置了SSH密钥）
git remote add origin git@github.com:YOUR_USERNAME/bgp-tracer.git
```

#### 3. 推送代码

```bash
# 重命名主分支为main（如果还没有）
git branch -M main

# 推送代码到GitHub
git push -u origin main
```

---

## ✅ 验证上传

### 1. 检查GitHub仓库

访问您的GitHub仓库页面，确认：
- ✅ 所有代码文件都已上传
- ✅ 没有数据文件（`data/updates_rrc00/`等）
- ✅ 没有`config.py`（包含敏感信息）
- ✅ 有`config.py.example`模板文件
- ✅ 有`.gitignore`文件

### 2. 克隆测试（可选）

在另一个目录测试克隆：

```bash
cd /tmp
git clone https://github.com/YOUR_USERNAME/bgp-tracer.git
cd bgp-tracer
ls -la

# 应该看到代码文件，但不应该看到数据文件
```

---

## 🔐 安全注意事项

### 已排除的敏感信息

以下内容**不会**被上传到GitHub：
- ✅ `config.py` - 包含API密钥和令牌
- ✅ 所有数据文件
- ✅ 日志文件
- ✅ 缓存文件

### 如果意外提交了敏感信息

如果发现敏感信息被提交了，请立即：

1. **撤销最后一次提交**（如果还没有推送）：
```bash
git reset --soft HEAD~1
# 编辑文件移除敏感信息
git add .
git commit -m "Remove sensitive information"
```

2. **如果已经推送到GitHub**：
   - 立即在GitHub上删除仓库或重置仓库
   - 更改所有API密钥和令牌
   - 使用`git filter-branch`或`git filter-repo`从历史中移除敏感信息

3. **检查Git历史**：
```bash
# 查看提交历史
git log --oneline

# 检查特定文件的历史
git log --all --full-history -- config.py
```

---

## 📦 项目结构（上传后）

上传到GitHub后，仓库应该包含：

```
bgp-tracer/
├── .gitignore                 # Git忽略规则
├── README.md                  # 项目说明
├── requirements.txt           # Python依赖
├── environment.yml           # Conda环境配置
├── config.py.example         # 配置模板（不含敏感信息）
├── chief_agent.py            # 主代理
├── extract_event_features.py # 特征提取
├── plot_event_features.py    # 可视化
├── agents/                   # 代理模块
├── tools/                    # 工具模块
├── utils/                    # 工具函数
├── data/                     # 数据目录（空或只有示例）
│   ├── asorg_loader.py
│   ├── asrel_loader.py
│   └── updates_loader.py
├── docs/                     # 文档
├── llm/                      # LLM相关
├── scripts/                  # 脚本
└── templates/                # 模板
```

**不应该包含**：
- ❌ `data/updates_rrc00/` - BGP更新数据
- ❌ `data/event_features/` - 特征提取结果
- ❌ `cache/` - 缓存文件
- ❌ `logs/` - 日志文件
- ❌ `results/` - 结果文件
- ❌ `config.py` - 包含敏感信息

---

## 🆘 常见问题

### Q1: 如何更新已上传的代码？

```bash
# 修改代码后
git add .
git commit -m "描述您的更改"
git push
```

### Q2: 如何添加新的忽略规则？

编辑`.gitignore`文件，添加新的规则，然后：

```bash
# 如果之前已经跟踪了这些文件，需要从Git中移除
git rm --cached <file>
git commit -m "Update .gitignore"
git push
```

### Q3: 如何创建新分支？

```bash
git checkout -b feature/new-feature
# 进行更改
git add .
git commit -m "Add new feature"
git push -u origin feature/new-feature
```

### Q4: 如何查看被忽略的文件？

```bash
git status --ignored
```

---

## 📚 后续步骤

上传完成后，建议：

1. **添加README说明**：
   - 项目简介
   - 安装说明
   - 使用示例
   - 配置说明（指向`config.py.example`）

2. **添加LICENSE文件**：
   - 选择合适的开源许可证（MIT、Apache 2.0等）

3. **添加CONTRIBUTING.md**（如果开源）：
   - 贡献指南
   - 代码规范

4. **设置GitHub Actions**（可选）：
   - 自动测试
   - 代码检查

---

## ✅ 完成检查清单

- [ ] `.gitignore`文件已创建并配置正确
- [ ] `config.py.example`已创建（不含敏感信息）
- [ ] `git status`显示只包含代码文件
- [ ] 所有代码已提交
- [ ] 远程仓库已添加
- [ ] 代码已推送到GitHub
- [ ] GitHub仓库已验证（无敏感信息）
- [ ] README已更新（如果需要）

---

**创建时间**: 2025-01-02  
**版本**: 1.0

