#!/bin/bash
# 检查Git状态脚本 - 验证哪些文件会被上传到GitHub

echo "=========================================="
echo "Git状态检查 - 验证上传文件"
echo "=========================================="
echo ""

# 检查是否在Git仓库中
if [ ! -d .git ]; then
    echo "⚠️  当前目录不是Git仓库"
    echo "   运行: git init"
    exit 1
fi

echo "📋 1. 检查.gitignore文件"
if [ -f .gitignore ]; then
    echo "   ✅ .gitignore文件存在"
    echo "   忽略规则数量: $(wc -l < .gitignore)"
else
    echo "   ❌ .gitignore文件不存在！"
    exit 1
fi

echo ""
echo "📋 2. 检查配置文件"
if [ -f config.py.example ]; then
    echo "   ✅ config.py.example存在"
else
    echo "   ⚠️  config.py.example不存在"
fi

if [ -f config.py ]; then
    # 检查config.py是否包含敏感信息
    if grep -q "YOUR_API_KEY_HERE\|YOUR_CLOUDFLARE_API_TOKEN_HERE" config.py 2>/dev/null; then
        echo "   ✅ config.py存在（看起来是模板，安全）"
    else
        echo "   ⚠️  config.py存在（可能包含敏感信息，应该被.gitignore排除）"
    fi
else
    echo "   ℹ️  config.py不存在（正常，应该从config.py.example创建）"
fi

echo ""
echo "📋 3. 检查将被跟踪的文件"
echo "   运行: git status --short"
git status --short | head -20
if [ $(git status --short | wc -l) -gt 20 ]; then
    echo "   ... (还有更多文件)"
fi

echo ""
echo "📋 4. 检查被忽略的文件"
echo "   运行: git status --ignored | head -20"
git status --ignored 2>/dev/null | head -20

echo ""
echo "📋 5. 检查敏感数据目录"
sensitive_dirs=("data/updates_rrc00" "data/event_features" "cache" "logs" "results")
for dir in "${sensitive_dirs[@]}"; do
    if git check-ignore -q "$dir" 2>/dev/null; then
        echo "   ✅ $dir 已被忽略"
    else
        if [ -d "$dir" ] && [ "$(ls -A $dir 2>/dev/null)" ]; then
            echo "   ⚠️  $dir 存在但未被忽略！"
        fi
    fi
done

echo ""
echo "📋 6. 统计信息"
echo "   将被跟踪的文件数: $(git ls-files 2>/dev/null | wc -l)"
echo "   未跟踪的文件数: $(git status --porcelain | grep '^??' | wc -l)"

echo ""
echo "=========================================="
echo "检查完成"
echo "=========================================="
echo ""
echo "如果看到⚠️，请检查.gitignore文件"
echo "如果一切正常，可以运行:"
echo "  git add ."
echo "  git commit -m 'Initial commit'"
echo "  git push"

