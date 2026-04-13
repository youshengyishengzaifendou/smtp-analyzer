@echo off
chcp 65001 >nul
setlocal

echo ============================================
echo  smtp-analyzer 上传到 GitHub
echo ============================================
echo.

REM 检查 git 是否安装
git --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 git，请先安装 Git：https://git-scm.com/download/win
    pause & exit /b 1
)

REM 检查 gh CLI 是否安装
gh --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 GitHub CLI (gh)，请先安装：https://cli.github.com/
    echo 安装后运行 "gh auth login" 完成登录
    pause & exit /b 1
)

REM 检查 gh 登录状态
gh auth status >nul 2>&1
if errorlevel 1 (
    echo [提示] 请先登录 GitHub CLI：
    gh auth login
)

echo [1/5] 初始化 git 仓库...
git init
if errorlevel 1 ( echo [错误] git init 失败 & pause & exit /b 1 )

echo [2/5] 设置默认分支为 main...
git checkout -b main 2>nul || git checkout main

echo [3/5] 添加所有文件...
git add .
if errorlevel 1 ( echo [错误] git add 失败 & pause & exit /b 1 )

echo [4/5] 创建初始提交...
git commit -m "feat: initial commit - SMTP traffic integrity analyzer

- Parse pcap/pcapng files for SMTP flows
- Detect TCP completeness and bidirectionality  
- Support VLAN (including QinQ)
- Output JSON/CSV reports with anomaly tags

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
if errorlevel 1 ( echo [错误] git commit 失败 & pause & exit /b 1 )

echo [5/5] 创建 GitHub 仓库并推送 (internal 可见性)...
gh repo create relaxcloud-cn/smtp-analyzer ^
    --internal ^
    --description "SMTP 流量完整性分析工具，解析 pcap/pcapng 文件，判断 SMTP 连接完整性与双向性" ^
    --source . ^
    --push

if errorlevel 1 (
    echo.
    echo [提示] 如果仓库已存在，尝试直接推送...
    git remote add origin https://github.com/relaxcloud-cn/smtp-analyzer.git 2>nul
    git push -u origin main
)

echo.
echo ============================================
echo  完成！仓库地址：
echo  https://github.com/relaxcloud-cn/smtp-analyzer
echo ============================================
pause
