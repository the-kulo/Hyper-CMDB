@echo off
echo ========================================
echo    Hyper-CMDB 开发环境启动脚本
echo ========================================
echo.

:: 检查环境变量文件
if not exist ".env" (
    echo [错误] 未找到 .env 文件，请先复制 .env.example 并配置
    echo 执行命令: copy .env.example .env
    pause
    exit /b 1
)

:: 检查Go环境
go version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Go环境，请先安装Go
    pause
    exit /b 1
)

:: 检查Node.js环境
node --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Node.js环境，请先安装Node.js
    pause
    exit /b 1
)

echo [信息] 环境检查通过
echo.

:: 启动后端服务
echo [启动] 正在启动后端服务...
start "Hyper-CMDB Backend" cmd /k "cd /d %~dp0.. && echo 启动后端服务... && go run cmd/server/main.go"

:: 等待后端服务启动
echo [等待] 等待后端服务启动...
timeout /t 5 /nobreak >nul

:: 启动前端服务
echo [启动] 正在启动前端服务...
start "Hyper-CMDB Frontend" cmd /k "cd /d %~dp0../ui && echo 安装依赖... && npm install && echo 启动前端服务... && npm run dev"

echo.
echo ========================================
echo    服务启动完成！
echo ========================================
echo 后端服务: http://localhost:8080
echo 前端服务: http://localhost:3000
echo 健康检查: http://localhost:8080/health
echo.
echo 按任意键退出...
pause >nul