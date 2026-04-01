@echo off
:: BlueTeam Log Analyzer - Windows 安装脚本
:: 需要 Python 3.9+ 已安装并加入 PATH

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║    BlueTeam Log Analyzer (BLA) 安装程序          ║
echo ║    Windows 版                                     ║
echo ╚══════════════════════════════════════════════════╝
echo.

:: 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 未找到 Python，请先安装 Python 3.9+
    echo         下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [OK] Python 版本: %PY_VER%

:: 获取脚本所在目录
set SCRIPT_DIR=%~dp0

:: 安装
echo.
echo 正在安装...
cd /d "%SCRIPT_DIR%"
python -m pip install -e . --quiet
if errorlevel 1 (
    echo [ERROR] 安装失败，请检查 pip 是否可用
    pause
    exit /b 1
)

echo [OK] 安装完成！
echo.
echo 可选：安装 EVTX 二进制解析支持:
echo   pip install python-evtx
echo.
echo ════════════════════════════════════════════════════
echo   使用方法:
echo.
echo   bla C:\Windows\System32\winevt\Logs\Security.evtx
echo   bla Security.xml --html report.html
echo   bla logs\ --json out.json --csv out.csv
echo   bla --help
echo ════════════════════════════════════════════════════
echo.
pause
