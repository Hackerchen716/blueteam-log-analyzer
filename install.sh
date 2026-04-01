#!/bin/bash
# BlueTeam Log Analyzer - Mac 安装脚本
set -e

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║    BlueTeam Log Analyzer (BLA) 安装程序          ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 检查 Python 版本
PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
if [ -z "$PYTHON" ]; then
    echo "❌ 未找到 Python 3，请先安装 Python 3.9+"
    exit 1
fi

PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✓ Python 版本: $PY_VER"

# 安装方式选择
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "安装方式:"
echo "  1. 安装到系统 (pip install -e .)  [推荐]"
echo "  2. 仅创建快捷方式 (不安装依赖)"
echo ""
read -p "请选择 [1/2]: " choice

if [ "$choice" = "1" ]; then
    echo ""
    echo "正在安装..."
    cd "$SCRIPT_DIR"
    $PYTHON -m pip install -e . --quiet
    echo "✓ 安装完成！"
    echo ""
    echo "可选：安装 EVTX 二进制解析支持:"
    echo "  pip install python-evtx"
else
    # 创建快捷脚本
    BLA_BIN="/usr/local/bin/bla"
    echo "#!/bin/bash" > "$BLA_BIN"
    echo "exec $PYTHON $SCRIPT_DIR/bla_cli.py \"\$@\"" >> "$BLA_BIN"
    chmod +x "$BLA_BIN"
    echo "✓ 快捷命令已创建: $BLA_BIN"
fi

echo ""
echo "════════════════════════════════════════════════════"
echo "  使用方法:"
echo ""
echo "  bla /var/log/auth.log"
echo "  bla /path/to/Security.xml --html report.html"
echo "  bla logs/ --json out.json --csv out.csv"
echo "  bla *.evtx --verbose"
echo ""
echo "  bla --help   查看完整帮助"
echo "════════════════════════════════════════════════════"
echo ""
