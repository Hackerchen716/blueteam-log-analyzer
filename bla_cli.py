#!/usr/bin/env python3
"""
BlueTeam Log Analyzer (BLA) - CLI 入口
蓝队应急响应日志分析工具

用法:
  bla <日志文件或目录> [选项]

示例:
  bla /var/log/auth.log                    # Linux 认证日志
  bla Security.xml --html report.html      # Windows 事件日志
  bla logs/ --json out.json --csv out.csv  # 批量分析目录
  bla *.evtx --verbose                     # EVTX 详细模式
"""

import sys
import os
import argparse
import glob
from typing import List

# Windows 10+ 启用 ANSI 颜色支持
if sys.platform == "win32":
    import ctypes
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

from bla.parsers import auto_parse
from bla.detection import run_detection
from bla.allowlist import apply_allowlist, load_allowlist
from bla.output import (
    print_terminal_report,
    generate_html_report,
    generate_json_report,
    generate_csv_report,
    generate_ioc_report,
)
from bla.utils.helpers import reset_counter, set_syslog_year
from bla.models import ParseResult


def main():
    parser = argparse.ArgumentParser(
        prog="bla",
        description="BlueTeam Log Analyzer - 蓝队应急响应日志分析工具",
        epilog="示例: bla /var/log/auth.log --html report.html",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "paths",
        nargs="+",
        help="日志文件或目录路径（支持通配符）",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="生成 HTML 报告（独立单文件，无需网络）",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="生成 JSON 报告",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="导出 CSV 事件列表（便于 Excel 分析）",
    )
    parser.add_argument(
        "--ioc",
        metavar="FILE",
        help="导出 IOC 清单（IP、域名、URL、路径、Hash、账户、进程、命令）",
    )
    parser.add_argument(
        "--profile",
        choices=("default", "cn-hvv"),
        default="default",
        help="检测画像：default 通用模式，cn-hvv 国内护网/重保增强模式",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FILE",
        help="加载 JSON 白名单，过滤可信 IP/账户/路径/进程/UA 等误报",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细模式：显示所有高危以上事件",
    )
    parser.add_argument(
        "--max-alerts",
        type=int,
        default=50,
        metavar="N",
        help="终端报告最多展示的告警数，0 表示全部展示（默认: 50）",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用终端彩色输出",
    )
    parser.add_argument(
        "--syslog-year",
        type=int,
        metavar="YEAR",
        help="指定 Linux syslog/auth.log 这类无年份时间戳使用的年份",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="BLA 1.0.0",
    )

    args = parser.parse_args()

    if args.max_alerts < 0:
        print("❌ 错误：--max-alerts 不能小于 0", file=sys.stderr)
        sys.exit(1)

    if args.syslog_year is not None:
        if args.syslog_year < 1970 or args.syslog_year > 2100:
            print("❌ 错误：--syslog-year 必须在 1970 到 2100 之间", file=sys.stderr)
            sys.exit(1)
        set_syslog_year(args.syslog_year)

    # 收集所有文件
    files = []
    for path in args.paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            for root, _, fnames in os.walk(path):
                for fname in fnames:
                    if not fname.startswith("."):
                        files.append(os.path.join(root, fname))
        else:
            # 通配符
            files.extend(glob.glob(path))

    if not files:
        print("❌ 错误：未找到任何日志文件", file=sys.stderr)
        sys.exit(1)

    # 去重
    files = sorted(set(files))
    print(f"\n🔍 开始分析 {len(files)} 个文件...\n")

    # 解析所有文件
    reset_counter()
    parse_results: List[ParseResult] = []

    for i, fpath in enumerate(files, 1):
        fname = os.path.basename(fpath)
        print(f"  [{i}/{len(files)}] 解析: {fname} ...", end=" ", flush=True)
        try:
            result = auto_parse(fpath)
            parse_results.append(result)
            print(f"✓ ({result.stats.total} 事件)")
        except Exception as e:
            print(f"✗ 错误: {e}")
            continue

    if not parse_results:
        print("\n❌ 所有文件解析失败", file=sys.stderr)
        sys.exit(1)

    if args.allowlist:
        try:
            allowlist = load_allowlist(args.allowlist)
            parse_results, suppressed = apply_allowlist(parse_results, allowlist)
            print(f"\n✓ 白名单过滤完成，压制 {suppressed} 条事件\n")
        except Exception as e:
            print(f"\n❌ 白名单加载失败: {e}", file=sys.stderr)
            sys.exit(1)

    # 合并所有事件
    all_events = []
    for r in parse_results:
        all_events.extend(r.events)

    print(f"\n✓ 解析完成，共 {len(all_events)} 条事件\n")
    print("🔎 运行威胁检测引擎...\n")

    # 运行检测
    summary = run_detection(all_events, profile=args.profile)

    print(f"✓ 检测完成，发现 {len(summary.alerts)} 个告警\n")

    # 输出报告
    print_terminal_report(parse_results, summary, args.verbose, args.no_color, args.max_alerts)

    if args.html:
        generate_html_report(parse_results, summary, args.html)
    if args.json:
        generate_json_report(parse_results, summary, args.json)
    if args.csv:
        generate_csv_report(parse_results, summary, args.csv)
    if args.ioc:
        generate_ioc_report(parse_results, summary, args.ioc)

    # 退出码：有严重告警则返回 1
    if any(a.level.value == "critical" for a in summary.alerts):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ 致命错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
