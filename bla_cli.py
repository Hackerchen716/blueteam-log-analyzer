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
  bla logs/ --sarif report.sarif           # 接入 GitHub Code Scanning
"""

import sys
import os
import argparse
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

# Windows 10+ 启用 ANSI 颜色支持
if sys.platform == "win32":
    import ctypes
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

from bla.config import (
    THRESHOLDS, load_thresholds, load_thresholds_from_env, set_thresholds,
)
from bla.parsers import auto_parse
from bla.detection import run_detection
from bla.allowlist import apply_allowlist, load_allowlist
from bla.rules import set_rule_dirs
from bla.output import (
    print_terminal_report,
    generate_html_report,
    generate_json_report,
    generate_csv_report,
    generate_ioc_report,
    generate_sarif_report,
    generate_report_bundle,
)
from bla.utils.helpers import reset_counter, safe_print as print, set_syslog_year
from bla.models import ParseResult, ThreatLevel


_EXIT_THRESHOLDS = {
    "none":     None,
    "critical": ThreatLevel.CRITICAL.score,
    "high":     ThreatLevel.HIGH.score,
    "medium":   ThreatLevel.MEDIUM.score,
}


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
        "--sarif",
        metavar="FILE",
        help="生成 SARIF 2.1.0 报告（可上传到 GitHub Code Scanning 等）",
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        help="生成标准报告目录（index.html/report.json/events.csv/iocs.txt/report.sarif）",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="加载自定义阈值 JSON（覆盖暴力破解 / DDoS 等内置阈值）",
    )
    parser.add_argument(
        "--rules",
        action="append",
        metavar="DIR",
        help="加载自定义 YAML 规则目录（可多次指定，当前支持 web_attacks 规则）",
    )
    parser.add_argument(
        "--exit-on",
        choices=tuple(_EXIT_THRESHOLDS.keys()),
        default="critical",
        help="按告警最高级别决定退出码：critical（默认 1）/ high / medium / none",
    )
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=0,
        metavar="N",
        help="并行解析的线程数，0 表示自动（默认: 0）。仅 IO/正则密集型解析受益",
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

    # 阈值加载顺序：内置默认 → 环境变量 → --config 文件
    set_thresholds(load_thresholds_from_env())
    if args.config:
        try:
            set_thresholds(load_thresholds(args.config))
        except Exception as e:
            print(f"❌ 错误：阈值文件加载失败: {e}", file=sys.stderr)
            sys.exit(1)

    rule_dirs = []
    if os.environ.get("BLA_RULES_DIR"):
        rule_dirs.extend([p for p in os.environ["BLA_RULES_DIR"].split(os.pathsep) if p])
    if args.rules:
        rule_dirs.extend(args.rules)
    try:
        set_rule_dirs(rule_dirs)
    except Exception as e:
        print(f"❌ 错误：规则目录加载失败: {e}", file=sys.stderr)
        sys.exit(1)

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

    # gen_id 是全局计数器，多线程并行解析时事件 ID 仍唯一（GIL 保证 +=
    # 原子）；多进程会破坏计数器一致性，因此只用线程池。1 个文件时不引入
    # 线程开销。
    workers = args.jobs if args.jobs > 0 else min(8, max(1, len(files)))
    if len(files) <= 1 or workers == 1:
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
    else:
        print(f"  并行解析（{workers} 个线程）...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_path = {pool.submit(auto_parse, fpath): fpath for fpath in files}
            done = 0
            for future in as_completed(future_to_path):
                done += 1
                fpath = future_to_path[future]
                fname = os.path.basename(fpath)
                try:
                    result = future.result()
                    parse_results.append(result)
                    print(f"  [{done}/{len(files)}] ✓ {fname} ({result.stats.total} 事件)")
                except Exception as e:
                    print(f"  [{done}/{len(files)}] ✗ {fname}: {e}")

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
    if args.sarif:
        generate_sarif_report(parse_results, summary, args.sarif)
    if args.out:
        generate_report_bundle(parse_results, summary, args.out)

    # 退出码：可通过 --exit-on 控制触发等级
    threshold = _EXIT_THRESHOLDS.get(args.exit_on)
    if threshold is None:
        sys.exit(0)
    if any(a.level.score >= threshold for a in summary.alerts):
        sys.exit(1)
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
