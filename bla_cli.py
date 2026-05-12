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
import json
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import List

# Windows 10+ 启用 ANSI 颜色支持
if sys.platform == "win32":
    import ctypes
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

from bla.__version__ import __version__
from bla.core import (
    AnalysisError,
    AnalysisOptions,
    AnalysisOutputs,
    collect_files,
    parse_files,
    run_analysis,
    write_reports,
)
from bla.log_sources import format_log_source_priorities
from bla.detection import run_detection
from bla.rules import validate_web_attack_rules
from bla.output import (
    print_terminal_report,
)
from bla.utils.helpers import reset_counter, safe_print as print
from bla.models import ParseResult, ThreatLevel


_EXIT_THRESHOLDS = {
    "none":     None,
    "critical": ThreatLevel.CRITICAL.score,
    "high":     ThreatLevel.HIGH.score,
    "medium":   ThreatLevel.MEDIUM.score,
}


def _dispatch_subcommand(argv: List[str]) -> bool:
    if len(argv) < 2 or argv[1] not in {"validate-rules", "benchmark", "explain"}:
        return False
    command = argv[1]
    if command == "validate-rules":
        _cmd_validate_rules(argv[2:])
    elif command == "benchmark":
        _cmd_benchmark(argv[2:])
    elif command == "explain":
        _cmd_explain(argv[2:])
    return True


def _cmd_validate_rules(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="bla validate-rules",
        description="校验内置和自定义 Web/P0 规则元数据与正则可编译性",
    )
    parser.add_argument("--rules", action="append", metavar="DIR", help="额外规则目录，可重复指定")
    parser.add_argument("--strict-metadata", action="store_true", help="元数据 warning 也作为失败处理")
    args = parser.parse_args(argv)

    try:
        result = validate_web_attack_rules(args.rules or [])
    except Exception as e:
        print(f"❌ 规则校验失败: {e}", file=sys.stderr)
        sys.exit(2)

    print("规则校验结果")
    print(f"  规则数:       {result['raw_rules']}")
    print(f"  编译模式数:   {result['compiled_patterns']}")
    print(f"  errors:      {result['errors']}")
    print(f"  warnings:    {result['warnings']}")
    for item in result["issues"][:50]:
        marker = "ERROR" if item["severity"] == "error" else "WARN"
        print(f"  [{marker}] {item['source']} :: {item['rule']} :: {item['message']}")
    if len(result["issues"]) > 50:
        print(f"  ... 还有 {len(result['issues']) - 50} 条问题未展示")

    if result["errors"] or (args.strict_metadata and result["warnings"]):
        sys.exit(1)
    sys.exit(0)


def _cmd_benchmark(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="bla benchmark",
        description="对真实日志或合成 P0/Web 日志做解析与检测性能评估",
    )
    parser.add_argument("paths", nargs="*", help="可选：真实日志文件/目录；为空时生成合成日志")
    parser.add_argument("--size-mb", type=int, default=10, help="合成日志大小，默认 10MB")
    parser.add_argument("--profile", choices=("default", "cn-hvv"), default="cn-hvv")
    parser.add_argument("-j", "--jobs", type=int, default=0)
    args = parser.parse_args(argv)

    files = _collect_files(args.paths)
    temp_path = None
    if not files:
        temp_path = _make_synthetic_p0_log(args.size_mb)
        files = [str(temp_path)]

    reset_counter()
    tracemalloc.start()
    started = time.perf_counter()
    parse_results = _parse_files(files, args.jobs, quiet=True)
    all_events = [event for result in parse_results for event in result.events]
    summary = run_detection(all_events, profile=args.profile)
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_bytes = sum(result.file_size_bytes for result in parse_results)
    mb = total_bytes / (1024 * 1024) if total_bytes else 0
    eps = len(all_events) / elapsed if elapsed > 0 else 0
    print("Benchmark")
    print(f"  files:       {len(files)}")
    print(f"  size:        {mb:.2f} MB")
    print(f"  events:      {len(all_events)}")
    print(f"  alerts:      {len(summary.alerts)}")
    print(f"  incidents:   {len(summary.incidents)}")
    print(f"  elapsed:     {elapsed:.3f}s")
    print(f"  throughput:  {mb / elapsed if elapsed > 0 else 0:.2f} MB/s")
    print(f"  event rate:  {eps:.0f} events/s")
    print(f"  peak memory: {peak / (1024 * 1024):.2f} MB")
    if temp_path:
        try:
            temp_path.unlink()
        except OSError:
            pass
    sys.exit(0)


def _cmd_explain(argv: List[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="bla explain",
        description="从 JSON 报告解释某个 alert_id 或 incident_id 的证据与处置建议",
    )
    parser.add_argument("id", help="告警 ID（如 awa1）或案件 ID（如 inc-001）")
    parser.add_argument("--report", default="report.json",
                        help="由 --json 或 --out 生成的 JSON 报告，默认 report.json")
    parser.add_argument("--format", choices=("text", "markdown"), default="text",
                        help="输出格式：text（默认）或 markdown（适合直接粘贴进工单/复盘文档）")
    args = parser.parse_args(argv)

    try:
        with open(args.report, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        print(f"❌ 无法读取报告 {args.report}: {e}", file=sys.stderr)
        sys.exit(2)

    target_id = args.id
    for incident in report.get("incidents", []):
        if incident.get("id") == target_id:
            if args.format == "markdown":
                print(_render_incident_markdown(incident))
            else:
                _print_incident_text(incident)
            sys.exit(0)

    for alert in report.get("alerts", []):
        if alert.get("id") == target_id or alert.get("rule_id") == target_id:
            if args.format == "markdown":
                print(_render_alert_markdown(alert))
            else:
                _print_alert_text(alert)
            sys.exit(0)

    print(f"❌ 报告中未找到 ID: {target_id}", file=sys.stderr)
    sys.exit(1)


def _print_incident_text(incident: dict) -> None:
    print(f"[案件] {incident.get('title')}")
    print(f"级别: {incident.get('level')}  置信度: {incident.get('confidence')}")
    print(incident.get("description", ""))
    print("\n关键证据:")
    for item in incident.get("evidence", []):
        print(f"  - {item}")
    print("\n建议补采:")
    for item in incident.get("next_logs", []):
        print(f"  - {item}")
    print("\n处置动作:")
    for item in incident.get("recommended_actions", []):
        print(f"  - {item}")


def _print_alert_text(alert: dict) -> None:
    print(f"[告警] {alert.get('rule_name')}")
    print(f"规则: {alert.get('rule_id')}  级别: {alert.get('level')}  置信度: {alert.get('confidence')}")
    print(alert.get("description", ""))
    print("\n证据:")
    for item in alert.get("evidence", []):
        print(f"  - {item}")
    print(f"\n建议: {alert.get('recommendation', '')}")


def _render_incident_markdown(incident: dict) -> str:
    """渲染 incident 为可直接粘贴进工单 / 复盘文档的 Markdown。"""
    phases = incident.get("attack_phases", [])
    source_types = incident.get("source_types", [])
    source_ips = incident.get("source_ips", [])
    accounts = incident.get("accounts", [])
    assets = incident.get("assets", [])
    timeline = incident.get("timeline", [])

    lines = [
        f"## 案件 {incident.get('id', '?')}：{incident.get('title', '')}",
        "",
        f"- **级别**：{incident.get('level', '?')}",
        f"- **置信度**：{incident.get('confidence', '?')}",
        f"- **影响事件**：{incident.get('affected_event_count', 0)} 条",
        f"- **关联告警**：{len(incident.get('affected_alerts', []))} 个",
        f"- **日志源**：{', '.join(source_types) or '?'}",
        f"- **攻击阶段**：{' → '.join(phases) or '?'}",
        f"- **源 IP**：{', '.join(source_ips[:5]) or '?'}",
        f"- **账号**：{', '.join(accounts[:5]) or '?'}",
        f"- **资产**：{', '.join(assets[:5]) or '?'}",
        "",
        "### 描述",
        "",
        incident.get("description", ""),
        "",
        "### 关键证据",
        "",
    ]
    lines.extend(f"- {item}" for item in incident.get("evidence", []))
    if not incident.get("evidence"):
        lines.append("- （无）")
    lines.extend(["", "### 处置动作", ""])
    lines.extend(f"- [ ] {item}" for item in incident.get("recommended_actions", []))
    if not incident.get("recommended_actions"):
        lines.append("- [ ] （待补充）")
    lines.extend(["", "### 待补采日志", ""])
    lines.extend(f"- {item}" for item in incident.get("next_logs", []))
    if not incident.get("next_logs"):
        lines.append("- （无）")
    if timeline:
        lines.extend(["", "### 关键事件时间线", "", "| 时间 | 级别 | 来源 | 描述 |", "|---|---|---|---|"])
        for item in timeline[:20]:
            ts = (item.get("timestamp") or "").replace("|", "\\|")
            level = (item.get("level") or "").replace("|", "\\|")
            src = (item.get("source_file") or "").replace("|", "\\|")
            msg = (item.get("message") or "").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {ts} | {level} | {src} | {msg} |")
    return "\n".join(lines)


def _render_alert_markdown(alert: dict) -> str:
    lines = [
        f"## 告警 {alert.get('id', '?')}：{alert.get('rule_name', '')}",
        "",
        f"- **规则**：{alert.get('rule_id', '?')}",
        f"- **级别**：{alert.get('level', '?')}",
        f"- **置信度**：{alert.get('confidence', '?')}",
        f"- **MITRE**：{alert.get('mitre_attack', '?')} / {alert.get('mitre_phase', '?')}",
        f"- **影响事件**：{alert.get('affected_event_count', 0)} 条",
        f"- **时间**：{alert.get('timestamp', '?')}",
        "",
        "### 描述",
        "",
        alert.get("description", ""),
        "",
        "### 证据",
        "",
    ]
    lines.extend(f"- {item}" for item in alert.get("evidence", []))
    if not alert.get("evidence"):
        lines.append("- （无）")
    lines.extend(["", "### 处置建议", "", alert.get("recommendation", "")])
    return "\n".join(lines)


def _collect_files(paths: List[str]) -> List[str]:
    return collect_files(paths)


def _parse_files(files: List[str], jobs: int = 0, quiet: bool = False) -> List[ParseResult]:
    return parse_files(files, jobs=jobs, quiet=quiet, print_fn=print)


def _make_synthetic_p0_log(size_mb: int) -> Path:
    size_mb = max(1, size_mb)
    fd, path_text = tempfile.mkstemp(prefix="bla-benchmark-", suffix=".jsonl")
    os.close(fd)
    path = Path(path_text)
    row_templates = [
        '{{"log_type":"waf","time":"2024-03-15 10:00:{sec:02d}","src_ip":"8.8.8.{octet}","host":"www.example.com","uri":"/login?id=1 UNION SELECT NULL--","action":"block","attack_type":"SQL Injection","status":"403"}}\n',
        '{{"log_type":"vpn","time":"2024-03-15 10:01:{sec:02d}","user":"alice","src_ip":"8.8.8.{octet}","result":"failed","reason":"bad password"}}\n',
        '{{"log_type":"dns","time":"2024-03-15 10:02:{sec:02d}","client_ip":"10.0.0.{octet}","query":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example","rcode":"NOERROR"}}\n',
        '{{"log_type":"proxy","time":"2024-03-15 10:03:{sec:02d}","src_ip":"10.0.0.{octet}","url":"http://evil.example/a.sh","bytes_out":"2048","action":"allow"}}\n',
        '{{"log_type":"edr","time":"2024-03-15 10:04:{sec:02d}","host":"win-{octet}","severity":"high","alert":"webshell beacon","process":"java.exe"}}\n',
    ]
    target = size_mb * 1024 * 1024
    written = 0
    i = 0
    with open(path, "w", encoding="utf-8") as f:
        while written < target:
            line = row_templates[i % len(row_templates)].format(sec=i % 60, octet=(i % 200) + 1)
            f.write(line)
            written += len(line.encode("utf-8"))
            i += 1
    return path


def main():
    if _dispatch_subcommand(sys.argv):
        return

    parser = argparse.ArgumentParser(
        prog="bla",
        description="BlueTeam Log Analyzer - 蓝队应急响应日志分析工具",
        epilog="示例: bla /var/log/auth.log --html report.html",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "paths",
        nargs="*",
        help="日志文件或目录路径（支持通配符）",
    )
    parser.add_argument(
        "--list-log-sources",
        action="store_true",
        help="打印应急日志源采集优先级清单后退出",
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
        "--full", "--no-truncate", "--evidence",
        dest="full_evidence",
        action="store_true",
        help="终端输出完整证据字段，包括完整 URL/Payload/User-Agent/Referer/原始日志行",
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
        version=f"BLA {__version__}",
    )

    args = parser.parse_args()

    if args.list_log_sources:
        print(format_log_source_priorities())
        sys.exit(0)

    if not args.paths:
        parser.error("缺少日志文件或目录路径；查看采集优先级可使用 --list-log-sources")

    if args.max_alerts < 0:
        print("❌ 错误：--max-alerts 不能小于 0", file=sys.stderr)
        sys.exit(1)

    if args.syslog_year is not None:
        if args.syslog_year < 1970 or args.syslog_year > 2100:
            print("❌ 错误：--syslog-year 必须在 1970 到 2100 之间", file=sys.stderr)
            sys.exit(1)

    # 收集所有文件
    files = _collect_files(args.paths)

    if not files:
        print("❌ 错误：未找到任何日志文件", file=sys.stderr)
        sys.exit(1)

    print(f"\n🔍 开始分析 {len(files)} 个文件...\n")

    try:
        run_result = run_analysis(
            AnalysisOptions(
                paths=files,
                profile=args.profile,
                jobs=args.jobs,
                config_path=args.config,
                rule_dirs=args.rules or [],
                allowlist_path=args.allowlist,
                syslog_year=args.syslog_year,
            ),
            quiet=False,
            print_fn=print,
        )
    except AnalysisError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 分析流程失败: {e}", file=sys.stderr)
        sys.exit(1)

    parse_results = run_result.parse_results
    summary = run_result.summary
    if run_result.suppressed_events:
        print(f"\n✓ 白名单过滤完成，压制 {run_result.suppressed_events} 条事件")

    print(f"\n✓ 解析完成，共 {summary.total_events} 条事件\n")

    print(f"✓ 检测完成，发现 {len(summary.alerts)} 个告警\n")

    # 输出报告
    print_terminal_report(
        parse_results,
        summary,
        args.verbose,
        args.no_color,
        args.max_alerts,
        args.full_evidence,
    )

    write_reports(
        parse_results,
        summary,
        AnalysisOutputs(
            html=args.html,
            json=args.json,
            csv=args.csv,
            ioc=args.ioc,
            sarif=args.sarif,
            bundle_dir=args.out,
        ),
    )

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
