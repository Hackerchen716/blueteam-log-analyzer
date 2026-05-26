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
import hashlib
from pathlib import Path
from typing import List, Optional

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

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
from bla.parsers import list_parser_names
from bla.utils.helpers import escape_markdown_text, reset_counter, safe_print as print, strip_terminal_control
from bla.models import ParseResult, ThreatLevel


_EXIT_THRESHOLDS = {
    "none":     None,
    "critical": ThreatLevel.CRITICAL.score,
    "high":     ThreatLevel.HIGH.score,
    "medium":   ThreatLevel.MEDIUM.score,
}


def _exit_code_for_alerts(alerts, exit_on: str) -> int:
    threshold = _EXIT_THRESHOLDS.get(exit_on)
    if threshold is None:
        return 0
    return 1 if any(a.level.score >= threshold for a in alerts) else 0


def _build_manifest_context(args: argparse.Namespace, run_result) -> dict:
    return {
        "inputs": [_input_manifest_record(path) for path in run_result.files],
        "options": {
            "profile": args.profile,
            "parser": args.type,
            "jobs": args.jobs,
            "config": args.config,
            "rules": args.rules or [],
            "allowlist": args.allowlist,
            "geoip_cache": os.path.basename(args.geoip_cache) if args.geoip_cache else None,
            "exit_on": args.exit_on,
            "syslog_year": args.syslog_year,
            "rdp_only": args.rdp,
            "max_alerts": args.max_alerts,
            "full_evidence": bool(args.full_evidence),
        },
        "parse_errors": run_result.parse_errors,
        "suppressed_events": run_result.suppressed_events,
    }


def _input_manifest_record(path: str) -> dict:
    record = {
        "source": "local",
        "path": os.path.basename(path),
        "name": os.path.basename(path),
        "size_bytes": 0,
        "sha256": "",
    }
    try:
        record["size_bytes"] = os.path.getsize(path)
        record["sha256"] = _sha256_file(path)
    except OSError:
        pass
    return record


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dispatch_subcommand(argv: List[str]) -> bool:
    if len(argv) < 2 or argv[1] not in {"validate-rules", "benchmark", "explain", "ssh", "remote-log"}:
        return False
    command = argv[1]
    if command == "validate-rules":
        _cmd_validate_rules(argv[2:])
    elif command == "benchmark":
        _cmd_benchmark(argv[2:])
    elif command == "explain":
        _cmd_explain(argv[2:])
    elif command == "ssh":
        _cmd_ssh(argv[2:])
    elif command == "remote-log":
        _cmd_remote_log(argv[2:])
    return True


def _cmd_ssh(argv: List[str]) -> None:
    from bla.remote import RemoteWorkspace, SSHClient

    parser = argparse.ArgumentParser(
        prog="bla ssh",
        description="通过 SSH 打开远程日志工作台；目标机不需要安装 Python、pip 或 BLA",
    )
    parser.add_argument("target", help="SSH 目标，例如 root@192.168.1.20 或 ~/.ssh/config 中的主机别名")
    parser.add_argument("-p", "--port", type=int, help="SSH 端口")
    parser.add_argument("-i", "--identity-file", help="SSH 私钥路径")
    parser.add_argument("--workdir", default=".", help="进入远程工作台后的初始目录，默认远程登录目录")
    parser.add_argument("--connect-timeout", type=int, default=10, help="SSH 连接超时秒数，默认 10")
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024,
                        help="单个远程输入最大拉取字节数，默认 268435456")
    parser.add_argument("--command-timeout", type=int, default=120,
                        help="远程只读命令超时秒数，默认 120")
    args = parser.parse_args(argv)

    if args.max_bytes <= 0:
        parser.error("--max-bytes 必须大于 0")
    if args.command_timeout <= 0:
        parser.error("--command-timeout 必须大于 0")
    try:
        client = SSHClient(
            target=args.target,
            port=args.port,
            identity_file=args.identity_file,
            connect_timeout=args.connect_timeout,
        )
    except ValueError as e:
        parser.error(str(e))
    workspace = RemoteWorkspace(
        client,
        initial_cwd=args.workdir,
        print_fn=print,
        max_fetch_bytes=args.max_bytes,
        command_timeout=args.command_timeout,
    )
    try:
        workspace.start()
    except RuntimeError as e:
        print(f"❌ 远程工作台启动失败: {e}", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


def _cmd_remote_log(argv: List[str]) -> None:
    from bla.remote import RemoteWorkspace, SSHClient

    parser = argparse.ArgumentParser(
        prog="bla remote-log",
        description="通过 SSH 只读采集远程日志子集，并在本机复用 BLA 分析流程",
    )
    parser.add_argument("target", help="SSH 目标，例如 root@192.168.1.20 或 ~/.ssh/config 主机别名")
    parser.add_argument("paths", nargs="+", help="远程日志路径，或 journalctl:UNIT")
    parser.add_argument("-p", "--port", type=int, help="SSH 端口")
    parser.add_argument("-i", "--identity-file", help="SSH 私钥路径")
    parser.add_argument("--workdir", default=".", help="远程初始目录，默认远程登录目录")
    parser.add_argument("--connect-timeout", type=int, default=10, help="SSH 连接超时秒数，默认 10")
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024,
                        help="单个远程输入最大采集字节数，默认 268435456")
    parser.add_argument("--command-timeout", type=int, default=120,
                        help="远程只读命令超时秒数，默认 120")
    parser.add_argument("--tail", type=int, help="仅采集远程文件最后 N 行")
    parser.add_argument("--grep", action="append", metavar="TEXT", help="仅保留包含关键词的行，可重复指定")
    parser.add_argument("--analyze", action="store_true", help="兼容显式分析语义；remote-log 默认进入本地分析流程")
    parser.add_argument("--audit-json", metavar="FILE", help="写出远程采集审计记录 JSON")
    parser.add_argument("--out", metavar="DIR", help="本地标准报告目录（含 manifest.json）")
    parser.add_argument("--geoip-cache", metavar="FILE",
                        help="加载本地 GeoIP JSON 缓存，仅用于 HTML 攻击源地理分布；不会联网查询")
    parser.add_argument("--html", metavar="FILE", help="本地 HTML 报告")
    parser.add_argument("--json", metavar="FILE", help="本地 JSON 报告")
    parser.add_argument("--csv", metavar="FILE", help="本地 CSV 事件列表")
    parser.add_argument("--ioc", metavar="FILE", help="本地 IOC 清单")
    parser.add_argument("--sarif", metavar="FILE", help="本地 SARIF 报告")
    parser.add_argument("--profile", choices=("default", "cn-hvv"), default="default")
    parser.add_argument("--type", choices=["auto"] + list_parser_names(), default="auto")
    parser.add_argument("--exit-on", choices=("none", "critical", "high", "medium"), default="critical")
    parser.add_argument("--rules", action="append", metavar="DIR")
    parser.add_argument("--allowlist", metavar="FILE")
    parser.add_argument("--config", metavar="FILE")
    parser.add_argument("--max-alerts", type=int, default=50)
    parser.add_argument("--full", "--no-truncate", "--evidence", dest="full_evidence", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--syslog-year", type=int)
    parser.add_argument("--rdp", action="store_true", help="仅保留带远程来源 IP 的 Windows 4624/4625 登录事件")
    args = parser.parse_args(argv)

    if args.max_bytes <= 0:
        parser.error("--max-bytes 必须大于 0")
    if args.command_timeout <= 0:
        parser.error("--command-timeout 必须大于 0")
    if args.connect_timeout <= 0:
        parser.error("--connect-timeout 必须大于 0")

    try:
        client = SSHClient(
            target=args.target,
            port=args.port,
            identity_file=args.identity_file,
            connect_timeout=args.connect_timeout,
        )
    except ValueError as e:
        parser.error(str(e))

    workspace = RemoteWorkspace(
        client,
        initial_cwd=args.workdir,
        print_fn=print,
        max_fetch_bytes=args.max_bytes,
        command_timeout=args.command_timeout,
    )
    try:
        workspace.resolve_cwd()
    except RuntimeError as e:
        print(f"❌ 远程采集启动失败: {e}", file=sys.stderr)
        sys.exit(2)

    remote_args = list(args.paths)
    _append_optional_arg(remote_args, "--tail", args.tail)
    for pattern in args.grep or []:
        remote_args.extend(["--grep", pattern])
    _append_optional_arg(remote_args, "--audit-json", args.audit_json)
    _append_optional_arg(remote_args, "--out", args.out)
    _append_optional_arg(remote_args, "--geoip-cache", args.geoip_cache)
    _append_optional_arg(remote_args, "--html", args.html)
    _append_optional_arg(remote_args, "--json", args.json)
    _append_optional_arg(remote_args, "--csv", args.csv)
    _append_optional_arg(remote_args, "--ioc", args.ioc)
    _append_optional_arg(remote_args, "--sarif", args.sarif)
    remote_args.extend(["--profile", args.profile, "--type", args.type, "--exit-on", args.exit_on])
    for rule_dir in args.rules or []:
        remote_args.extend(["--rules", rule_dir])
    _append_optional_arg(remote_args, "--allowlist", args.allowlist)
    _append_optional_arg(remote_args, "--config", args.config)
    remote_args.extend(["--max-alerts", str(args.max_alerts)])
    if args.full_evidence:
        remote_args.append("--full")
    if args.no_color:
        remote_args.append("--no-color")
    _append_optional_arg(remote_args, "--syslog-year", args.syslog_year)
    if args.rdp:
        remote_args.append("--rdp")

    sys.exit(workspace.run_bla(remote_args))


def _append_optional_arg(target: List[str], flag: str, value) -> None:
    if value is not None:
        target.extend([flag, str(value)])


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
    parser.add_argument("--memory", action="store_true", help="启用 tracemalloc 统计峰值内存；会让耗时基准偏慢")
    args = parser.parse_args(argv)

    files = _collect_files(args.paths)
    temp_path = None
    if not files:
        temp_path = _make_synthetic_p0_log(args.size_mb)
        files = [str(temp_path)]

    reset_counter()
    if args.memory:
        tracemalloc.start()
    started = time.perf_counter()
    parse_started = time.perf_counter()
    parse_results = _parse_files(files, args.jobs, quiet=True)
    parse_elapsed = time.perf_counter() - parse_started
    all_events = [event for result in parse_results for event in result.events]
    detect_started = time.perf_counter()
    summary = run_detection(all_events, profile=args.profile)
    detect_elapsed = time.perf_counter() - detect_started
    elapsed = time.perf_counter() - started
    peak = None
    if args.memory:
        _current, peak = tracemalloc.get_traced_memory()
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
    print(f"  parse:       {parse_elapsed:.3f}s")
    print(f"  enrich+detect: {detect_elapsed:.3f}s")
    print(f"  throughput:  {mb / elapsed if elapsed > 0 else 0:.2f} MB/s")
    print(f"  event rate:  {eps:.0f} events/s")
    if peak is not None:
        print(f"  peak memory: {peak / (1024 * 1024):.2f} MB")
    else:
        print("  peak memory: not measured (use --memory)")
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
    print(f"[案件] {_plain(incident.get('title'))}")
    print(f"级别: {_plain(incident.get('level'))}  置信度: {_plain(incident.get('confidence'))}")
    print(_plain(incident.get("description", "")))
    print("\n关键证据:")
    for item in incident.get("evidence", []):
        print(f"  - {_plain(item)}")
    print("\n建议补采:")
    for item in incident.get("next_logs", []):
        print(f"  - {_plain(item)}")
    print("\n处置动作:")
    for item in incident.get("recommended_actions", []):
        print(f"  - {_plain(item)}")


def _print_alert_text(alert: dict) -> None:
    print(f"[告警] {_plain(alert.get('rule_name'))}")
    print(f"规则: {_plain(alert.get('rule_id'))}  级别: {_plain(alert.get('level'))}  置信度: {_plain(alert.get('confidence'))}")
    print(_plain(alert.get("description", "")))
    print("\n证据:")
    for item in alert.get("evidence", []):
        print(f"  - {_plain(item)}")
    print(f"\n建议: {_plain(alert.get('recommendation', ''))}")


def _render_incident_markdown(incident: dict) -> str:
    """渲染 incident 为可直接粘贴进工单 / 复盘文档的 Markdown。"""
    phases = [_md(item) for item in incident.get("attack_phases", [])]
    source_types = [_md(item) for item in incident.get("source_types", [])]
    source_ips = [_md(item) for item in incident.get("source_ips", [])]
    accounts = [_md(item) for item in incident.get("accounts", [])]
    assets = [_md(item) for item in incident.get("assets", [])]
    timeline = incident.get("timeline", [])

    lines = [
        f"## 案件 {_md(incident.get('id', '?'))}：{_md(incident.get('title', ''))}",
        "",
        f"- **级别**：{_md(incident.get('level', '?'))}",
        f"- **置信度**：{_md(incident.get('confidence', '?'))}",
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
        _md(incident.get("description", "")),
        "",
        "### 关键证据",
        "",
    ]
    lines.extend(f"- {_md(item)}" for item in incident.get("evidence", []))
    if not incident.get("evidence"):
        lines.append("- （无）")
    lines.extend(["", "### 处置动作", ""])
    lines.extend(f"- [ ] {_md(item)}" for item in incident.get("recommended_actions", []))
    if not incident.get("recommended_actions"):
        lines.append("- [ ] （待补充）")
    lines.extend(["", "### 待补采日志", ""])
    lines.extend(f"- {_md(item)}" for item in incident.get("next_logs", []))
    if not incident.get("next_logs"):
        lines.append("- （无）")
    if timeline:
        lines.extend(["", "### 关键事件时间线", "", "| 时间 | 级别 | 来源 | 描述 |", "|---|---|---|---|"])
        for item in timeline[:20]:
            ts = _md(item.get("timestamp"))
            level = _md(item.get("level"))
            src = _md(item.get("source_file"))
            msg = _md(item.get("message"))
            lines.append(f"| {ts} | {level} | {src} | {msg} |")
    return "\n".join(lines)


def _render_alert_markdown(alert: dict) -> str:
    lines = [
        f"## 告警 {_md(alert.get('id', '?'))}：{_md(alert.get('rule_name', ''))}",
        "",
        f"- **规则**：{_md(alert.get('rule_id', '?'))}",
        f"- **级别**：{_md(alert.get('level', '?'))}",
        f"- **置信度**：{_md(alert.get('confidence', '?'))}",
        f"- **MITRE**：{_md(alert.get('mitre_attack', '?'))} / {_md(alert.get('mitre_phase', '?'))}",
        f"- **影响事件**：{alert.get('affected_event_count', 0)} 条",
        f"- **时间**：{_md(alert.get('timestamp', '?'))}",
        "",
        "### 描述",
        "",
        _md(alert.get("description", "")),
        "",
        "### 证据",
        "",
    ]
    lines.extend(f"- {_md(item)}" for item in alert.get("evidence", []))
    if not alert.get("evidence"):
        lines.append("- （无）")
    lines.extend(["", "### 处置建议", "", _md(alert.get("recommendation", ""))])
    return "\n".join(lines)


def _plain(value: object) -> str:
    return strip_terminal_control(value)


def _md(value: object) -> str:
    return escape_markdown_text(value).replace("\r", " ").replace("\n", " ")


def _collect_files(paths: List[str]) -> List[str]:
    return collect_files(paths)


def _parse_files(
    files: List[str],
    jobs: int = 0,
    quiet: bool = False,
    parser_name: Optional[str] = None,
) -> List[ParseResult]:
    return parse_files(files, jobs=jobs, parser_name=parser_name, quiet=quiet, print_fn=print)


def _make_synthetic_p0_log(size_mb: int) -> Path:
    size_mb = max(1, size_mb)
    fd, path_text = tempfile.mkstemp(prefix="bla-benchmark-", suffix=".jsonl")
    os.close(fd)
    path = Path(path_text)
    row_templates = [
        '{{"log_type":"waf","time":"2024-03-15 10:00:{sec:02d}","src_ip":"203.0.113.{octet}","host":"app.example.test","uri":"/login?id=1 UNION SELECT NULL--","action":"block","attack_type":"SQL Injection","status":"403"}}\n',
        '{{"log_type":"vpn","time":"2024-03-15 10:01:{sec:02d}","user":"alice","src_ip":"198.51.100.{octet}","result":"failed","reason":"bad password"}}\n',
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
        help="生成标准报告目录（index.html/report.json/events.csv/iocs.txt/report.sarif/manifest.json）",
    )
    parser.add_argument(
        "--geoip-cache",
        metavar="FILE",
        help="加载本地 GeoIP JSON 缓存，仅用于 HTML 攻击源地理分布；不会联网查询",
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
        "--type",
        choices=["auto"] + list_parser_names(),
        default="auto",
        help="强制指定日志类型；默认 auto 自动识别",
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
        "--rdp",
        action="store_true",
        help="RDP/登录专项模式：仅保留带远程来源 IP 的 Windows 4624/4625 登录事件",
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
                parser_name=None if args.type == "auto" else args.type,
                jobs=args.jobs,
                config_path=args.config,
                rule_dirs=args.rules or [],
                allowlist_path=args.allowlist,
                syslog_year=args.syslog_year,
                rdp_only=args.rdp,
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
    if run_result.parse_errors:
        print(f"\n⚠️  有 {len(run_result.parse_errors)} 个输入解析失败，已从本次分析结果中排除:", file=sys.stderr)
        for item in run_result.parse_errors[:10]:
            print(f"  - {item}", file=sys.stderr)
        if len(run_result.parse_errors) > 10:
            print(f"  ... 还有 {len(run_result.parse_errors) - 10} 个失败输入未展示", file=sys.stderr)

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

    try:
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
                geoip_cache_path=args.geoip_cache,
            ),
            manifest_context=_build_manifest_context(args, run_result),
        )
    except OSError as e:
        print(f"\n❌ 报告写入失败: {e}", file=sys.stderr)
        sys.exit(1)

    # 退出码：可通过 --exit-on 控制触发等级
    sys.exit(_exit_code_for_alerts(summary.alerts, args.exit_on))


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
