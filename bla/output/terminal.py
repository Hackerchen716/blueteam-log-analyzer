"""
终端彩色输出模块
支持 macOS / Linux / Windows 10+ 终端 ANSI 颜色
"""
from __future__ import annotations
import sys
from typing import List

from ..models import (
    ParseResult, AnalysisSummary, DetectionAlert, ThreatLevel, LogEvent
)
from ..utils.helpers import safe_stream

# ANSI 颜色
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"

BG_RED    = "\033[41m"
BG_ORANGE = "\033[48;5;208m"
BG_YELLOW = "\033[43m"
BG_GREEN  = "\033[42m"
BG_BLUE   = "\033[44m"


def _level_color(level: ThreatLevel) -> str:
    return {
        "critical": RED,
        "high":     ORANGE,
        "medium":   YELLOW,
        "low":      GREEN,
        "info":     BLUE,
    }.get(level.value, RESET)


def _level_badge(level: ThreatLevel) -> str:
    c = _level_color(level)
    labels = {"critical":"[严重]","high":"[高危]","medium":"[中危]","low":"[低危]","info":"[信息]"}
    return f"{BOLD}{c}{labels.get(level.value,'[?]')}{RESET}"


def _hr(char: str = "─", width: int = 80) -> str:
    return GRAY + char * width + RESET


def _section(title: str, color: str = "") -> str:
    line = "═" * 80
    color = color or CYAN
    return f"\n{BOLD}{color}{line}\n  {title}\n{line}{RESET}\n"


def _fmt_top(items: list, key: str, limit: int = 3) -> str:
    if not items:
        return "-"
    return ", ".join(f"{item.get(key, '?')}({item.get('count', 0)})" for item in items[:limit])


def _truncate_text(text: str, max_len: int) -> str:
    if max_len <= 0:
        return ""
    text = text or ""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _evidence_text(text: str, full: bool, max_len: int = 220) -> str:
    """Terminal keeps summaries compact unless full evidence output is requested."""
    return text if full else _truncate_text(text, max_len)


def _basename(path: str) -> str:
    s = (path or "").replace("/", "\\")
    if "\\" in s:
        return s.rsplit("\\", 1)[-1]
    return s


def print_terminal_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    verbose: bool = False,
    no_color: bool = False,
    max_alerts: int = 50,
    full_evidence: bool = False,
) -> None:
    """打印完整的终端分析报告"""
    if no_color:
        _disable_color()

    out = safe_stream(sys.stdout)

    event_by_id = {}
    for result in parse_results:
        event_by_id.update({event.id: event for event in result.events})

    # ── 标题横幅 ──────────────────────────────────────────
    out.write(f"\n{BOLD}{BLUE}")
    out.write("╔══════════════════════════════════════════════════════════════════════════════╗\n")
    out.write("║         BlueTeam Log Analyzer (BLA)  -  Blue Team Incident Response          ║\n")
    out.write("║                    Version 1.0.2  |  100% Offline  |  No AI                  ║\n")
    out.write("╚══════════════════════════════════════════════════════════════════════════════╝\n")
    out.write(RESET)

    # ── 风险总览 ──────────────────────────────────────────
    out.write(_section("📊 分析总览"))
    risk_color = _level_color(summary.risk_level)
    out.write(f"  {BOLD}综合风险评分: {risk_color}{summary.risk_score}/100  {_level_badge(summary.risk_level)}{RESET}\n")
    out.write(f"  分析文件数:   {WHITE}{summary.files_analyzed}{RESET}\n")
    out.write(f"  总事件数:     {WHITE}{summary.total_events}{RESET}\n")
    out.write(f"  告警数量:     {WHITE}{len(summary.alerts)}{RESET}\n")
    out.write(f"  关联案件:     {WHITE}{len(summary.incidents)}{RESET}\n")

    # 按级别统计
    total_events = sum(r.stats.total for r in parse_results)
    crit  = sum(r.stats.critical for r in parse_results)
    high  = sum(r.stats.high for r in parse_results)
    med   = sum(r.stats.medium for r in parse_results)
    low   = sum(r.stats.low for r in parse_results)
    info  = sum(r.stats.info for r in parse_results)

    out.write(f"\n  {_hr()}\n")
    out.write(f"  事件级别分布:\n")
    out.write(f"    {RED}{BOLD}严重: {crit:>5}{RESET}  {ORANGE}{BOLD}高危: {high:>5}{RESET}  "
              f"{YELLOW}中危: {med:>5}{RESET}  {GREEN}低危: {low:>5}{RESET}  {BLUE}信息: {info:>5}{RESET}\n")

    # ── 文件解析结果 ──────────────────────────────────────
    out.write(_section("📁 文件解析结果"))
    for r in parse_results:
        size_kb = r.file_size_bytes / 1024
        out.write(f"  {BOLD}{CYAN}{r.file_name}{RESET}  {DIM}({r.log_type}){RESET}\n")
        out.write(f"    大小: {size_kb:.1f} KB  |  解析耗时: {r.parse_time_ms:.0f}ms  |  "
                  f"总事件: {r.stats.total}  |  "
                  f"{RED}严重:{r.stats.critical}{RESET}  {ORANGE}高:{r.stats.high}{RESET}  "
                  f"{YELLOW}中:{r.stats.medium}{RESET}\n")
        if r.stats.time_start:
            out.write(f"    时间范围: {DIM}{r.stats.time_start}  ~  {r.stats.time_end}{RESET}\n")
        if r.stats.top_ips:
            top_ip = r.stats.top_ips[0]
            out.write(f"    Top IP:   {WHITE}{top_ip['ip']}{RESET} ({top_ip['count']} 次)\n")
        out.write("\n")

    has_windows_logon = any(r.stats.windows_logon_stats for r in parse_results)
    has_windows_4688 = any(r.stats.windows_process_creation_stats for r in parse_results)
    if has_windows_logon or has_windows_4688:
        out.write(_section("🔎 专项分析"))
        for r in parse_results:
            if not r.stats.windows_logon_stats and not r.stats.windows_process_creation_stats:
                continue
            out.write(f"  {BOLD}{CYAN}{r.file_name}{RESET}  {DIM}({r.log_type}){RESET}\n")

            if r.stats.windows_logon_stats:
                win_stats = r.stats.windows_logon_stats
                out.write(
                    f"    {BOLD}EID 4624/4625 登录事件{RESET}  "
                    f"成功={win_stats.get('total_success', 0)}  |  失败={win_stats.get('total_failure', 0)}  |  "
                    f"账户={win_stats.get('unique_accounts', 0)}  |  源IP={win_stats.get('unique_source_ips', 0)}\n"
                )
                for event_id in ("4624", "4625"):
                    event_stats = win_stats.get("events", {}).get(event_id)
                    if not event_stats:
                        continue
                    out.write(f"      {DIM}EID {event_id}{RESET}  {BOLD}{event_stats.get('event_name', '')}{RESET}  (总计 {event_stats.get('total', 0)})\n")
                    out.write(f"        Top账户:     {_fmt_top(event_stats.get('principals', []), 'principal', 5)}\n")
                    out.write(f"        Top源IP:     {_fmt_top(event_stats.get('source_ips', []), 'source_ip', 5)}\n")
                    logon_types = event_stats.get("logon_types", [])[:5]
                    logon_type_text = ", ".join(
                        f"{item.get('logon_type', '?')}:{item.get('label', '未知')}({item.get('count', 0)})"
                        for item in logon_types
                    ) if logon_types else "-"
                    out.write(f"        登录类型:    {logon_type_text}\n")
                    out.write(f"        账号域:      {_fmt_top(event_stats.get('account_domains', []), 'account_domain', 5)}\n")
                    out.write(f"        工作站:      {_fmt_top(event_stats.get('workstations', []), 'workstation', 5)}\n")
                    if event_id == "4625":
                        if event_stats.get("failure_reasons"):
                            out.write(f"        失败原因:    {_fmt_top(event_stats.get('failure_reasons', []), 'failure_reason', 5)}\n")
                        if event_stats.get("status_codes"):
                            out.write(f"        Status:      {_fmt_top(event_stats.get('status_codes', []), 'status_code', 5)}\n")
                        if event_stats.get("sub_status_codes"):
                            out.write(f"        SubStatus:   {_fmt_top(event_stats.get('sub_status_codes', []), 'sub_status_code', 5)}\n")
                    out.write("\n")

            if r.stats.windows_process_creation_stats:
                pstats = r.stats.windows_process_creation_stats
                out.write(
                    f"    {BOLD}EID 4688 进程创建{RESET}  "
                    f"总数={pstats.get('total', 0)}  |  唯一父子对={pstats.get('unique_pairs', 0)}\n"
                )
                header = (
                    f"      {DIM}{'#':<3} {'父进程':<18} {'子进程':<16} {'次数':>4} {'最近时间':<20} {'路径':<1}{RESET}\n"
                )
                out.write(header)
                out.write(f"      {DIM}{'-'*76}{RESET}\n")
                for idx, item in enumerate(pstats.get('top', [])[:10], 1):
                    parent_path = item.get("parent_process") or ""
                    child_name = item.get("child_process") or ""
                    count = item.get("count", 0)
                    ts = item.get("time") or "-"
                    path = item.get("path") or "-"
                    parent_name = _basename(parent_path) or "(unknown)"
                    parent_col = _truncate_text(parent_name, 18)
                    child_col = _truncate_text(child_name or "(unknown)", 16)
                    ts_col = _truncate_text(ts, 20)
                    path_col = _truncate_text(path, 24)
                    out.write(f"      {idx:>2}. {parent_col:<18} {child_col:<16} {count:>4} {ts_col:<20} {path_col}\n")
                out.write("\n")

            out.write("\n")

    # ── ATT&CK 攻击链 ─────────────────────────────────────
    if summary.attack_chain:
        out.write(_section("⛓  ATT&CK 攻击链分析"))
        chain_labels = ["侦察","初始访问","执行","持久化","权限提升","防御规避","凭据访问","横向移动","命令控制"]
        active_phases = {c.phase: c for c in summary.attack_chain}

        for i, phase in enumerate(chain_labels):
            if phase in active_phases:
                c = active_phases[phase]
                color = _level_color(c.level)
                techs = ", ".join(c.techniques[:3])
                out.write(f"  {BOLD}{color}▶ {phase}{RESET}  ({c.event_count} 个事件)  {DIM}{techs}{RESET}\n")
                if i < len(chain_labels) - 1 and chain_labels[i+1] in active_phases:
                    out.write(f"    {GRAY}│{RESET}\n")
            else:
                out.write(f"  {DIM}○ {phase}{RESET}\n")

    # ── 应急案件视图 ──────────────────────────────────────
    if summary.incidents:
        out.write(_section("🧩 应急案件视图"))
        for i, incident in enumerate(summary.incidents[:10], 1):
            color = _level_color(incident.level)
            out.write(f"\n  {BOLD}[INC-{i:02d}] {_level_badge(incident.level)} {color}{incident.title}{RESET}\n")
            out.write(f"       {incident.description}\n")
            out.write(f"       {DIM}置信度: {incident.confidence}  |  日志源: {', '.join(incident.source_types[:6]) or '?'}  |  事件: {len(incident.affected_events)}{RESET}\n")
            if incident.evidence:
                out.write(f"       {GRAY}关键证据:{RESET}\n")
                for item in incident.evidence[:4]:
                    out.write(f"         • {item}\n")
            if incident.next_logs:
                out.write(f"       {CYAN}建议补采: {', '.join(incident.next_logs[:5])}{RESET}\n")
            if incident.recommended_actions:
                out.write(f"       {YELLOW}处置动作: {incident.recommended_actions[0]}{RESET}\n")
            out.write(f"  {_hr('─', 76)}\n")

    # ── 告警详情 ──────────────────────────────────────────
    out.write(_section("🚨 威胁告警"))
    if not summary.alerts:
        out.write(f"  {GREEN}未发现明显威胁告警{RESET}\n")
    else:
        shown_alerts = summary.alerts if max_alerts <= 0 else summary.alerts[:max_alerts]
        if max_alerts > 0 and len(summary.alerts) > max_alerts:
            out.write(f"  {DIM}终端仅展示前 {max_alerts} 个告警；完整结果请查看 --html / --json 报告，或使用 --max-alerts 0。{RESET}\n")
        for i, alert in enumerate(shown_alerts, 1):
            color = _level_color(alert.level)
            badge = _level_badge(alert.level)
            out.write(f"\n  {BOLD}[{i:02d}] {badge} {color}{alert.rule_name}{RESET}\n")
            out.write(f"       {alert.description}\n")
            out.write(f"       {DIM}MITRE: {alert.mitre_attack}  |  阶段: {alert.mitre_phase}  |  "
                      f"置信度: {alert.confidence}  |  时间: {alert.timestamp}{RESET}\n")
            out.write(f"       {GRAY}证据:{RESET}\n")
            evidence_items = alert.evidence if full_evidence else alert.evidence[:3]
            for ev in evidence_items:
                out.write(f"         • {_evidence_text(ev, full_evidence)}\n")
            if not full_evidence and len(alert.evidence) > 3:
                out.write(f"         {DIM}… 还有 {len(alert.evidence) - 3} 条证据；使用 --full / --no-truncate 查看完整证据。{RESET}\n")
            if full_evidence and alert.level.score >= ThreatLevel.HIGH.score:
                out.write(f"       {GRAY}完整事件证据:{RESET}\n")
                for event_id in alert.affected_events[:5]:
                    event = event_by_id.get(event_id)
                    if not event:
                        continue
                    method = event.details.get("method", "")
                    path = event.details.get("decoded_path") or event.details.get("path", "")
                    status = event.details.get("status", "")
                    ua = event.details.get("user_agent", "")
                    referer = event.details.get("referer", "")
                    if method or path or status:
                        out.write(f"         - 请求: {method} {path} -> {status}\n")
                    if ua:
                        out.write(f"           User-Agent: {ua}\n")
                    if referer:
                        out.write(f"           Referer: {referer}\n")
                    if event.raw_line:
                        out.write(f"           原始日志: {event.raw_line}\n")
            out.write(f"       {YELLOW}建议: {alert.recommendation}{RESET}\n")
            out.write(f"  {_hr('─', 76)}\n")

    # ── 时间线（按风险/时间排序的 Top 20 事件）─────────────
    # _build_timeline 已按 (-level.score, -timestamp) 排序，所以取前 20
    # 实际是"风险最高/最新的 20 条"，标题随排序语义同步。
    if summary.timeline:
        out.write(_section("📅 关键事件时间线 Top 20（按风险/时间）"))
        for entry in summary.timeline[:20]:
            color = _level_color(entry.level)
            badge = _level_badge(entry.level)
            mitre = f" {DIM}[{entry.mitre_attack}]{RESET}" if entry.mitre_attack else ""
            message = _evidence_text(entry.message, full_evidence, 180)
            out.write(f"  {DIM}{entry.timestamp}{RESET}  {badge}  {color}{message}{RESET}{mitre}\n")

    # ── 应急处置建议 ──────────────────────────────────────
    out.write(_section("💡 应急处置建议"))
    for i, rec in enumerate(summary.recommendations, 1):
        out.write(f"  {BOLD}{i}.{RESET} {rec}\n")

    # ── Top IP ────────────────────────────────────────────
    all_ips: dict = {}
    for r in parse_results:
        for ip_info in r.stats.top_ips:
            ip = ip_info["ip"]
            all_ips[ip] = all_ips.get(ip, 0) + ip_info["count"]
    if all_ips:
        out.write(_section("🌐 Top 攻击源 IP"))
        sorted_ips = sorted(all_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in sorted_ips:
            bar = "█" * min(count // 5, 30)
            out.write(f"  {WHITE}{ip:<20}{RESET}  {RED}{bar}{RESET} {count}\n")

    # ── 详细事件（verbose 模式）──────────────────────────
    if verbose:
        out.write(_section("📋 详细事件列表（高危以上）"))
        all_events: List[LogEvent] = []
        for r in parse_results:
            all_events.extend(e for e in r.events if e.level.score >= ThreatLevel.HIGH.score)
        all_events.sort(key=lambda e: e.timestamp)
        for ev in all_events[:100]:
            color = _level_color(ev.level)
            out.write(f"  {DIM}{ev.timestamp}{RESET}  {_level_badge(ev.level)}  "
                      f"{color}{ev.message}{RESET}\n")
            if ev.details:
                for k, v in list(ev.details.items())[:3]:
                    out.write(f"    {DIM}{k}: {v}{RESET}\n")

    out.write(f"\n{BOLD}{BLUE}{'═'*80}{RESET}\n")
    out.write(f"{BOLD}  分析完成。如需详细报告请使用 --html / --json / --csv 参数。{RESET}\n")
    out.write(f"{BOLD}{BLUE}{'═'*80}{RESET}\n\n")
    out.flush()


def _disable_color():
    """禁用颜色（重定向输出时使用）"""
    global RESET, BOLD, DIM, RED, ORANGE, YELLOW, GREEN, BLUE, CYAN, WHITE, GRAY
    global BG_RED, BG_ORANGE, BG_YELLOW, BG_GREEN, BG_BLUE
    RESET = BOLD = DIM = RED = ORANGE = YELLOW = GREEN = BLUE = CYAN = WHITE = GRAY = ""
    BG_RED = BG_ORANGE = BG_YELLOW = BG_GREEN = BG_BLUE = ""
