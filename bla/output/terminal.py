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


def _section(title: str, color: str = CYAN) -> str:
    line = "═" * 80
    return f"\n{BOLD}{color}{line}\n  {title}\n{line}{RESET}\n"


def print_terminal_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    verbose: bool = False,
    no_color: bool = False,
) -> None:
    """打印完整的终端分析报告"""
    if no_color:
        _disable_color()

    out = sys.stdout

    # ── 标题横幅 ──────────────────────────────────────────
    out.write(f"\n{BOLD}{BLUE}")
    out.write("╔══════════════════════════════════════════════════════════════════════════════╗\n")
    out.write("║         BlueTeam Log Analyzer (BLA)  -  Blue Team Incident Response          ║\n")
    out.write("║                    Version 1.0.0  |  100% Offline  |  No AI                  ║\n")
    out.write("╚══════════════════════════════════════════════════════════════════════════════╝\n")
    out.write(RESET)

    # ── 风险总览 ──────────────────────────────────────────
    out.write(_section("📊 分析总览"))
    risk_color = _level_color(summary.risk_level)
    out.write(f"  {BOLD}综合风险评分: {risk_color}{summary.risk_score}/100  {_level_badge(summary.risk_level)}{RESET}\n")
    out.write(f"  分析文件数:   {WHITE}{summary.files_analyzed}{RESET}\n")
    out.write(f"  总事件数:     {WHITE}{summary.total_events}{RESET}\n")
    out.write(f"  告警数量:     {WHITE}{len(summary.alerts)}{RESET}\n")

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

    # ── 告警详情 ──────────────────────────────────────────
    out.write(_section("🚨 威胁告警"))
    if not summary.alerts:
        out.write(f"  {GREEN}未发现明显威胁告警{RESET}\n")
    else:
        for i, alert in enumerate(summary.alerts, 1):
            color = _level_color(alert.level)
            badge = _level_badge(alert.level)
            out.write(f"\n  {BOLD}[{i:02d}] {badge} {color}{alert.rule_name}{RESET}\n")
            out.write(f"       {alert.description}\n")
            out.write(f"       {DIM}MITRE: {alert.mitre_attack}  |  阶段: {alert.mitre_phase}  |  "
                      f"置信度: {alert.confidence}  |  时间: {alert.timestamp}{RESET}\n")
            out.write(f"       {GRAY}证据:{RESET}\n")
            for ev in alert.evidence[:3]:
                out.write(f"         • {ev}\n")
            out.write(f"       {YELLOW}建议: {alert.recommendation}{RESET}\n")
            out.write(f"  {_hr('─', 76)}\n")

    # ── 时间线（最近20条重要事件）────────────────────────
    if summary.timeline:
        out.write(_section("📅 关键事件时间线（最近20条）"))
        for entry in summary.timeline[-20:]:
            color = _level_color(entry.level)
            badge = _level_badge(entry.level)
            mitre = f" {DIM}[{entry.mitre_attack}]{RESET}" if entry.mitre_attack else ""
            out.write(f"  {DIM}{entry.timestamp}{RESET}  {badge}  {color}{entry.message}{RESET}{mitre}\n")

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
    RESET = BOLD = DIM = RED = ORANGE = YELLOW = GREEN = BLUE = CYAN = WHITE = GRAY = ""
