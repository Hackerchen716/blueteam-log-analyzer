"""
HTML 报告输出
生成独立单文件 HTML 报告（内嵌 CSS/JS，无需网络）
"""
from __future__ import annotations

import datetime
from html import escape
from typing import List

from ..ioc import extract_iocs
from ..models import AnalysisSummary, ParseResult, ThreatLevel
from ..utils.helpers import format_timestamp_local, safe_print


def _level_color_hex(level: ThreatLevel) -> str:
    return {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#22c55e",
        "info":     "#3b82f6",
    }.get(level.value, "#6b7280")


def _level_bg_hex(level: ThreatLevel) -> str:
    return {
        "critical": "#450a0a",
        "high":     "#431407",
        "medium":   "#422006",
        "low":      "#052e16",
        "info":     "#172554",
    }.get(level.value, "#1f2937")


def _h(value) -> str:
    """Escape attacker-controlled log content before embedding it in HTML."""
    return escape("" if value is None else str(value), quote=True)


def _pct(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return part * 100.0 / total


def generate_html_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 准备数据
    total_events = sum(r.stats.total for r in parse_results)
    crit  = sum(r.stats.critical for r in parse_results)
    high  = sum(r.stats.high for r in parse_results)
    med   = sum(r.stats.medium for r in parse_results)
    low   = sum(r.stats.low for r in parse_results)
    info  = sum(r.stats.info for r in parse_results)

    # 所有 IP 汇总
    all_ips: dict = {}
    for r in parse_results:
        for ip_info in r.stats.top_ips:
            all_ips[ip_info["ip"]] = all_ips.get(ip_info["ip"], 0) + ip_info["count"]
    top_ips = sorted(all_ips.items(), key=lambda x: x[1], reverse=True)[:15]

    all_events = []
    for result in parse_results:
        all_events.extend(result.events)
    # 报告的 IOC 摘要走告警过滤，避免业务流量污染封禁清单
    iocs = extract_iocs(all_events, alerts=summary.alerts)
    ioc_counts = {
        "IP": len(iocs["ips"]),
        "域名": len(iocs["domains"]),
        "URL": len(iocs["urls"]),
        "路径": len(iocs["file_paths"]),
        "Hash": len(iocs["hashes"]),
        "账户": len(iocs["users"]),
        "进程": len(iocs["processes"]),
        "命令": len(iocs["commands"]),
    }
    ioc_summary_html = ""
    for label, count in ioc_counts.items():
        ioc_summary_html += f"""
        <div class="ioc-card">
          <div class="ioc-num">{count}</div>
          <div class="ioc-label">{_h(label)}</div>
        </div>"""
    top_ioc_values = []
    for key in ("ips", "domains", "urls", "file_paths", "users", "processes"):
        top_ioc_values.extend(iocs[key][:5])
    ioc_preview_html = "".join(f"<code>{_h(value)}</code>" for value in top_ioc_values[:20])
    if not ioc_preview_html:
        ioc_preview_html = '<span class="empty-inline">暂无 IOC</span>'

    # 纯 CSS 图表，避免报告依赖外部 CDN，保持 100% 离线。
    level_rows = [
        ("严重", crit, "#ef4444"),
        ("高危", high, "#f97316"),
        ("中危", med, "#eab308"),
        ("低危", low, "#22c55e"),
        ("信息", info, "#3b82f6"),
    ]
    nonzero = [(label, count, color) for label, count, color in level_rows if count > 0]
    if nonzero:
        cursor = 0.0
        segments = []
        for _label, count, color in nonzero:
            end = cursor + _pct(count, total_events)
            segments.append(f"{color} {cursor:.2f}% {end:.2f}%")
            cursor = end
        donut_bg = "conic-gradient(" + ", ".join(segments) + ")"
    else:
        donut_bg = "#334155"

    level_legend_html = ""
    for label, count, color in level_rows:
        level_legend_html += f"""
        <div class="legend-row">
          <span><i style="background:{color};"></i>{_h(label)}</span>
          <strong>{count}</strong>
        </div>"""

    max_ip_count = max((count for _, count in top_ips), default=1)
    ip_bars_html = ""
    for ip, count in top_ips:
        width = max(3.0, _pct(count, max_ip_count))
        ip_bars_html += f"""
        <div class="bar-row">
          <span class="bar-label">{_h(ip)}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%;"></div></div>
          <strong>{count}</strong>
        </div>"""
    if not ip_bars_html:
        ip_bars_html = '<div class="empty-state">暂无 IP 数据</div>'

    # 告警 HTML
    alerts_html = ""
    for i, alert in enumerate(summary.alerts, 1):
        color = _level_color_hex(alert.level)
        bg    = _level_bg_hex(alert.level)
        evidence_items = "".join(f"<li>{_h(e)}</li>" for e in alert.evidence)
        alerts_html += f"""
        <div class="alert-card" data-level="{_h(alert.level.value)}" style="border-left:4px solid {color}; background:{bg};">
          <div class="alert-header">
            <span class="badge" style="background:{color};">{_h(alert.level.label)}</span>
            <span class="alert-num">#{i:02d}</span>
            <strong>{_h(alert.rule_name)}</strong>
            <span class="mitre-tag">{_h(alert.mitre_attack)}</span>
            <span class="phase-tag">{_h(alert.mitre_phase)}</span>
          </div>
          <p class="alert-desc">{_h(alert.description)}</p>
          <div class="alert-meta">
            <span>置信度: {_h(alert.confidence)}</span>
            <span>时间: {_h(format_timestamp_local(alert.timestamp))}</span>
            <span>影响事件: {len(alert.affected_events)}</span>
          </div>
          <details>
            <summary>证据详情</summary>
            <ul class="evidence-list">{evidence_items}</ul>
          </details>
          <div class="recommendation">💡 {_h(alert.recommendation)}</div>
        </div>"""
    if not alerts_html:
        alerts_html = '<div class="empty-state">未发现明显威胁告警</div>'

    # 时间线 HTML
    timeline_html = ""
    for entry in summary.timeline[:100]:
        color = _level_color_hex(entry.level)
        mitre = f'<span class="mitre-tag">{_h(entry.mitre_attack)}</span>' if entry.mitre_attack else ""
        timeline_html += f"""
        <div class="tl-entry">
          <div class="tl-dot" style="background:{color};"></div>
          <div class="tl-content">
            <span class="tl-time">{_h(format_timestamp_local(entry.timestamp))}</span>
            <span class="badge" style="background:{color}; font-size:10px;">{_h(entry.level.label)}</span>
            {mitre}
            <span class="tl-cat">[{_h(entry.category)}]</span>
            <span class="tl-msg">{_h(entry.message)}</span>
          </div>
        </div>"""
    if not timeline_html:
        timeline_html = '<div class="empty-state">暂无关键事件</div>'

    # 攻击链 HTML
    chain_phases = ["侦察","初始访问","执行","持久化","权限提升","防御规避","凭据访问","横向移动","命令控制"]
    active_phases = {c.phase: c for c in summary.attack_chain}
    chain_parts: List[str] = []
    for idx, phase in enumerate(chain_phases):
        if phase in active_phases:
            c = active_phases[phase]
            color = _level_color_hex(c.level)
            techs = ", ".join(c.techniques[:3])
            chain_parts.append(f"""
            <div class="chain-item active" style="border-color:{color};">
              <div class="chain-phase" style="color:{color};">{_h(phase)}</div>
              <div class="chain-count">{c.event_count} 事件</div>
              <div class="chain-techs">{_h(techs)}</div>
            </div>""")
        else:
            chain_parts.append(f"""
            <div class="chain-item inactive">
              <div class="chain-phase">{_h(phase)}</div>
            </div>""")
        if idx < len(chain_phases) - 1:
            chain_parts.append('<div class="chain-arrow">→</div>')
    chain_html = "".join(chain_parts)

    # Incident/case HTML
    from ..detection.correlation import KILL_CHAIN_ORDER as _INCIDENT_KILL_CHAIN
    incidents_html = ""
    for i, incident in enumerate(summary.incidents, 1):
        color = _level_color_hex(incident.level)
        evidence_items = "".join(f"<li>{_h(item)}</li>" for item in incident.evidence[:8])
        action_items = "".join(f"<li>{_h(item)}</li>" for item in incident.recommended_actions)
        next_logs = "".join(f"<code>{_h(item)}</code>" for item in incident.next_logs)
        mini_timeline = "".join(
            f"<li><span>{_h(format_timestamp_local(item.timestamp))}</span>{_h(item.message)}</li>"
            for item in incident.timeline[:6]
        )
        # incident 级 mini kill chain：每个阶段一格，命中亮色，未命中灰色
        hit_phases = set(incident.attack_phases)
        chain_chips = []
        visible_phases = [p for p in _INCIDENT_KILL_CHAIN if p != "其他"]
        for idx, phase in enumerate(visible_phases):
            cls = "kc-chip kc-hit" if phase in hit_phases else "kc-chip kc-miss"
            kc_color = color if phase in hit_phases else "#475569"
            chain_chips.append(
                f'<span class="{cls}" style="border-color:{kc_color};color:{kc_color};">{_h(phase)}</span>'
            )
            if idx < len(visible_phases) - 1:
                chain_chips.append('<span class="kc-sep">›</span>')
        kill_chain_html = "".join(chain_chips)
        incidents_html += f"""
        <div class="incident-card" style="border-left-color:{color};">
          <div class="incident-head">
            <span class="badge" style="background:{color};">{_h(incident.level.label)}</span>
            <strong>#{i:02d} {_h(incident.title)}</strong>
            <span class="phase-tag">置信度 {_h(incident.confidence)}</span>
          </div>
          <p>{_h(incident.description)}</p>
          <div class="incident-killchain">{kill_chain_html}</div>
          <div class="incident-meta">
            <span>日志源: {_h(', '.join(incident.source_types[:8]) or '?')}</span>
            <span>事件: {len(incident.affected_events)}</span>
          </div>
          <div class="incident-grid">
            <div><h3>关键证据</h3><ul>{evidence_items}</ul></div>
            <div><h3>处置动作</h3><ul>{action_items}</ul></div>
          </div>
          <div class="next-logs">{next_logs}</div>
          <details><summary>案件时间线</summary><ul class="mini-timeline">{mini_timeline}</ul></details>
        </div>"""
    if not incidents_html:
        incidents_html = '<div class="empty-state">暂无跨源关联案件</div>'

    # 文件列表 HTML
    files_html = ""
    for r in parse_results:
        files_html += f"""
        <tr>
          <td>{_h(r.file_name)}</td>
          <td>{_h(r.log_type)}</td>
          <td>{r.stats.total}</td>
          <td style="color:#ef4444;">{r.stats.critical}</td>
          <td style="color:#f97316;">{r.stats.high}</td>
          <td style="color:#eab308;">{r.stats.medium}</td>
          <td>{r.file_size_bytes//1024} KB</td>
          <td>{r.parse_time_ms:.0f}ms</td>
          <td>{_h(format_timestamp_local(r.stats.time_start) if r.stats.time_start else '-')}</td>
        </tr>"""

    # Windows 登录摘要 HTML
    windows_logon_html = ""
    for r in parse_results:
        win_stats = r.stats.windows_logon_stats
        if not win_stats:
            continue
        event_blocks = ""
        for event_id in ("4624", "4625"):
            event_stats = win_stats.get("events", {}).get(event_id)
            if not event_stats:
                continue

            logon_types = "、".join(
                f"{item.get('logon_type', '?')}({item.get('label', '未知')}): {item.get('count', 0)}"
                for item in event_stats.get("logon_types", [])[:5]
            ) or "-"
            principals = "、".join(
                f"{item.get('principal', '?')}({item.get('count', 0)})"
                for item in event_stats.get("principals", [])[:5]
            ) or "-"
            source_ips = "、".join(
                f"{item.get('source_ip', '?')}({item.get('count', 0)})"
                for item in event_stats.get("source_ips", [])[:5]
            ) or "-"
            domains = "、".join(
                f"{item.get('account_domain', '?')}({item.get('count', 0)})"
                for item in event_stats.get("account_domains", [])[:5]
            ) or "-"
            processes = "、".join(
                f"{item.get('process_name', '?')}({item.get('count', 0)})"
                for item in event_stats.get("process_names", [])[:5]
            ) or "-"
            failure_reasons = "、".join(
                f"{item.get('failure_reason', '?')}({item.get('count', 0)})"
                for item in event_stats.get("failure_reasons", [])[:5]
            ) or "-"

            failure_html = (
                f"<tr><th>失败原因</th><td>{_h(failure_reasons)}</td></tr>"
                if event_id == "4625" else ""
            )
            event_blocks += f"""
            <div class="card" style="margin-bottom:12px;">
              <h3>EID {event_id} - {_h(event_stats.get('event_name', ''))} ({event_stats.get('total', 0)})</h3>
              <table>
                <tbody>
                  <tr><th>账户</th><td>{_h(principals)}</td></tr>
                  <tr><th>账号域</th><td>{_h(domains)}</td></tr>
                  <tr><th>源IP</th><td>{_h(source_ips)}</td></tr>
                  <tr><th>登录类型</th><td>{_h(logon_types)}</td></tr>
                  <tr><th>进程名</th><td>{_h(processes)}</td></tr>
                  {failure_html}
                </tbody>
              </table>
            </div>"""

        windows_logon_html += f"""
        <h3>{_h(r.file_name)}</h3>
        <div class="card">
          <div style="margin-bottom:10px; color:#94a3b8;">
            4624 成功登录: {win_stats.get('total_success', 0)} 条 &nbsp;|&nbsp;
            4625 登录失败: {win_stats.get('total_failure', 0)} 条 &nbsp;|&nbsp;
            唯一账户: {win_stats.get('unique_accounts', 0)} &nbsp;|&nbsp;
            唯一源IP: {win_stats.get('unique_source_ips', 0)}
          </div>
          {event_blocks}
        </div>"""

    # 建议 HTML
    recs_html = "".join(f"<li>{_h(r)}</li>" for r in summary.recommendations)

    risk_color = _level_color_hex(summary.risk_level)
    risk_score = summary.risk_score

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLA 分析报告 - {now}</title>
<style>
  :root {{
    --bg: #0f172a; --bg2: #1e293b; --bg3: #334155;
    --text: #e2e8f0; --text2: #94a3b8; --border: #334155;
    --crit: #ef4444; --high: #f97316; --med: #eab308;
    --low: #22c55e; --info: #3b82f6; --accent: #06b6d4;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'SF Mono', 'JetBrains Mono', monospace; background: var(--bg); color: var(--text); font-size: 13px; line-height: 1.6; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  h1 {{ font-size: 22px; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 15px; color: var(--accent); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  h3 {{ font-size: 13px; color: var(--text2); margin-bottom: 8px; }}
  .header {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
  .header-left h1 span {{ color: var(--text2); font-size: 14px; }}
  .header-meta {{ color: var(--text2); font-size: 11px; }}
  .risk-badge {{ text-align: center; }}
  .risk-score {{ font-size: 48px; font-weight: bold; color: {risk_color}; line-height: 1; }}
  .risk-label {{ font-size: 12px; color: var(--text2); }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  @media (max-width: 860px) {{
    .header, .grid-2 {{ display: block; }}
    .risk-badge {{ margin-top: 16px; text-align: left; }}
    .grid-4 {{ grid-template-columns: repeat(2, 1fr); }}
    .stat-card, .card {{ margin-bottom: 12px; }}
  }}
  .stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-num {{ font-size: 32px; font-weight: bold; }}
  .stat-label {{ font-size: 11px; color: var(--text2); margin-top: 4px; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; }}
  .alert-card {{ border-radius: 8px; padding: 14px; margin-bottom: 12px; }}
  .incident-card {{ background: var(--bg2); border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 8px; padding: 14px; margin-bottom: 12px; }}
  .incident-head {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }}
  .incident-meta {{ display: flex; gap: 12px; flex-wrap: wrap; color: var(--text2); font-size: 11px; margin: 8px 0; }}
  .incident-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 10px; }}
  .incident-grid ul {{ margin-left: 16px; color: var(--text2); }}
  .next-logs {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }}
  .next-logs code {{ background: #111827; border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; color: var(--accent); }}
  .mini-timeline {{ margin: 8px 0 0 16px; color: var(--text2); }}
  .mini-timeline span {{ color: var(--accent); margin-right: 8px; }}
  .incident-killchain {{ display: flex; gap: 4px; flex-wrap: wrap; align-items: center; margin: 10px 0 6px; }}
  .kc-chip {{ display: inline-block; padding: 2px 8px; border-radius: 999px; border: 1px solid; font-size: 11px; line-height: 1.6; }}
  .kc-chip.kc-miss {{ opacity: 0.5; }}
  .kc-sep {{ color: var(--text2); font-size: 12px; }}
  .alert-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }}
  .alert-num {{ color: var(--text2); font-size: 11px; }}
  .alert-desc {{ margin-bottom: 8px; }}
  .alert-meta {{ display: flex; gap: 16px; font-size: 11px; color: var(--text2); margin-bottom: 8px; }}
  .mitre-tag {{ background: #1e3a5f; color: #60a5fa; padding: 1px 6px; border-radius: 3px; font-size: 11px; }}
  .phase-tag {{ background: #1e2a1e; color: #86efac; padding: 1px 6px; border-radius: 3px; font-size: 11px; }}
  .evidence-list {{ margin: 8px 0 8px 16px; color: var(--text2); font-size: 12px; }}
  .recommendation {{ background: #1c2a1c; border-left: 3px solid #22c55e; padding: 8px 12px; border-radius: 4px; font-size: 12px; margin-top: 8px; }}
  details summary {{ cursor: pointer; color: var(--accent); font-size: 12px; margin: 4px 0; }}
  .tl-entry {{ display: flex; gap: 12px; margin-bottom: 8px; align-items: flex-start; }}
  .tl-dot {{ width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }}
  .tl-content {{ flex: 1; display: flex; flex-wrap: wrap; gap: 6px; align-items: baseline; }}
  .tl-time {{ color: var(--text2); font-size: 11px; white-space: nowrap; }}
  .tl-cat {{ color: var(--text2); font-size: 11px; }}
  .tl-msg {{ color: var(--text); }}
  .chain-wrapper {{ display: flex; align-items: center; flex-wrap: wrap; gap: 4px; overflow-x: auto; padding: 8px 0; }}
  .chain-item {{ border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; min-width: 90px; text-align: center; }}
  .chain-item.active {{ background: var(--bg3); }}
  .chain-item.inactive {{ opacity: 0.35; }}
  .chain-phase {{ font-size: 12px; font-weight: bold; }}
  .chain-count {{ font-size: 11px; color: var(--text2); }}
  .chain-techs {{ font-size: 10px; color: var(--text2); margin-top: 2px; }}
  .chain-arrow {{ color: var(--text2); font-size: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: var(--bg3); color: var(--text2); padding: 8px 10px; text-align: left; font-weight: normal; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--bg3); }}
  .rec-list {{ list-style: none; }}
  .rec-list li {{ padding: 8px 12px; border-left: 3px solid var(--accent); margin-bottom: 8px; background: var(--bg3); border-radius: 0 4px 4px 0; }}
  .chart-wrap {{ display: grid; grid-template-columns: 180px 1fr; gap: 18px; align-items: center; min-height: 210px; }}
  .donut {{ width: 170px; height: 170px; border-radius: 50%; background: {donut_bg}; position: relative; box-shadow: inset 0 0 0 1px rgba(255,255,255,.08); }}
  .donut::after {{ content: ""; position: absolute; inset: 42px; border-radius: 50%; background: var(--bg2); box-shadow: inset 0 0 0 1px var(--border); }}
  .donut-label {{ position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 1; }}
  .donut-label strong {{ font-size: 26px; }}
  .donut-label span {{ color: var(--text2); font-size: 11px; }}
  .legend-row {{ display: flex; justify-content: space-between; gap: 14px; padding: 6px 0; border-bottom: 1px solid rgba(148,163,184,.12); }}
  .legend-row span {{ display: flex; align-items: center; gap: 8px; color: var(--text2); }}
  .legend-row i {{ width: 9px; height: 9px; border-radius: 2px; display: inline-block; }}
  .bar-row {{ display: grid; grid-template-columns: minmax(110px, 160px) 1fr 44px; align-items: center; gap: 10px; margin: 8px 0; }}
  .bar-label {{ color: var(--text2); overflow-wrap: anywhere; }}
  .bar-track {{ height: 12px; border-radius: 999px; background: var(--bg3); overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--high), var(--crit)); }}
  .empty-state {{ color: var(--text2); padding: 20px 0; text-align: center; }}
  .empty-inline {{ color: var(--text2); }}
  .ioc-grid {{ display: grid; grid-template-columns: repeat(8, 1fr); gap: 10px; margin-bottom: 12px; }}
  .ioc-card {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 10px; text-align: center; }}
  .ioc-num {{ font-size: 22px; font-weight: bold; color: var(--accent); }}
  .ioc-label {{ color: var(--text2); font-size: 11px; }}
  .ioc-preview {{ display: flex; gap: 6px; flex-wrap: wrap; }}
  .ioc-preview code {{ background: #111827; border: 1px solid var(--border); color: var(--text2); border-radius: 4px; padding: 2px 6px; overflow-wrap: anywhere; }}
  @media (max-width: 860px) {{ .ioc-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
  .tab-bar {{ display: flex; gap: 4px; margin-bottom: 12px; }}
  .tab {{ padding: 6px 14px; border-radius: 6px 6px 0 0; cursor: pointer; background: var(--bg3); color: var(--text2); border: 1px solid var(--border); border-bottom: none; font-size: 12px; }}
  .tab.active {{ background: var(--bg2); color: var(--text); }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; }}
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 4px 12px; border-radius: 4px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); cursor: pointer; font-size: 12px; }}
  .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
  input[type=text] {{ background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 4px 10px; border-radius: 4px; font-size: 12px; width: 240px; }}
</style>
</head>
<body>
<div class="container">

  <!-- 标题 -->
  <div class="header">
    <div class="header-left">
      <h1>🛡 BlueTeam Log Analyzer <span>| 蓝队应急响应日志分析报告</span></h1>
      <div class="header-meta">
        生成时间: {now} &nbsp;|&nbsp; 分析文件: {summary.files_analyzed} 个 &nbsp;|&nbsp;
        总事件: {total_events} 条 &nbsp;|&nbsp; 告警: {len(summary.alerts)} 个 &nbsp;|&nbsp; 案件: {len(summary.incidents)} 个
      </div>
    </div>
    <div class="risk-badge">
      <div class="risk-score">{risk_score}</div>
      <div class="risk-label">风险评分 / 100</div>
      <div><span class="badge" style="background:{risk_color}; margin-top:4px;">{summary.risk_level.label}</span></div>
    </div>
  </div>

  <!-- 统计卡片 -->
  <div class="grid-4">
    <div class="stat-card"><div class="stat-num" style="color:#ef4444;">{crit}</div><div class="stat-label">严重事件</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#f97316;">{high}</div><div class="stat-label">高危事件</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#eab308;">{med}</div><div class="stat-label">中危事件</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#22c55e;">{low}</div><div class="stat-label">低危事件</div></div>
  </div>

  <!-- ATT&CK 攻击链 -->
  <h2>⛓ ATT&CK 攻击链</h2>
  <div class="card">
    <div class="chain-wrapper">{chain_html}</div>
  </div>

  <!-- 图表区 -->
  <div class="grid-2">
    <div class="card">
      <h3>事件级别分布</h3>
      <div class="chart-wrap">
        <div class="donut"><div class="donut-label"><strong>{total_events}</strong><span>事件</span></div></div>
        <div>{level_legend_html}</div>
      </div>
    </div>
    <div class="card">
      <h3>Top 攻击源 IP</h3>
      <div>{ip_bars_html}</div>
    </div>
  </div>

  <!-- 告警 -->
  <h2>🧩 应急案件视图 ({len(summary.incidents)})</h2>
  <div>{incidents_html}</div>

  <!-- 告警 -->
  <h2>🚨 威胁告警 ({len(summary.alerts)})</h2>
  <div class="filter-bar">
    <input type="text" id="alertSearch" placeholder="搜索告警..." oninput="filterAlerts()">
    <button class="filter-btn active" onclick="setFilter('all', this)">全部</button>
    <button class="filter-btn" onclick="setFilter('critical', this)" style="color:#ef4444;">严重</button>
    <button class="filter-btn" onclick="setFilter('high', this)" style="color:#f97316;">高危</button>
    <button class="filter-btn" onclick="setFilter('medium', this)" style="color:#eab308;">中危</button>
  </div>
  <div id="alertsContainer">{alerts_html}</div>

  <!-- IOC 摘要 -->
  <h2>🧭 IOC 摘要</h2>
  <div class="card">
    <div class="ioc-grid">{ioc_summary_html}</div>
    <div class="ioc-preview">{ioc_preview_html}</div>
  </div>

  <!-- 时间线 -->
  <h2>📅 关键事件时间线</h2>
  <div class="card" style="max-height:500px; overflow-y:auto;">
    {timeline_html}
  </div>

  <!-- 文件详情 -->
  <h2>📁 文件解析详情</h2>
  <div class="card">
    <table>
      <thead><tr>
        <th>文件名</th><th>类型</th><th>总事件</th>
        <th>严重</th><th>高危</th><th>中危</th>
        <th>大小</th><th>耗时</th><th>起始日期</th>
      </tr></thead>
      <tbody>{files_html}</tbody>
    </table>
  </div>

  <!-- Windows 登录摘要 -->
  {"<h2>🔐 Windows 登录事件摘要 (4624 / 4625)</h2>" + windows_logon_html if windows_logon_html else ""}

  <!-- 建议 -->
  <h2>💡 应急处置建议</h2>
  <div class="card">
    <ul class="rec-list">{recs_html}</ul>
  </div>

</div>

<script>
// 告警过滤
let currentFilter = 'all';
function setFilter(level, btn) {{
  currentFilter = level;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterAlerts();
}}
function filterAlerts() {{
  const q = document.getElementById('alertSearch').value.toLowerCase();
  document.querySelectorAll('.alert-card').forEach(card => {{
    const text = card.textContent.toLowerCase();
    const levelMatch = currentFilter === 'all' || card.dataset.level === currentFilter;
    card.style.display = (text.includes(q) && levelMatch) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    safe_print(f"  [✓] HTML 报告已保存: {output_path}")
    safe_print(f"      用浏览器打开: open {output_path}")
