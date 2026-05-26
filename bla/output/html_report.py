"""
HTML 报告输出
生成独立单文件 HTML 报告（内嵌 CSS/JS，无需网络）
"""
from __future__ import annotations

import datetime
import base64
from html import escape
from importlib import resources
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Sequence

from ..ioc import extract_iocs
from ..models import AnalysisSummary, ParseResult, ThreatLevel
from ..utils.helpers import format_timestamp_local, safe_print, sanitize_report_text
from .geo_map import build_geo_map_section


TIMELINE_LIMIT = 100


def _asset_data_uri(filename: str) -> str:
    """Return an embedded package asset as a data URI for single-file offline reports."""
    try:
        data = resources.files("bla.output").joinpath("assets", filename).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return ""
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:image/png;base64,{encoded}"


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
        "critical": "#fff5f5",
        "high":     "#fff7ed",
        "medium":   "#fffbeb",
        "low":      "#f0fdf4",
        "info":     "#eff6ff",
    }.get(level.value, "#f8fafc")


def _h(value) -> str:
    """Escape attacker-controlled log content before embedding it in HTML."""
    return escape(sanitize_report_text(value), quote=True)


def _pct(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return part * 100.0 / total


def _format_count(value: int) -> str:
    return f"{value:,}"


def _compact_count(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M".replace(".0M", "M")
    if value >= 10_000:
        return f"{value / 1_000:.1f}k".replace(".0k", "k")
    return str(value)


def _highest_level(levels: Sequence[ThreatLevel]) -> ThreatLevel:
    if not levels:
        return ThreatLevel.INFO
    return max(levels, key=lambda level: level.score)


def _highest_confidence(values: Sequence[str]) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    return max((value or "low" for value in values), key=lambda value: order.get(value, 0), default="low")


def _top_counter_text(counter: Counter, limit: int = 8) -> str:
    if not counter:
        return "?"
    parts = [f"{item}({count})" for item, count in counter.most_common(limit)]
    extra = len(counter) - limit
    if extra > 0:
        parts.append(f"+{extra}")
    return ", ".join(parts)


def _unique_ordered(values: Sequence[Any]) -> List[Any]:
    seen = set()
    result = []
    for value in values:
        if value in (None, "", "-", "null", "None"):
            continue
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _alert_display_items(alerts, event_by_id: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return alert cards optimized for human reading.

    JSON/SARIF keep the raw alerts. HTML groups high-volume credential alerts
    so one repeated campaign does not occupy hundreds of cards.
    """
    groupable = {"BRUTE-001", "SPRAY-001"}
    grouped: Dict[tuple, List[Any]] = defaultdict(list)
    first_index: Dict[tuple, int] = {}
    entries: List[tuple[int, str, Any]] = []

    for idx, alert in enumerate(alerts):
        if alert.rule_id in groupable:
            key = (alert.rule_id, alert.rule_name, alert.mitre_attack, alert.mitre_phase)
            grouped[key].append(alert)
            first_index.setdefault(key, idx)
        else:
            entries.append((idx, "single", alert))

    for key, group in grouped.items():
        if len(group) == 1:
            entries.append((first_index[key], "single", group[0]))
        else:
            entries.append((first_index[key], "group", group))

    entries.sort(key=lambda item: item[0])
    display: List[Dict[str, Any]] = []
    for _idx, kind, payload in entries:
        if kind == "single":
            alert = payload
            display.append({
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "description": alert.description,
                "level": alert.level,
                "mitre_attack": alert.mitre_attack,
                "mitre_phase": alert.mitre_phase,
                "affected_events": alert.affected_events,
                "affected_count": len(alert.affected_events),
                "evidence": alert.evidence,
                "recommendation": alert.recommendation,
                "timestamp": alert.timestamp,
                "confidence": alert.confidence,
            })
            continue

        group = payload
        event_ids = []
        seen = set()
        source_ips = Counter()
        accounts = Counter()
        timestamps = []
        for alert in group:
            timestamps.append(alert.timestamp)
            for event_id in alert.affected_events:
                if event_id in seen:
                    continue
                seen.add(event_id)
                event_ids.append(event_id)
                event = event_by_id.get(event_id)
                if not event:
                    continue
                if event.ip:
                    source_ips[event.ip] += 1
                if event.user:
                    accounts[event.user] += 1
                if event.timestamp:
                    timestamps.append(event.timestamp)

        first = group[0]
        max_level = _highest_level([alert.level for alert in group])
        confidence = _highest_confidence([alert.confidence for alert in group])
        time_start = min(timestamps) if timestamps else first.timestamp
        time_end = max(timestamps) if timestamps else first.timestamp
        source_count = len(source_ips) or len(group)
        account_count = len(accounts)
        event_count = len(event_ids) or sum(len(alert.affected_events) for alert in group)
        if first.rule_id == "SPRAY-001":
            title = "密码喷洒攻击（合并）"
            desc = (
                f"检测到 {len(group)} 个来源的密码喷洒活动，"
                f"涉及 {source_count} 个源 IP、{account_count} 个账号、{event_count} 条事件"
            )
            recommendation = "按密码喷洒活动整体处置：启用 MFA/异常登录检测，核查目标账号是否存在成功登录，并批量处置高频源 IP。"
        else:
            title = "暴力破解攻击（合并）"
            desc = (
                f"检测到 {len(group)} 个来源的暴力破解活动，"
                f"涉及 {source_count} 个源 IP、{account_count} 个账号、{event_count} 条事件"
            )
            recommendation = "按暴力破解活动整体处置：封锁高频源 IP，检查是否有成功登录，启用账户锁定策略和 MFA。"
        evidence = [
            f"合并告警: {len(group)} 个",
            f"来源IP数: {source_count}",
            f"Top 来源IP: {_top_counter_text(source_ips)}",
            f"目标账号数: {account_count}",
            f"Top 账号: {_top_counter_text(accounts)}",
            f"时间范围: {format_timestamp_local(time_start)} ~ {format_timestamp_local(time_end)}",
        ]
        display.append({
            "rule_id": first.rule_id,
            "rule_name": title,
            "description": desc,
            "level": max_level,
            "mitre_attack": first.mitre_attack,
            "mitre_phase": first.mitre_phase,
            "affected_events": event_ids,
            "affected_count": event_count,
            "evidence": evidence,
            "recommendation": recommendation,
            "timestamp": time_end,
            "confidence": confidence,
        })
    return display


def _incident_group_key(incident):
    source_types = tuple(sorted(incident.source_types))
    attack_phases = tuple(incident.attack_phases)
    assets = tuple(sorted(incident.assets))
    if (
        source_types == ("linux-auth",)
        and attack_phases == ("身份突破",)
        and assets
    ):
        return ("identity", source_types, attack_phases, assets)
    return None


def _incident_to_display(incident) -> Dict[str, Any]:
    return {
        "title": incident.title,
        "description": incident.description,
        "level": incident.level,
        "confidence": incident.confidence,
        "affected_alerts": incident.affected_alerts,
        "affected_events": incident.affected_events,
        "source_ips": incident.source_ips,
        "accounts": incident.accounts,
        "assets": incident.assets,
        "source_types": incident.source_types,
        "attack_phases": incident.attack_phases,
        "evidence": incident.evidence,
        "timeline": incident.timeline,
        "recommended_actions": incident.recommended_actions,
        "next_logs": incident.next_logs,
    }


def _incident_display_items(
    incidents: Sequence[Any],
    event_by_id: Dict[str, Any],
    alert_by_id: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Return incident cards optimized for report reading.

    Raw report.json keeps every correlated incident. The HTML report groups
    repeated identity incidents that only differ by source IP, so operators see
    the campaign first and can drill into events/timeline for detail.
    """
    grouped: Dict[tuple, List[Any]] = defaultdict(list)
    first_index: Dict[tuple, int] = {}
    entries: List[tuple[int, str, Any]] = []

    for idx, incident in enumerate(incidents):
        key = _incident_group_key(incident)
        if key:
            grouped[key].append(incident)
            first_index.setdefault(key, idx)
        else:
            entries.append((idx, "single", incident))

    for key, group in grouped.items():
        if len(group) == 1:
            entries.append((first_index[key], "single", group[0]))
        else:
            entries.append((first_index[key], "group", group))

    entries.sort(key=lambda item: item[0])
    display: List[Dict[str, Any]] = []
    for _idx, kind, payload in entries:
        if kind == "single":
            display.append(_incident_to_display(payload))
            continue

        group = payload
        event_ids: List[str] = []
        alert_ids: List[str] = []
        source_ips = Counter()
        accounts = Counter()
        assets = Counter()
        source_types: List[str] = []
        attack_phases: List[str] = []
        timeline = []
        recommended_actions: List[str] = []
        next_logs: List[str] = []

        for incident in group:
            alert_ids.extend(incident.affected_alerts)
            source_types.extend(incident.source_types)
            attack_phases.extend(incident.attack_phases)
            recommended_actions.extend(incident.recommended_actions)
            next_logs.extend(incident.next_logs)
            timeline.extend(incident.timeline)
            for value in incident.source_ips:
                source_ips[value] += 1
            for value in incident.accounts:
                accounts[value] += 1
            for value in incident.assets:
                assets[value] += 1
            for event_id in incident.affected_events:
                if event_id in event_ids:
                    continue
                event_ids.append(event_id)
                event = event_by_id.get(event_id)
                if not event:
                    continue
                event_ip = event.details.get("src_ip") or event.details.get("source_ip") or event.ip
                event_account = event.details.get("account") or event.user
                event_asset = event.details.get("asset") or event.host
                if event_ip:
                    source_ips[event_ip] += 1
                if event_account:
                    accounts[event_account] += 1
                if event_asset:
                    assets[event_asset] += 1

        unique_alert_ids = _unique_ordered(alert_ids)
        unique_source_types = _unique_ordered(source_types)
        unique_attack_phases = _unique_ordered(attack_phases)
        unique_assets = list(assets.keys())
        event_count = len(event_ids)
        source_count = len(source_ips)
        account_count = len(accounts)
        alert_rules = Counter(
            alert_by_id[alert_id].rule_id
            for alert_id in unique_alert_ids
            if alert_id in alert_by_id
        )
        unique_timeline = []
        seen_timeline = set()
        for item in timeline:
            key = (item.timestamp or "", item.event_id or "", item.message or "")
            if key in seen_timeline:
                continue
            seen_timeline.add(key)
            unique_timeline.append(item)
        timeline = sorted(unique_timeline, key=lambda item: (item.timestamp or "", item.event_id or "", item.message or ""))
        actions = [
            "按同一身份突破活动批量处置：封锁高频源 IP，核查账号登录源、MFA 状态和登录后操作，必要时冻结账号并重置凭据。"
        ]
        actions.extend(recommended_actions)
        first = group[0]
        evidence = [
            f"合并案件: {len(group)} 个",
            f"来源IP数: {source_count}",
            f"Top 来源IP: {_top_counter_text(source_ips)}",
            f"目标账号数: {account_count}",
            f"Top 账号: {_top_counter_text(accounts)}",
            f"资产: {', '.join(unique_assets[:8]) or '?'}",
            f"日志源: {', '.join(unique_source_types) or '?'}",
            f"攻击阶段: {', '.join(unique_attack_phases) or '?'}",
            f"关联告警: {len(unique_alert_ids)} 个",
            f"关键事件: {event_count} 条",
        ]
        if alert_rules:
            evidence.append(f"告警类型: {_top_counter_text(alert_rules)}")
        display.append({
            "title": "身份突破攻击活动（合并）",
            "description": (
                f"在 {', '.join(unique_source_types) or '日志'} 中合并 {len(group)} 个相似身份突破案件；"
                f"涉及 {source_count} 个源 IP、{account_count} 个账号、"
                f"{len(unique_assets)} 个资产、{event_count} 条关键事件。"
            ),
            "level": _highest_level([incident.level for incident in group]),
            "confidence": _highest_confidence([incident.confidence for incident in group]),
            "affected_alerts": unique_alert_ids,
            "affected_events": event_ids,
            "source_ips": list(source_ips.keys()),
            "accounts": list(accounts.keys()),
            "assets": unique_assets,
            "source_types": unique_source_types,
            "attack_phases": unique_attack_phases,
            "evidence": evidence,
            "timeline": timeline,
            "recommended_actions": _unique_ordered(actions),
            "next_logs": _unique_ordered(next_logs or first.next_logs),
        })
    return display


def generate_html_report(
    parse_results: List[ParseResult],
    summary: AnalysisSummary,
    output_path: str,
    geoip_cache_path: Optional[str] = None,
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
    event_by_id = {event.id: event for event in all_events}
    alert_by_id = {alert.id: alert for alert in summary.alerts}
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
        ("critical", "严重", crit, "#ef4444"),
        ("high", "高危", high, "#f97316"),
        ("medium", "中危", med, "#eab308"),
        ("low", "低危", low, "#22c55e"),
        ("info", "信息", info, "#3b82f6"),
    ]
    nonzero = [(label, count, color) for _level, label, count, color in level_rows if count > 0]
    if nonzero:
        cursor = 0.0
        segments = []
        for _label, count, color in nonzero:
            end = cursor + _pct(count, total_events)
            segments.append(f"{color} {cursor:.2f}% {end:.2f}%")
            cursor = end
        donut_bg = "conic-gradient(" + ", ".join(segments) + ")"
    else:
        donut_bg = "#e2e8f0"

    level_legend_html = ""
    for _level, label, count, color in level_rows:
        level_legend_html += f"""
        <div class="legend-row">
          <span><i style="background:{color};"></i>{_h(label)}</span>
          <strong>{_h(_format_count(count))}</strong>
        </div>"""

    stat_cards_html = ""
    for level_value, label, count, color in level_rows[:4]:
        disabled_class = " is-empty" if count <= 0 else ""
        action_label = "查看事件" if count > 0 else "暂无事件"
        stat_cards_html += f"""
    <button class="stat-card stat-link{disabled_class}" type="button" data-level="{_h(level_value)}" onclick="jumpToEvents('{_h(level_value)}')" aria-label="查看{_h(label)}事件">
      <span class="stat-accent" style="background:{color};"></span>
      <span class="stat-num" style="color:{color};">{_h(_format_count(count))}</span>
      <span class="stat-label">{_h(label)}事件</span>
      <span class="stat-action">{_h(action_label)}</span>
    </button>"""

    geo_css, geo_section_html = build_geo_map_section(parse_results, geoip_cache_path)

    max_ip_count = max((count for _, count in top_ips), default=1)
    ip_bars_html = ""
    for ip, count in top_ips:
        width = max(3.0, _pct(count, max_ip_count))
        ip_bars_html += f"""
        <div class="bar-row">
          <span class="bar-label">{_h(ip)}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%;"></div></div>
          <strong>{_h(_format_count(count))}</strong>
        </div>"""
    if not ip_bars_html:
        ip_bars_html = '<div class="empty-state">暂无 IP 数据</div>'

    # 告警 HTML。原始 JSON/SARIF 保持逐条告警；HTML 将高重复凭据类告警合并展示。
    display_alerts = _alert_display_items(summary.alerts, event_by_id)
    alerts_html = ""
    for i, alert in enumerate(display_alerts, 1):
        color = _level_color_hex(alert["level"])
        bg    = _level_bg_hex(alert["level"])
        evidence_items = "".join(f"<li>{_h(e)}</li>" for e in alert["evidence"])
        alerts_html += f"""
        <div class="alert-card" id="alert-{i:02d}" data-level="{_h(alert['level'].value)}" style="border-left:4px solid {color}; background:{bg};">
          <div class="alert-header">
            <span class="badge" style="background:{color};">{_h(alert['level'].label)}</span>
            <span class="alert-num">#{i:02d}</span>
            <strong>{_h(alert['rule_name'])}</strong>
            <span class="mitre-tag">{_h(alert['mitre_attack'])}</span>
            <span class="phase-tag">{_h(alert['mitre_phase'])}</span>
          </div>
          <p class="alert-desc">{_h(alert['description'])}</p>
          <div class="alert-meta">
            <span>置信度: {_h(alert['confidence'])}</span>
            <span>时间: {_h(format_timestamp_local(alert['timestamp']))}</span>
            <span>影响事件: {alert['affected_count']}</span>
          </div>
          <details>
            <summary>证据详情</summary>
            <ul class="evidence-list">{evidence_items}</ul>
          </details>
          <div class="recommendation"><strong>建议</strong><span>{_h(alert['recommendation'])}</span></div>
        </div>"""
    if not alerts_html:
        alerts_html = '<div class="empty-state">未发现明显威胁告警</div>'
    alert_title = f"威胁告警 ({len(summary.alerts)})"
    if len(display_alerts) != len(summary.alerts):
        alert_title += f" · 合并展示 {len(display_alerts)} 组"

    # 时间线 HTML
    timeline_html = ""
    for entry in summary.timeline[:TIMELINE_LIMIT]:
        color = _level_color_hex(entry.level)
        mitre = f'<span class="mitre-tag">{_h(entry.mitre_attack)}</span>' if entry.mitre_attack else ""
        timeline_html += f"""
        <div class="tl-entry" data-level="{_h(entry.level.value)}">
          <div class="tl-dot" style="background:{color};"></div>
          <div class="tl-content">
            <span class="tl-time">{_h(format_timestamp_local(entry.timestamp))}</span>
            <span class="badge" style="background:{color}; font-size:10px;">{_h(entry.level.label)}</span>
            {mitre}
            <span class="tl-cat">[{_h(entry.category)}]</span>
            <span class="tl-msg">{_h(entry.message)}</span>
          </div>
        </div>"""
    timeline_total = len(summary.timeline)
    if timeline_total > TIMELINE_LIMIT:
        timeline_html += f"""
        <div class="empty-state">
          时间线仅展示前 {TIMELINE_LIMIT} 条，共 {timeline_total} 条；完整事件请查看 report.json 或 events.csv。
        </div>"""
    if not timeline_html:
        timeline_html = '<div class="empty-state">暂无关键事件</div>'

    # 攻击链 HTML
    chain_phases = [
        "侦察","初始访问","身份突破","执行","持久化","权限提升","主机失陷",
        "远程访问","横向移动","命令控制","数据外传","凭据访问","防御规避","网络活动","其他",
    ]
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

    # Incident/case HTML。原始 JSON 保持逐案明细；HTML 将重复身份类案件合并展示。
    from ..detection.correlation import KILL_CHAIN_ORDER as _INCIDENT_KILL_CHAIN
    display_incidents = _incident_display_items(summary.incidents, event_by_id, alert_by_id)
    incidents_html = ""
    for i, incident in enumerate(display_incidents, 1):
        color = _level_color_hex(incident["level"])
        evidence_items = "".join(f"<li>{_h(item)}</li>" for item in incident["evidence"][:10])
        action_items = "".join(f"<li>{_h(item)}</li>" for item in incident["recommended_actions"])
        next_logs = "".join(f"<code>{_h(item)}</code>" for item in incident["next_logs"])
        mini_timeline = "".join(
            f"<li><span>{_h(format_timestamp_local(item.timestamp))}</span>{_h(item.message)}</li>"
            for item in incident["timeline"][:6]
        )
        # incident 级 mini kill chain：每个阶段一格，命中亮色，未命中灰色
        hit_phases = set(incident["attack_phases"])
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
            <span class="badge" style="background:{color};">{_h(incident['level'].label)}</span>
            <strong>#{i:02d} {_h(incident['title'])}</strong>
            <span class="phase-tag">置信度 {_h(incident['confidence'])}</span>
          </div>
          <p>{_h(incident['description'])}</p>
          <div class="incident-killchain">{kill_chain_html}</div>
          <div class="incident-meta">
            <span>日志源: {_h(', '.join(incident['source_types'][:8]) or '?')}</span>
            <span>事件: {len(incident['affected_events'])}</span>
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
    incident_title = f"应急案件视图 ({len(summary.incidents)})"
    if len(display_incidents) != len(summary.incidents):
        incident_title += f" · 合并展示 {len(display_incidents)} 组"

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
    logo_data_uri = _asset_data_uri("bla-logo.png")
    logo_html = (
        f'<img class="brand-logo" src="{logo_data_uri}" alt="BLA logo">'
        if logo_data_uri else '<span class="brand-mark">BLA</span>'
    )

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLA 分析报告 - {now}</title>
<style>
  :root {{
    --bg: #f4f7fb; --surface: #ffffff; --surface2: #f8fafc;
    --text: #172033; --muted: #667085; --faint: #98a2b3; --border: #d9e2ec;
    --crit: #d92d20; --high: #e26f20; --med: #b88700;
    --low: #16803a; --info: #2563eb; --accent: #0e7490;
    --shadow: 0 12px 30px rgba(15, 23, 42, .07);
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    font-size: 14px; line-height: 1.62;
  }}
  button, input {{ font: inherit; }}
  .container {{ max-width: 1480px; margin: 0 auto; padding: 32px 36px 48px; }}
  h1 {{ display:flex; align-items:center; gap:14px; font-size: 24px; margin-bottom: 12px; }}
  h2 {{ display:flex; align-items:center; gap:10px; font-size: 18px; color:#123243; margin: 30px 0 14px; }}
  h2::before {{ content:""; width:4px; height:18px; border-radius:999px; background:#1f7a8c; }}
  h3 {{ font-size: 14px; color: var(--muted); margin-bottom: 10px; }}
  .mono, .chain-techs, .tl-time, code {{ font-family: "SF Mono", "JetBrains Mono", ui-monospace, monospace; }}
  .header {{
    min-height: 132px; background: linear-gradient(135deg, #fff, #f9fbff);
    border: 1px solid var(--border); border-radius: 14px; padding: 26px 30px;
    margin-bottom: 20px; display:flex; justify-content:space-between; align-items:center; box-shadow: var(--shadow);
  }}
  .brand-mark {{
    width:42px; height:42px; border-radius:10px; display:inline-flex; align-items:center; justify-content:center;
    color:#fff; background:#1f7a8c; font-size:12px; font-weight:800; letter-spacing:.05em;
  }}
  .brand-logo {{
    width: 116px;
    height: auto;
    display: block;
    flex-shrink: 0;
  }}
  .brand-name {{ font-weight: 800; color: #123243; }}
  .report-title {{ padding-left: 16px; border-left:1px solid #cbd5e1; color: var(--muted); font-size: 16px; font-weight: 700; }}
  .header-meta {{ display:flex; flex-wrap:wrap; gap:10px; color:var(--muted); font-size:12px; font-weight:650; }}
  .header-meta span {{ padding:5px 9px; border:1px solid #e2e8f0; border-radius:999px; background:#fff; }}
  .risk-badge {{ min-width: 146px; text-align:center; background:#fff5f5; border:1px solid #fecaca; border-radius:14px; padding:12px 16px; }}
  .risk-score {{ font-size: 52px; font-weight: 850; color: {risk_color}; line-height: 1; }}
  .risk-label {{ color: var(--muted); font-size: 12px; font-weight: 700; margin: 4px 0; }}
  .grid-4 {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:14px; margin-bottom: 24px; }}
  .grid-2 {{ display:grid; grid-template-columns: 1fr 1fr; gap:18px; }}
  .card, .stat-card, .incident-card {{
    background: var(--surface); border:1px solid var(--border); border-radius:14px; box-shadow: var(--shadow);
  }}
  .card {{ padding: 20px; margin-bottom: 18px; }}
  .stat-card {{
    position:relative; min-height:112px; padding: 20px 22px; text-align:left; overflow:hidden;
    appearance:none; cursor:pointer; transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease;
  }}
  .stat-card:hover {{ transform: translateY(-2px); border-color:#b7c4d4; box-shadow:0 16px 34px rgba(15,23,42,.11); }}
  .stat-card:focus-visible {{ outline:3px solid rgba(14,116,144,.22); outline-offset:2px; }}
  .stat-card.is-empty {{ cursor: default; }}
  .stat-card.is-empty:hover {{ transform:none; }}
  .stat-accent {{ position:absolute; inset:0 0 auto 0; height:4px; }}
  .stat-num {{ display:block; font-size:34px; line-height:1; font-weight:850; margin-top:10px; }}
  .stat-label {{ display:block; color:var(--muted); font-size:13px; font-weight:750; margin-top:10px; }}
  .stat-action {{ display:block; color:var(--faint); font-size:11px; margin-top:4px; }}
  .badge {{ display:inline-block; padding:3px 9px; border-radius:999px; font-size:11px; font-weight:750; color:#fff; }}
  .alert-card {{ border-radius:14px; padding:16px; margin-bottom:12px; border:1px solid var(--border); color:var(--text); }}
  .incident-card {{ border-left:4px solid var(--accent); padding:16px; margin-bottom:12px; }}
  .incident-head {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:8px; font-size:15px; }}
  .incident-meta {{ display:flex; gap:12px; flex-wrap:wrap; color:var(--muted); font-size:12px; margin:9px 0; }}
  .incident-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:12px; padding:14px; border:1px solid #e2e8f0; border-radius:12px; background:var(--surface2); }}
  .incident-grid ul {{ margin-left:16px; color:var(--muted); }}
  .next-logs {{ display:flex; gap:6px; flex-wrap:wrap; margin-top:10px; }}
  .next-logs code, .ioc-preview code {{ background:#f8fafc; border:1px solid var(--border); border-radius:5px; padding:2px 6px; color:#0e7490; }}
  .mini-timeline {{ margin:8px 0 0 16px; color:var(--muted); }}
  .mini-timeline span {{ color:#0e7490; margin-right:8px; }}
  .incident-killchain {{ display:flex; gap:4px; flex-wrap:wrap; align-items:center; margin:10px 0 6px; }}
  .kc-chip {{ display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid; font-size:11px; line-height:1.6; }}
  .kc-chip.kc-miss {{ opacity:.45; }}
  .kc-sep {{ color:var(--faint); font-size:12px; }}
  .alert-header {{ display:flex; align-items:center; gap:8px; margin-bottom:8px; flex-wrap:wrap; }}
  .alert-num, .alert-meta, .tl-time, .tl-cat {{ color:var(--muted); font-size:12px; }}
  .alert-desc {{ margin-bottom:8px; }}
  .alert-meta {{ display:flex; gap:16px; margin-bottom:8px; }}
  .mitre-tag {{ background:#eff6ff; color:#1d4ed8; padding:2px 7px; border-radius:5px; font-size:11px; }}
  .phase-tag {{ background:#ecfdf3; color:#047857; padding:2px 7px; border-radius:5px; font-size:11px; }}
  .evidence-list {{ margin:8px 0 8px 16px; color:var(--muted); font-size:12px; }}
  .recommendation {{ display:flex; gap:8px; background:#ecfdf3; border-left:3px solid #16a34a; padding:9px 12px; border-radius:6px; font-size:12px; margin-top:8px; }}
  .recommendation strong {{ color:#047857; flex-shrink:0; }}
  details summary {{ cursor:pointer; color:#0e7490; font-size:12px; margin:4px 0; }}
  .chain-wrapper {{ display:flex; align-items:center; flex-wrap:wrap; gap:8px; overflow-x:auto; padding:10px 0; }}
  .chain-item {{ border:1px solid var(--border); border-radius:12px; padding:11px 14px; min-width:104px; text-align:center; background:#fff; }}
  .chain-item.active {{ background:#fff7ed; }}
  .chain-item.inactive {{ color:var(--faint); background:var(--surface2); }}
  .chain-phase {{ font-size:13px; font-weight:800; }}
  .chain-count {{ font-size:12px; color:var(--muted); font-weight:700; }}
  .chain-techs {{ font-size:11px; color:var(--muted); margin-top:2px; }}
  .chain-arrow {{ color:var(--faint); font-size:16px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; }}
  th {{ background:var(--surface2); color:var(--muted); padding:8px 10px; text-align:left; font-weight:700; }}
  td {{ padding:7px 10px; border-bottom:1px solid var(--border); }}
  tr:hover td {{ background:var(--surface2); }}
  .rec-list {{ list-style:none; }}
  .rec-list li {{ padding:9px 12px; border-left:3px solid var(--accent); margin-bottom:8px; background:var(--surface2); border-radius:0 6px 6px 0; }}
  .chart-wrap {{ display:grid; grid-template-columns:180px 1fr; gap:18px; align-items:center; min-height:210px; }}
  .donut {{ width:170px; height:170px; border-radius:50%; background:{donut_bg}; position:relative; }}
  .donut::after {{ content:""; position:absolute; inset:42px; border-radius:50%; background:#fff; box-shadow:inset 0 0 0 1px var(--border); }}
  .donut-label {{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; z-index:1; }}
  .donut-label strong {{ font-size:24px; letter-spacing:0; line-height:1; }}
  .donut-label span {{ color:var(--muted); font-size:12px; margin-top:5px; }}
  .legend-row {{ display:flex; justify-content:space-between; gap:14px; padding:7px 0; border-bottom:1px solid #edf1f6; }}
  .legend-row span {{ display:flex; align-items:center; gap:8px; color:var(--muted); }}
  .legend-row i {{ width:9px; height:9px; border-radius:2px; display:inline-block; }}
  .bar-row {{ display:grid; grid-template-columns:minmax(110px,160px) 1fr 44px; align-items:center; gap:10px; margin:10px 0; }}
  .bar-label {{ color:var(--muted); overflow-wrap:anywhere; }}
  .bar-track {{ height:12px; border-radius:999px; background:#e8edf5; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:999px; background:linear-gradient(90deg, var(--high), var(--crit)); }}
  .empty-state {{ color:var(--muted); padding:20px 0; text-align:center; }}
  .empty-inline {{ color:var(--muted); }}
  .ioc-grid {{ display:grid; grid-template-columns:repeat(8,1fr); gap:10px; margin-bottom:12px; }}
  .ioc-card {{ background:var(--surface2); border:1px solid var(--border); border-radius:10px; padding:10px; text-align:center; }}
  .ioc-num {{ font-size:22px; font-weight:800; color:var(--accent); }}
  .ioc-label {{ color:var(--muted); font-size:11px; }}
  .ioc-preview {{ display:flex; gap:6px; flex-wrap:wrap; }}
  .filter-bar, .timeline-tools {{ display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; align-items:center; }}
  .filter-btn {{ padding:6px 12px; border-radius:999px; border:1px solid var(--border); background:#fff; color:var(--muted); cursor:pointer; font-size:12px; font-weight:700; }}
  .filter-btn:hover {{ border-color:#b7c4d4; color:var(--text); }}
  .filter-btn.active {{ border-color:var(--accent); color:var(--accent); background:#effafa; }}
  input[type=text] {{ background:#fff; border:1px solid var(--border); color:var(--text); padding:6px 11px; border-radius:999px; font-size:12px; width:240px; }}
  .timeline-card {{ max-height:500px; overflow-y:auto; }}
  .tl-entry {{ display:flex; gap:12px; margin-bottom:9px; align-items:flex-start; }}
  .tl-entry.is-hidden, .alert-card.is-hidden {{ display:none; }}
  .tl-dot {{ width:10px; height:10px; border-radius:50%; margin-top:6px; flex-shrink:0; }}
  .tl-content {{ flex:1; display:flex; flex-wrap:wrap; gap:6px; align-items:baseline; }}
  .tl-msg {{ color:var(--text); }}
{geo_css}
  @media (max-width: 860px) {{
    .container {{ padding:20px; }}
    .header, .grid-2 {{ display:block; }}
    .risk-badge {{ margin-top:16px; text-align:left; }}
    .grid-4 {{ grid-template-columns:repeat(2,1fr); }}
    .incident-grid, .chart-wrap {{ display:block; }}
    .ioc-grid {{ grid-template-columns:repeat(2,1fr); }}
    .stat-card, .card {{ margin-bottom:12px; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- 标题 -->
  <div class="header">
    <div class="header-left">
      <h1>{logo_html}<span class="brand-name">BlueTeam Log Analyzer</span><span class="report-title">蓝队应急响应日志分析报告</span></h1>
      <div class="header-meta">
        <span>生成时间: {now}</span>
        <span>分析文件: {summary.files_analyzed} 个</span>
        <span>总事件: {total_events} 条</span>
        <span>告警: {len(summary.alerts)} 个</span>
        <span>案件: {len(summary.incidents)} 个</span>
      </div>
    </div>
    <div class="risk-badge">
      <div class="risk-score">{risk_score}</div>
      <div class="risk-label">风险评分 / 100</div>
      <div><span class="badge" style="background:{risk_color}; margin-top:4px;">{summary.risk_level.label}</span></div>
    </div>
  </div>

  <!-- 统计卡片 -->
  <div class="grid-4">{stat_cards_html}
  </div>

  {geo_section_html}

  <!-- ATT&CK 攻击链 -->
  <h2>ATT&CK 攻击链</h2>
  <div class="card">
    <div class="chain-wrapper">{chain_html}</div>
  </div>

  <!-- 图表区 -->
  <div class="grid-2">
    <div class="card">
      <h3>事件级别分布</h3>
      <div class="chart-wrap">
        <div class="donut" title="共 {_h(_format_count(total_events))} 条事件"><div class="donut-label"><strong>{_h(_compact_count(total_events))}</strong><span>事件</span></div></div>
        <div>{level_legend_html}</div>
      </div>
    </div>
    <div class="card">
      <h3>Top 攻击源 IP</h3>
      <div>{ip_bars_html}</div>
    </div>
  </div>

  <!-- 告警 -->
  <h2>{_h(incident_title)}</h2>
  <div>{incidents_html}</div>

  <!-- 告警 -->
  <h2 id="alertsSection">{_h(alert_title)}</h2>
  <div class="filter-bar">
    <input type="text" id="alertSearch" placeholder="搜索告警..." oninput="filterAlerts()">
    <button class="filter-btn active" type="button" data-alert-filter="all" onclick="setFilter('all', this)">全部</button>
    <button class="filter-btn" type="button" data-alert-filter="critical" onclick="setFilter('critical', this)" style="color:#d92d20;">严重</button>
    <button class="filter-btn" type="button" data-alert-filter="high" onclick="setFilter('high', this)" style="color:#e26f20;">高危</button>
    <button class="filter-btn" type="button" data-alert-filter="medium" onclick="setFilter('medium', this)" style="color:#b88700;">中危</button>
  </div>
  <div id="alertsContainer">{alerts_html}</div>

  <!-- IOC 摘要 -->
  <h2>IOC 摘要</h2>
  <div class="card">
    <div class="ioc-grid">{ioc_summary_html}</div>
    <div class="ioc-preview">{ioc_preview_html}</div>
  </div>

  <!-- 时间线 -->
  <h2 id="timelineSection">关键事件时间线</h2>
  <div class="timeline-tools">
    <button class="filter-btn active" type="button" data-timeline-filter="all" onclick="setTimelineFilter('all', this)">全部事件</button>
    <button class="filter-btn" type="button" data-timeline-filter="critical" onclick="setTimelineFilter('critical', this)" style="color:#d92d20;">严重</button>
    <button class="filter-btn" type="button" data-timeline-filter="high" onclick="setTimelineFilter('high', this)" style="color:#e26f20;">高危</button>
    <button class="filter-btn" type="button" data-timeline-filter="medium" onclick="setTimelineFilter('medium', this)" style="color:#b88700;">中危</button>
    <button class="filter-btn" type="button" data-timeline-filter="low" onclick="setTimelineFilter('low', this)" style="color:#16803a;">低危</button>
  </div>
  <div class="card timeline-card">
    {timeline_html}
    <div id="timelineEmpty" class="empty-state" style="display:none;">当前级别暂无关键事件</div>
  </div>

  <!-- 文件详情 -->
  <h2>文件解析详情</h2>
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
  {"<h2>Windows 登录事件摘要 (4624 / 4625)</h2>" + windows_logon_html if windows_logon_html else ""}

  <!-- 建议 -->
  <h2>应急处置建议</h2>
  <div class="card">
    <ul class="rec-list">{recs_html}</ul>
  </div>

</div>

<script>
// 告警过滤
let currentFilter = 'all';
function setFilter(level, btn) {{
  currentFilter = level;
  document.querySelectorAll('[data-alert-filter]').forEach(b => b.classList.remove('active'));
  if (btn) {{
    btn.classList.add('active');
  }} else {{
    const target = document.querySelector(`[data-alert-filter="${{level}}"]`);
    if (target) target.classList.add('active');
  }}
  filterAlerts();
}}
function filterAlerts() {{
  const q = document.getElementById('alertSearch').value.toLowerCase();
  document.querySelectorAll('.alert-card').forEach(card => {{
    const text = card.textContent.toLowerCase();
    const levelMatch = currentFilter === 'all' || card.dataset.level === currentFilter;
    card.classList.toggle('is-hidden', !(text.includes(q) && levelMatch));
  }});
}}

let currentTimelineFilter = 'all';
function setTimelineFilter(level, btn) {{
  currentTimelineFilter = level;
  document.querySelectorAll('[data-timeline-filter]').forEach(b => b.classList.remove('active'));
  if (btn) {{
    btn.classList.add('active');
  }} else {{
    const target = document.querySelector(`[data-timeline-filter="${{level}}"]`);
    if (target) target.classList.add('active');
  }}
  filterTimeline();
}}
function filterTimeline() {{
  let visible = 0;
  document.querySelectorAll('.tl-entry').forEach(entry => {{
    const match = currentTimelineFilter === 'all' || entry.dataset.level === currentTimelineFilter;
    entry.classList.toggle('is-hidden', !match);
    if (match) visible += 1;
  }});
  const empty = document.getElementById('timelineEmpty');
  if (empty) empty.style.display = visible ? 'none' : '';
}}
function jumpToEvents(level) {{
  setFilter(level);
  setTimelineFilter(level);
  const hasAlert = document.querySelector(`.alert-card[data-level="${{level}}"]:not(.is-hidden)`);
  const section = hasAlert ? document.getElementById('alertsSection') : document.getElementById('timelineSection');
  if (section) section.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    safe_print(f"  [✓] HTML 报告已保存: {output_path}")
    safe_print(f"      请用浏览器打开该文件: {output_path}")
