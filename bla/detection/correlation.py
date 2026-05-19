"""Cross-source incident correlation for P0/HVV investigations."""
from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..models import DetectionAlert, Incident, LogEvent, ThreatLevel, TimelineEntry


_LEVEL_ORDER = {
    ThreatLevel.CRITICAL: 4,
    ThreatLevel.HIGH: 3,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.LOW: 1,
    ThreatLevel.INFO: 0,
}

_FAMILY_PHASE = {
    "reconnaissance": "侦察",
    "initial-access": "初始访问",
    "identity": "身份突破",
    "execution": "执行",
    "persistence": "持久化",
    "privilege-escalation": "权限提升",
    "compromise": "主机失陷",
    "remote-access": "远程访问",
    "lateral-movement": "横向移动",
    "command-control": "命令控制",
    "exfiltration": "数据外传",
    "network": "网络活动",
    "other": "其他",
}

# 按 ATT&CK kill chain 顺序定义阶段权重，用于 incident.attack_phases 排序，
# 这样 HTML / explain 输出的攻击链一定是从"侦察"走到"数据外传"，符合
# 蓝队复盘的阅读习惯，而不是按字母序。
KILL_CHAIN_ORDER = (
    "侦察",
    "初始访问",
    "身份突破",
    "执行",
    "持久化",
    "权限提升",
    "主机失陷",
    "远程访问",
    "横向移动",
    "命令控制",
    "数据外传",
    "网络活动",
    "其他",
)
_PHASE_INDEX = {phase: idx for idx, phase in enumerate(KILL_CHAIN_ORDER)}


def correlate_incidents(events: Sequence[LogEvent], alerts: Sequence[DetectionAlert]) -> List[Incident]:
    """Build incident-level cases from related alerts/events."""
    if not events and not alerts:
        return []

    event_by_id = {event.id: event for event in events}
    events_for_alert: Dict[str, List[LogEvent]] = {
        alert.id: [event_by_id[eid] for eid in alert.affected_events if eid in event_by_id]
        for alert in alerts
    }

    groups: Dict[Tuple[str, str], Dict[str, Set[str]]] = defaultdict(
        lambda: {"alerts": set(), "events": set()}
    )
    for alert in alerts:
        related = events_for_alert.get(alert.id) or []
        keys = _correlation_keys(related)
        if not keys:
            keys = [("alert", alert.id)]
        for key in keys:
            groups[key]["alerts"].add(alert.id)
            groups[key]["events"].update(event.id for event in related)

    # Keep high-value standalone events visible when they did not become an alert.
    alert_event_ids = {eid for alert in alerts for eid in alert.affected_events}
    for event in events:
        if event.id in alert_event_ids:
            continue
        if event.level.score < ThreatLevel.HIGH.score:
            continue
        if event.details.get("source_type") in {"waf", "vpn", "bastion", "dns", "proxy", "firewall", "edr", "application"}:
            for key in _correlation_keys([event]) or [("event", event.id)]:
                groups[key]["events"].add(event.id)

    incidents: List[Incident] = []
    used_event_sets: Set[Tuple[str, ...]] = set()
    alert_by_id = {alert.id: alert for alert in alerts}
    for members in _merged_group_members(groups.values()):
        group_events = [event_by_id[eid] for eid in sorted(members["events"]) if eid in event_by_id]
        group_alerts = [alert_by_id[aid] for aid in sorted(members["alerts"]) if aid in alert_by_id]
        if not _is_incident_candidate(group_events, group_alerts):
            continue
        event_key = tuple(sorted(event.id for event in group_events))
        if event_key in used_event_sets:
            continue
        used_event_sets.add(event_key)
        incidents.append(_build_incident(len(incidents) + 1, group_events, group_alerts))

    incidents.sort(key=lambda item: (_LEVEL_ORDER[item.level], len(item.source_types), len(item.affected_events)), reverse=True)
    incidents = _drop_subset_incidents(incidents)
    incidents = [incident for incident in incidents if not _is_low_value_windows_standalone_incident(incident)]
    for idx, incident in enumerate(incidents, 1):
        incident.id = f"inc-{idx:03d}"
    return incidents[:50]


def _merged_group_members(groups: Iterable[Dict[str, Set[str]]]) -> List[Dict[str, Set[str]]]:
    merged: List[Dict[str, Set[str]]] = []
    for members in groups:
        current = {
            "alerts": set(members["alerts"]),
            "events": set(members["events"]),
        }
        idx = 0
        while idx < len(merged):
            existing = merged[idx]
            if current["alerts"] & existing["alerts"] or current["events"] & existing["events"]:
                current["alerts"].update(existing["alerts"])
                current["events"].update(existing["events"])
                merged.pop(idx)
                idx = 0
                continue
            idx += 1
        merged.append(current)
    return merged


def _correlation_keys(events: Iterable[LogEvent]) -> List[Tuple[str, str]]:
    keys: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for event in events:
        day = (event.timestamp or "")[:10] or "unknown"
        candidates = [
            ("session", event.details.get("session_id", "")),
            ("trace", event.details.get("trace_id", "")),
            ("ip", event.details.get("src_ip", "") or event.details.get("source_ip", "") or event.ip or ""),
            ("workstation", event.details.get("workstation", "")),
            ("account", event.details.get("account", "") or event.details.get("target_account", "") or event.user or ""),
            ("account", event.details.get("account_name", "")),
            ("account", event.details.get("member_account", "")),
            ("sid", event.details.get("target_sid", "")),
            ("sid", event.details.get("member_sid", "")),
            ("asset", event.details.get("asset", "") or event.host or ""),
        ]
        for kind, value in candidates:
            value = str(value or "").strip()
            if not value:
                continue
            key = (kind, f"{value}|{day}")
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def _is_incident_candidate(events: Sequence[LogEvent], alerts: Sequence[DetectionAlert]) -> bool:
    if not events and not alerts:
        return False
    source_types = {str(event.details.get("source_type") or "") for event in events}
    source_types.discard("")
    families = {str(event.details.get("event_family") or "") for event in events}
    families.discard("")
    if len(source_types) >= 2 and (alerts or len(families) >= 2):
        return True
    if any(alert.level.score >= ThreatLevel.HIGH.score for alert in alerts):
        return True
    if any(event.level.score >= ThreatLevel.CRITICAL.score for event in events):
        return True
    return False


def _drop_subset_incidents(incidents: Sequence[Incident]) -> List[Incident]:
    kept: List[Incident] = []
    for incident in incidents:
        current = set(incident.affected_events)
        if current and any(_is_duplicate_incident(incident, existing) for existing in kept):
            continue
        kept.append(incident)
    return kept


def _is_duplicate_incident(candidate: Incident, existing: Incident) -> bool:
    current = set(candidate.affected_events)
    previous = set(existing.affected_events)
    if not current or not previous:
        return False
    if current.issubset(previous):
        return True
    overlap = len(current & previous)
    smaller = min(len(current), len(previous))
    if smaller == 0 or overlap / smaller < 0.8:
        return False
    same_entities = bool(
        set(candidate.source_ips) & set(existing.source_ips)
        or set(candidate.assets) & set(existing.assets)
        or set(candidate.accounts) & set(existing.accounts)
    )
    return (
        same_entities
        and candidate.source_types == existing.source_types
        and candidate.attack_phases == existing.attack_phases
    )


def _is_low_value_windows_standalone_incident(incident: Incident) -> bool:
    return (
        incident.source_types == ["windows-event"]
        and incident.confidence == "low"
        and len(incident.affected_events) <= 1
        and not incident.source_ips
    )


def _build_incident(index: int, events: Sequence[LogEvent], alerts: Sequence[DetectionAlert]) -> Incident:
    events, alerts = _focus_windows_chain_scope(events, alerts)
    max_level = _max_level(
        [event.level for event in events] + [alert.level for alert in alerts],
        default=ThreatLevel.INFO,
    )
    source_ips = _sorted_values(event.details.get("src_ip") or event.details.get("source_ip") or event.ip for event in events)
    accounts = _sorted_values(event.details.get("account") or event.user for event in events)
    assets = _sorted_values(event.details.get("asset") or event.host for event in events)
    operators = _sorted_values(event.details.get("operator_account") or event.details.get("subject_account") for event in events)
    workstations = _sorted_values(event.details.get("source_workstation") or event.details.get("workstation") for event in events)
    source_types = _sorted_values(event.details.get("source_type") for event in events)
    families = _sorted_values(event.details.get("event_family") for event in events)
    raw_phases = [_FAMILY_PHASE.get(family, family) for family in families]
    # 按 ATT&CK kill chain 顺序去重排序，未知阶段排在已知之后
    phases = sorted(
        dict.fromkeys(raw_phases),
        key=lambda phase: (_PHASE_INDEX.get(phase, len(_PHASE_INDEX)), phase),
    )
    confidence = _confidence(events, alerts, source_types, families)
    title = _title(source_ips, accounts, assets, source_types, phases, max_level, alerts)
    description = _description(source_ips, accounts, assets, operators, workstations, source_types, phases, alerts, events)
    timeline = _timeline(events)
    evidence = _evidence(events, alerts, source_ips, accounts, assets, operators, workstations, source_types, phases)

    return Incident(
        id=f"inc-{index:03d}",
        title=title,
        description=description,
        level=max_level,
        confidence=confidence,
        affected_alerts=[alert.id for alert in alerts],
        affected_events=[event.id for event in events],
        source_ips=source_ips,
        accounts=accounts,
        assets=assets,
        source_types=source_types,
        attack_phases=phases,
        evidence=evidence,
        timeline=timeline,
        recommended_actions=_recommended_actions(source_types, families, max_level),
        next_logs=_next_logs(source_types, families),
    )


def _max_level(levels: Sequence[ThreatLevel], default: ThreatLevel) -> ThreatLevel:
    return max(levels, key=lambda level: level.score) if levels else default


def _sorted_values(values: Iterable[object]) -> List[str]:
    return sorted({str(value) for value in values if value not in (None, "", "-", "null", "None")})


def _focus_windows_chain_scope(
    events: Sequence[LogEvent],
    alerts: Sequence[DetectionAlert],
) -> Tuple[List[LogEvent], List[DetectionAlert]]:
    chain_alerts = [alert for alert in alerts if alert.rule_id == "WIN-CHAIN-001"]
    if not chain_alerts:
        return list(events), list(alerts)

    chain_event_ids = {event_id for alert in chain_alerts for event_id in alert.affected_events}
    chain_events = [event for event in events if event.id in chain_event_ids]
    if not chain_events:
        return list(events), list(alerts)

    account_keys = {
        _account_key(value)
        for event in chain_events
        for value in (
            event.details.get("account"),
            event.details.get("target_account"),
            event.details.get("account_name"),
        )
        if _account_key(value)
    }
    sids = {
        str(value).strip().lower()
        for event in chain_events
        for value in (event.details.get("target_sid"), event.details.get("member_sid"))
        if value not in (None, "", "-")
    }
    focused = [
        event for event in events
        if event.id in chain_event_ids
        or (
            _event_matches_account(event, account_keys, sids)
            and _event_within_chain_window(event, chain_events, window_seconds=15 * 60)
        )
    ]
    focused_ids = {event.id for event in focused}
    focused_alerts = [
        alert for alert in alerts
        if alert.rule_id == "WIN-CHAIN-001" or set(alert.affected_events) & focused_ids
    ]
    return focused, focused_alerts


def _event_matches_account(event: LogEvent, account_keys: Set[str], sids: Set[str]) -> bool:
    if not account_keys and not sids:
        return False
    event_keys = {
        _account_key(value)
        for value in (
            event.details.get("account"),
            event.details.get("target_account"),
            event.details.get("target_user"),
            event.details.get("member_account"),
            event.details.get("member_name"),
            event.details.get("account_name"),
        )
        if _account_key(value)
    }
    if event_keys & account_keys:
        return True
    event_sids = {
        str(value).strip().lower()
        for value in (event.details.get("target_sid"), event.details.get("member_sid"))
        if value not in (None, "", "-")
    }
    return bool(event_sids & sids)


def _event_within_chain_window(event: LogEvent, chain_events: Sequence[LogEvent], window_seconds: int) -> bool:
    current = _event_datetime(event)
    chain_times = [_event_datetime(item) for item in chain_events]
    chain_times = [item for item in chain_times if item is not None]
    if current is None or not chain_times:
        return True
    return min(chain_times) - datetime.timedelta(seconds=window_seconds) <= current <= max(chain_times) + datetime.timedelta(seconds=window_seconds)


def _event_datetime(event: LogEvent) -> Optional[datetime.datetime]:
    if not event.timestamp:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def _account_key(value: object) -> str:
    text = str(value or "").strip().strip("\\/")
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    return text.lower()


def _first_human(values: Sequence[str]) -> str:
    for value in values:
        if not value.startswith("S-1-"):
            return value
    return values[0] if values else ""


def _human_accounts(values: Sequence[str]) -> List[str]:
    human = [value for value in values if not value.startswith("S-1-")]
    return human or list(values)


def _chain_account(alerts: Sequence[DetectionAlert]) -> str:
    for alert in alerts:
        if alert.rule_id != "WIN-CHAIN-001":
            continue
        for item in alert.evidence:
            if item.startswith("目标账户:"):
                return item.split(":", 1)[1].strip()
    return ""


def _confidence(
    events: Sequence[LogEvent],
    alerts: Sequence[DetectionAlert],
    source_types: Sequence[str],
    families: Sequence[str],
) -> str:
    if any(alert.rule_id == "WIN-CHAIN-001" for alert in alerts):
        return "high"
    if len(source_types) >= 3 or (len(source_types) >= 2 and len(families) >= 3):
        return "high"
    if len(source_types) >= 2 or len(alerts) >= 2 or len(events) >= 5:
        return "medium"
    return "low"


def _title(
    source_ips: Sequence[str],
    accounts: Sequence[str],
    assets: Sequence[str],
    source_types: Sequence[str],
    phases: Sequence[str],
    level: ThreatLevel,
    alerts: Sequence[DetectionAlert],
) -> str:
    if any(alert.rule_id == "WIN-CHAIN-001" for alert in alerts):
        account = _chain_account(alerts) or _first_human(accounts)
        return f"可疑本地管理员账号与远程登录: {account}" if account else "可疑本地管理员账号与远程登录"
    subject = source_ips[0] if source_ips else (assets[0] if assets else "未知实体")
    if len(source_types) >= 2:
        return f"P0 多源关联案件: {subject}"
    if phases:
        return f"{level.label}案件: {subject} / {phases[0]}"
    return f"{level.label}案件: {subject}"


def _description(
    source_ips: Sequence[str],
    accounts: Sequence[str],
    assets: Sequence[str],
    operators: Sequence[str],
    workstations: Sequence[str],
    source_types: Sequence[str],
    phases: Sequence[str],
    alerts: Sequence[DetectionAlert],
    events: Sequence[LogEvent],
) -> str:
    subject = source_ips[0] if source_ips else (workstations[0] if workstations else "未知来源")
    if any(alert.rule_id == "WIN-CHAIN-001" for alert in alerts):
        return (
            f"{subject} 关联到 Windows 账号创建、特权组加入和远程登录链路；"
            f"核心账号: {_chain_account(alerts) or _first_human(accounts) or '?'}；"
            f"操作者: {', '.join(operators[:3]) or '?'}；"
            f"来源工作站: {', '.join(workstations[:3]) or '?'}；"
            f"资产: {', '.join(assets[:5]) or '?'}；"
            f"阶段: {', '.join(phases[:6]) or '未分类'}。"
        )
    return (
        f"{subject} 在 {len(source_types) or 1} 类日志源中关联到 "
        f"{len(alerts)} 个告警、{len(events)} 条关键事件；"
        f"阶段: {', '.join(phases[:6]) or '未分类'}；"
        f"资产: {', '.join(assets[:5]) or '?'}；"
        f"账号: {', '.join(accounts[:5]) or '?'}。"
    )


def _timeline(events: Sequence[LogEvent]) -> List[TimelineEntry]:
    ordered = sorted(events, key=lambda event: event.timestamp or "")
    return [
        TimelineEntry(
            timestamp=event.timestamp,
            level=event.level,
            category=event.category,
            message=event.message,
            event_id=event.id,
            source_file=event.source_file,
            mitre_attack=event.mitre_attack,
        )
        for event in ordered[:30]
    ]


def _evidence(
    events: Sequence[LogEvent],
    alerts: Sequence[DetectionAlert],
    source_ips: Sequence[str],
    accounts: Sequence[str],
    assets: Sequence[str],
    operators: Sequence[str],
    workstations: Sequence[str],
    source_types: Sequence[str],
    phases: Sequence[str],
) -> List[str]:
    evidence = []
    if accounts:
        evidence.append(f"核心账号: {', '.join(_human_accounts(accounts)[:5])}")
    if operators:
        evidence.append(f"操作者: {', '.join(operators[:5])}")
    if source_ips:
        evidence.append(f"来源IP: {', '.join(source_ips[:5])}")
    if workstations:
        evidence.append(f"来源工作站: {', '.join(workstations[:5])}")
    if assets:
        evidence.append(f"资产: {', '.join(assets[:5])}")
    evidence.extend([
        f"日志源: {', '.join(source_types) or '?'}",
        f"攻击阶段: {', '.join(phases) or '?'}",
        f"关联告警: {len(alerts)} 个",
        f"关键事件: {len(events)} 条",
    ])
    for alert in alerts[:3]:
        evidence.append(f"{alert.rule_id}: {alert.rule_name} ({alert.level.label})")
    for event in sorted(events, key=lambda item: item.timestamp or "")[:3]:
        source_type = event.details.get("source_type") or event.source
        evidence.append(f"{event.timestamp or '?'} {source_type}: {event.message}")
    return evidence


def _recommended_actions(source_types: Sequence[str], families: Sequence[str], level: ThreatLevel) -> List[str]:
    actions = []
    if level.score >= ThreatLevel.CRITICAL.score or "compromise" in families:
        actions.append("优先隔离疑似失陷主机，保全内存、进程树、网络连接和关键日志。")
    if "initial-access" in families or "waf" in source_types:
        actions.append("核查入口 URL、漏洞命中规则和应用同时间窗口异常，确认是否利用成功。")
    if "identity" in families or "vpn" in source_types:
        actions.append("核查账号登录源、MFA 状态和登录后操作，必要时冻结账号并重置凭据。")
    if "persistence" in families or "privilege-escalation" in families or "remote-access" in families:
        actions.append("禁用可疑新建账号，移出特权组，核查 RDP/NTLM 来源工作站和同时间窗口管理员操作。")
    if "command-control" in families or "proxy" in source_types or "dns" in source_types:
        actions.append("封禁恶意域名/IP，回溯 DNS、代理和防火墙外联链路。")
    if "exfiltration" in families:
        actions.append("核查外发对象、账号、文件范围和业务影响，启动数据泄露评估。")
    if not actions:
        actions.append("围绕同源 IP、账号和资产继续补采日志，确认是否存在后续动作。")
    return actions


def _next_logs(source_types: Sequence[str], families: Sequence[str]) -> List[str]:
    wanted = []
    if "waf" in source_types or "initial-access" in families:
        wanted.extend(["Web access/error 日志", "业务应用日志", "WAF 原始命中详情"])
    if "identity" in families:
        wanted.extend(["VPN/SSO/MFA 审计", "AD/域控 Security 日志", "堡垒机会话审计"])
    if "persistence" in families or "privilege-escalation" in families or "remote-access" in families:
        wanted.extend(["Windows Security 4720/4722/4724/4732/4624/4776", "TerminalServices RDP 会话日志", "EDR/XDR 进程树", "防火墙/NAT 会话日志"])
    if "compromise" in families or "execution" in families:
        wanted.extend(["EDR/XDR 进程树", "Windows Sysmon", "Linux auditd/auth.log"])
    if "command-control" in families or "network" in families:
        wanted.extend(["DNS 解析日志", "出口代理/SWG 日志", "防火墙/NAT 会话日志"])
    if "exfiltration" in families:
        wanted.extend(["DLP/数据库审计", "对象存储/文件服务器访问日志"])
    if not wanted:
        wanted.extend(["同时间窗口 P0 日志源", "资产 CMDB/变更记录"])
    return sorted(dict.fromkeys(wanted))
