"""
威胁检测引擎核心逻辑
"""
from __future__ import annotations
import datetime
import re
from collections import defaultdict
from typing import List, Dict, Optional, Set, Tuple

from .. import config
from ..models import (
    LogEvent, DetectionAlert, TimelineEntry, AttackChainEntry,
    AnalysisSummary, ThreatLevel
)
from ..utils.helpers import gen_id, is_private_ip
from .correlation import correlate_incidents
from .enrichment import enrich_events
from .registry import DetectorRegistry, DetectorSpec, normalize_profiles


_CONFIDENCE_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}
_WINDOWS_ACCOUNT_CHAIN_WINDOW_SECONDS = 10 * 60


def _adjust_for_private_ip(ip: str, confidence: str, evidence: List[str]) -> str:
    """如果攻击源是私有 IP，置信度下调一档并在 evidence 里标注来源类型。

    内网渗透测试、扫描器、合法运维操作经常会触发同样的特征，但风险显著低于
    互联网攻击。降级而不是直接抑制，是为了让蓝队仍然能看到事件。
    """
    if not ip or not is_private_ip(ip):
        if ip:
            evidence.append(f"来源类型: 公网")
        return confidence
    evidence.append(f"来源类型: 内网/私有 IP（{ip}）")
    return _CONFIDENCE_DOWNGRADE.get(confidence, confidence)


def run_detection(
    events: List[LogEvent],
    profile: str = "default",
    pre_enriched: bool = False,
    detector_registry: Optional[DetectorRegistry] = None,
) -> AnalysisSummary:
    if not pre_enriched:
        events = enrich_events(events)
    alerts: List[DetectionAlert] = []
    registry = detector_registry or get_default_detector_registry()
    for detector in registry.list(profile):
        alerts += detector.run(events)
    alerts = _dedup_alerts(alerts)

    lvl_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda a: lvl_order.get(a.level.value, 9))

    timeline     = _build_timeline(events)
    attack_chain = _build_attack_chain(events, alerts)
    incidents    = correlate_incidents(events, alerts)
    risk_score   = _calc_risk_score(events, alerts, incidents, attack_chain)
    risk_level   = (ThreatLevel.CRITICAL if risk_score >= 80 else
                    ThreatLevel.HIGH     if risk_score >= 60 else
                    ThreatLevel.MEDIUM   if risk_score >= 40 else
                    ThreatLevel.LOW      if risk_score >= 20 else
                    ThreatLevel.INFO)
    recommendations = _gen_recommendations(alerts)

    return AnalysisSummary(
        risk_score      = risk_score,
        risk_level      = risk_level,
        alerts          = alerts,
        timeline        = timeline,
        attack_chain    = attack_chain,
        recommendations = recommendations,
        total_events    = len(events),
        files_analyzed  = len(set(e.source_file for e in events)),
        incidents       = incidents,
    )


def detect_brute_force(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    failed_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if any(t in ev.tags for t in ("failed-login", "failed-logon")) and ev.ip:
            failed_by_ip[ev.ip].append(ev)
    for ip, evts in failed_by_ip.items():
        n = len(evts)
        if n < config.THRESHOLDS.brute_force_min:
            continue
        if n >= config.THRESHOLDS.brute_force_critical:
            level = ThreatLevel.CRITICAL
        elif n >= config.THRESHOLDS.brute_force_high:
            level = ThreatLevel.HIGH
        else:
            level = ThreatLevel.MEDIUM
        users = sorted(set(e.user for e in evts if e.user))
        ts_sorted = sorted(evts, key=lambda e: e.timestamp)
        evidence = [f"攻击源IP: {ip}", f"失败次数: {n}", f"目标账户数: {len(users)}",
                    f"时间: {ts_sorted[0].timestamp} ~ {ts_sorted[-1].timestamp}"]
        confidence = _adjust_for_private_ip(
            ip, "high" if n >= config.THRESHOLDS.brute_force_high else "medium", evidence
        )
        alerts.append(DetectionAlert(
            id="a"+gen_id("bf"), rule_id="BRUTE-001", rule_name="暴力破解攻击",
            description=f"来自 {ip} 的暴力破解，共失败 {n} 次，目标: {', '.join(users[:5])}{'...' if len(users)>5 else ''}",
            level=level, category="暴力破解", mitre_attack="T1110.001", mitre_phase="凭据访问",
            affected_events=[e.id for e in evts],
            evidence=evidence,
            recommendation=f"立即封锁 IP {ip}，检查是否有成功登录，启用账户锁定策略和 MFA",
            timestamp=ts_sorted[-1].timestamp, confidence=confidence,
        ))
    return alerts


def detect_password_spray(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    failed_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if any(t in ev.tags for t in ("failed-login", "failed-logon")) and ev.ip and ev.user:
            failed_by_ip[ev.ip].append(ev)
    for ip, evts in failed_by_ip.items():
        unique_users = set(e.user for e in evts if e.user)
        if len(unique_users) < config.THRESHOLDS.spray_min_unique_users:
            continue
        avg = len(evts) / len(unique_users)
        if avg > config.THRESHOLDS.spray_max_avg_per_user:
            continue
        evidence = [f"攻击源IP: {ip}", f"目标账户数: {len(unique_users)}", f"总尝试: {len(evts)}",
                    f"目标: {', '.join(list(unique_users)[:5])}"]
        confidence = _adjust_for_private_ip(ip, "high", evidence)
        alerts.append(DetectionAlert(
            id="a"+gen_id("sp"), rule_id="SPRAY-001", rule_name="密码喷洒攻击",
            description=f"来自 {ip} 的密码喷洒，针对 {len(unique_users)} 个账户，平均每账户 {avg:.1f} 次",
            level=ThreatLevel.HIGH, category="密码喷洒", mitre_attack="T1110.003", mitre_phase="凭据访问",
            affected_events=[e.id for e in evts],
            evidence=evidence,
            recommendation="密码喷洒绕过锁定策略，检查所有目标账户是否有成功登录，实施异常登录检测",
            timestamp=max(e.timestamp for e in evts), confidence=confidence,
        ))
    return alerts


def detect_windows_account_remote_access_chain(events: List[LogEvent]) -> List[DetectionAlert]:
    """Detect newly created Windows accounts that quickly become remote admin access."""
    alerts: List[DetectionAlert] = []
    created = [
        event for event in events
        if event.event_id == "4720"
        and "account-creation" in event.tags
        and event.details.get("account_sensitivity") != "system-initialization"
    ]
    privileged_groups = [
        event for event in events
        if event.event_id in ("4728", "4732", "4756")
        and "group-add" in event.tags
        and event.details.get("group_sensitivity") == "privileged"
    ]
    remote_logons = [
        event for event in events
        if event.event_id == "4624"
        and "successful-login" in event.tags
        and str(event.details.get("LogonType", "")).strip() in {"3", "10"}
    ]
    ntlm_success = [
        event for event in events
        if event.event_id == "4776"
        and (event.details.get("credential_validation_result") == "success" or event.details.get("auth_result") == "success")
    ]
    account_changes = [
        event for event in events
        if event.event_id in ("4722", "4724", "4738")
    ]

    seen: Set[Tuple[str, str, str]] = set()
    for create_event in created:
        create_ts = _event_datetime(create_event)
        if create_ts is None:
            continue
        target_account = _target_account(create_event)
        target_user = create_event.details.get("target_user") or target_account
        target_sid = create_event.details.get("target_sid", "")
        account_key = _account_key(target_account or target_user)
        if not account_key and not target_sid:
            continue

        matching_groups = [
            event for event in privileged_groups
            if _matches_windows_account(event, account_key, target_sid)
            and _seconds_between(create_event, event) is not None
            and 0 <= _seconds_between(create_event, event) <= _WINDOWS_ACCOUNT_CHAIN_WINDOW_SECONDS
        ]
        for group_event in matching_groups:
            matching_logons = [
                event for event in remote_logons
                if _matches_windows_account(event, account_key, target_sid)
                and _seconds_between(group_event, event) is not None
                and 0 <= _seconds_between(group_event, event) <= _WINDOWS_ACCOUNT_CHAIN_WINDOW_SECONDS
            ]
            if not matching_logons:
                continue
            matching_logons.sort(key=lambda item: (str(item.details.get("LogonType")) != "10", item.timestamp or ""))
            logon_event = matching_logons[0]
            chain_key = (create_event.id, group_event.id, logon_event.id)
            if chain_key in seen:
                continue
            seen.add(chain_key)

            end_event = logon_event
            related = _account_events_before(events, create_event, account_key, target_sid, window_seconds=15 * 60)
            related.append(create_event)
            related.extend(_account_events_between(account_changes, create_event, end_event, account_key, target_sid))
            related.append(group_event)
            related.extend(_account_events_between(ntlm_success, create_event, end_event, account_key, target_sid))
            related.append(logon_event)
            related = _dedup_events_by_id(sorted(related, key=lambda item: item.timestamp or ""))

            operator = create_event.details.get("subject_account") or create_event.details.get("operator_account") or create_event.user or "?"
            group = group_event.details.get("group_account") or group_event.details.get("group_name") or "?"
            source_ip = logon_event.details.get("source_ip") or logon_event.ip or "?"
            workstation = _best_remote_workstation(related, logon_event.host) or logon_event.details.get("workstation") or "?"
            logon_type = logon_event.details.get("LogonType") or "?"
            logon_label = logon_event.details.get("logon_type_label") or "未知"
            window_seconds = _seconds_between(create_event, logon_event)

            display_account = target_account or target_user or "?"
            for event in related:
                event.details["account"] = display_account
                event.details.setdefault("target_account", display_account)
                if target_sid:
                    event.details.setdefault("target_sid", target_sid)
                if operator != "?":
                    event.details.setdefault("operator_account", operator)
                if workstation != "?":
                    event.details.setdefault("source_workstation", workstation)
                if event is group_event:
                    event.details["member_account"] = display_account

            evidence = [
                f"目标账户: {display_account}",
                f"操作者: {operator}",
                f"目标组: {group}",
                f"来源IP: {source_ip}",
                f"来源工作站: {workstation}",
                f"登录类型: {logon_type}({logon_label})",
                f"时间窗口: {int(window_seconds or 0)} 秒",
                "链路: 账户创建 -> 账号启用/密码变更 -> 特权组加入 -> NTLM/远程登录",
            ]
            alerts.append(DetectionAlert(
                id="a"+gen_id("wc"),
                rule_id="WIN-CHAIN-001",
                rule_name="新建账户加入管理员组后发生远程登录",
                description=(
                    f"Windows 账号 {display_account} 被 {operator} 创建并加入 {group}，"
                    f"随后从 {source_ip if source_ip != '?' else workstation} 发生远程登录"
                ),
                level=ThreatLevel.CRITICAL,
                category="Windows 账号接管",
                mitre_attack="T1021.001",
                mitre_phase="横向移动",
                affected_events=[event.id for event in related],
                evidence=evidence,
                recommendation=(
                    f"立即核查并禁用/隔离账号 {display_account}，移出特权组 {group}，"
                    f"回溯来源 {source_ip}/{workstation} 的 RDP、NTLM、EDR 和防火墙日志。"
                ),
                timestamp=logon_event.timestamp,
                confidence="high" if source_ip != "?" or workstation != "?" else "medium",
            ))
    return alerts


def detect_privilege_escalation(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    group_events = [
        e for e in events
        if any(t in e.tags for t in ("group-add",))
        and e.event_id in ("4728","4732","4756")
        and e.details.get("group_sensitivity") == "privileged"
    ]
    for ev in group_events:
        operator = ev.details.get("subject_account") or ev.details.get("subject_user") or ev.user or "?"
        group = ev.details.get("group_account") or ev.details.get("group_name") or "?"
        member = ev.details.get("member_name") or ev.details.get("member_sid") or "?"
        alerts.append(DetectionAlert(
            id="a"+gen_id("pe"), rule_id="PRIV-001", rule_name="账户添加到特权组",
            description=ev.message, level=ThreatLevel.HIGH, category="权限提升",
            mitre_attack="T1098.001", mitre_phase="权限提升", affected_events=[ev.id],
            evidence=[
                ev.message,
                f"操作者: {operator}",
                f"目标组: {group}",
                f"成员: {member}",
                f"证据强度: {ev.details.get('evidence_strength') or 'high'}",
                f"时间: {ev.timestamp}",
            ],
            recommendation="验证此操作是否经过授权，检查添加的账户是否为合法管理员",
            timestamp=ev.timestamp, confidence="high",
        ))
    sudo_denied = [e for e in events if "sudo-denied" in e.tags]
    if len(sudo_denied) >= config.THRESHOLDS.sudo_denied_min:
        alerts.append(DetectionAlert(
            id="a"+gen_id("sd"), rule_id="PRIV-002", rule_name="Sudo 权限滥用尝试",
            description=f"检测到 {len(sudo_denied)} 次 sudo 权限拒绝",
            level=ThreatLevel.HIGH, category="权限提升", mitre_attack="T1548.003", mitre_phase="权限提升",
            affected_events=[e.id for e in sudo_denied], evidence=[e.message for e in sudo_denied[:3]],
            recommendation="检查被拒绝的 sudo 命令，审查 sudoers 配置",
            timestamp=max(e.timestamp for e in sudo_denied), confidence="medium",
        ))
    root_logins = [e for e in events if "root-login" in e.tags]
    if root_logins:
        alerts.append(DetectionAlert(
            id="a"+gen_id("rl"), rule_id="PRIV-003", rule_name="Root 账户直接登录",
            description=f"检测到 {len(root_logins)} 次 root 直接登录",
            level=ThreatLevel.HIGH, category="权限提升", mitre_attack="T1078.003", mitre_phase="权限提升",
            affected_events=[e.id for e in root_logins],
            evidence=[f"{e.timestamp}: {e.message}" for e in root_logins[:3]],
            recommendation="禁止 root 直接 SSH 登录 (PermitRootLogin no)，使用普通账户 sudo 提权",
            timestamp=max(e.timestamp for e in root_logins), confidence="high",
        ))
    return alerts


def detect_persistence(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    for ev in [e for e in events if "service-install" in e.tags]:
        alerts.append(DetectionAlert(
            id="a"+gen_id("ps"), rule_id="PERS-001", rule_name="安装新系统服务",
            description=ev.message, level=ThreatLevel.HIGH, category="持久化",
            mitre_attack="T1543.003", mitre_phase="持久化", affected_events=[ev.id],
            evidence=[ev.message, f"时间: {ev.timestamp}"],
            recommendation="验证服务合法性，检查服务二进制路径",
            timestamp=ev.timestamp, confidence="medium",
        ))
    for ev in [e for e in events if "scheduled-task" in e.tags and e.event_id == "4698"]:
        alerts.append(DetectionAlert(
            id="a"+gen_id("pt"), rule_id="PERS-002", rule_name="创建计划任务",
            description=ev.message, level=ThreatLevel.HIGH, category="持久化",
            mitre_attack="T1053.005", mitre_phase="持久化", affected_events=[ev.id],
            evidence=[ev.message, f"创建者: {ev.user or '?'}"],
            recommendation="检查计划任务执行内容，验证是否为合法维护任务",
            timestamp=ev.timestamp, confidence="medium",
        ))
    for ev in [e for e in events if "account-creation" in e.tags and e.details.get("account_sensitivity") != "system-initialization"]:
        target = ev.details.get("target_account") or ev.details.get("target_user") or ev.user or "?"
        operator = ev.details.get("subject_account") or ev.details.get("subject_user") or "?"
        alerts.append(DetectionAlert(
            id="a"+gen_id("pa"), rule_id="PERS-003", rule_name="创建新用户账户",
            description=ev.message, level=ThreatLevel.HIGH, category="持久化",
            mitre_attack="T1136", mitre_phase="持久化", affected_events=[ev.id],
            evidence=[
                ev.message,
                f"目标账户: {target}",
                f"操作者: {operator}",
                f"证据强度: {ev.details.get('evidence_strength') or 'high'}",
                f"时间: {ev.timestamp}",
            ],
            recommendation="验证新账户合法性，检查创建者身份",
            timestamp=ev.timestamp, confidence="high",
        ))
    return alerts


def detect_defense_evasion(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    log_clear = [e for e in events if "log-cleared" in e.tags]
    if log_clear:
        alerts.append(DetectionAlert(
            id="a"+gen_id("de"), rule_id="EVAS-001", rule_name="日志清除 - 反取证行为",
            description=f"检测到 {len(log_clear)} 次日志清除操作，典型反取证行为",
            level=ThreatLevel.CRITICAL, category="防御规避",
            mitre_attack="T1070.001", mitre_phase="防御规避",
            affected_events=[e.id for e in log_clear],
            evidence=[f"{e.timestamp}: {e.message}" for e in log_clear],
            recommendation="立即保存所有现有日志，检查备份日志，攻击者可能正在清理痕迹",
            timestamp=max(e.timestamp for e in log_clear), confidence="high",
        ))
    audit_change = [e for e in events if "audit-policy" in e.tags]
    if audit_change:
        alerts.append(DetectionAlert(
            id="a"+gen_id("ap"), rule_id="EVAS-002", rule_name="审计策略修改",
            description="检测到审计策略被修改，可能用于减少日志记录",
            level=ThreatLevel.CRITICAL, category="防御规避",
            mitre_attack="T1562.002", mitre_phase="防御规避",
            affected_events=[e.id for e in audit_change],
            evidence=[e.message for e in audit_change],
            recommendation="立即恢复审计策略，检查是否有其他防御规避行为",
            timestamp=max(e.timestamp for e in audit_change), confidence="high",
        ))
    return alerts


def detect_credential_access(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    mimi = [e for e in events if
            re.search(r'mimikatz|lsadump|sekurlsa|kerberos::ptt|privilege::debug|credential.?dump',
                      e.message + e.raw_line + " ".join(str(v) for v in e.details.values()), re.I)]
    if mimi:
        alerts.append(DetectionAlert(
            id="a"+gen_id("ca"), rule_id="CRED-001", rule_name="Mimikatz / 凭据转储工具",
            description="检测到 Mimikatz 或类似凭据转储工具特征",
            level=ThreatLevel.CRITICAL, category="凭据访问",
            mitre_attack="T1003.001", mitre_phase="凭据访问",
            affected_events=[e.id for e in mimi], evidence=[e.message for e in mimi[:3]],
            recommendation="立即隔离受影响主机，所有账户密码视为已泄露，强制重置所有凭据",
            timestamp=max(e.timestamp for e in mimi), confidence="high",
        ))
    lsass = [e for e in events if "lsass-dump" in e.tags or
             (re.search(r'lsass', e.message + e.raw_line, re.I) and "sysmon" in e.tags)]
    if lsass:
        alerts.append(DetectionAlert(
            id="a"+gen_id("ls"), rule_id="CRED-002", rule_name="LSASS 进程访问",
            description="检测到对 LSASS 进程的访问，可能存在凭据转储",
            level=ThreatLevel.CRITICAL, category="凭据访问",
            mitre_attack="T1003.001", mitre_phase="凭据访问",
            affected_events=[e.id for e in lsass], evidence=[e.message for e in lsass[:3]],
            recommendation="启用 Windows Credential Guard，检查访问 LSASS 的进程是否合法",
            timestamp=max(e.timestamp for e in lsass), confidence="high",
        ))
    return alerts


def detect_suspicious_execution(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    critical_ps = [e for e in events if e.category == "PowerShell" and e.level == ThreatLevel.CRITICAL]
    if critical_ps:
        alerts.append(DetectionAlert(
            id="a"+gen_id("ex"), rule_id="EXEC-001", rule_name="高危 PowerShell 执行",
            description=f"检测到 {len(critical_ps)} 个高危 PowerShell 脚本（含混淆/下载/绕过特征）",
            level=ThreatLevel.CRITICAL, category="执行",
            mitre_attack="T1059.001", mitre_phase="执行",
            affected_events=[e.id for e in critical_ps], evidence=[e.message for e in critical_ps[:3]],
            recommendation="检查 PS 脚本内容，启用脚本块日志，考虑启用 AMSI 和 CLM",
            timestamp=max(e.timestamp for e in critical_ps), confidence="high",
        ))
    lolbins = [e for e in events if "lolbin" in e.tags]
    if lolbins:
        alerts.append(DetectionAlert(
            id="a"+gen_id("lb"), rule_id="EXEC-002", rule_name="Living-off-the-Land (LOLBins)",
            description=f"检测到 {len(lolbins)} 个系统工具滥用行为",
            level=ThreatLevel.HIGH, category="执行",
            mitre_attack="T1218", mitre_phase="执行",
            affected_events=[e.id for e in lolbins], evidence=[e.message for e in lolbins[:3]],
            recommendation="检查 LOLBins 命令行参数，验证是否为合法系统管理操作",
            timestamp=max(e.timestamp for e in lolbins), confidence="medium",
        ))
    return alerts


def detect_lateral_movement(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    rdp = [e for e in events if "rdp" in e.tags and "lateral-movement" in e.tags]
    if rdp:
        unique_hosts = set(e.host for e in rdp if e.host)
        if len(unique_hosts) > 1 or len(rdp) > 3:
            alerts.append(DetectionAlert(
                id="a"+gen_id("lm"), rule_id="LAT-001", rule_name="RDP 横向移动",
                description=f"检测到 RDP 横向移动，涉及 {len(unique_hosts)} 台主机，{len(rdp)} 个连接",
                level=ThreatLevel.HIGH, category="横向移动",
                mitre_attack="T1021.001", mitre_phase="横向移动",
                affected_events=[e.id for e in rdp], evidence=[e.message for e in rdp[:3]],
                recommendation="检查 RDP 连接源 IP 和目标主机，确认是否为授权的远程管理",
                timestamp=max(e.timestamp for e in rdp), confidence="medium",
            ))
    explicit = [
        e for e in events
        if "explicit-creds" in e.tags
        and e.details.get("credential_use_scope") != "local-system"
    ]
    if len(explicit) >= 3:
        targets = sorted(set(e.details.get("TargetServerName","") for e in explicit if e.details.get("TargetServerName")))
        alerts.append(DetectionAlert(
            id="a"+gen_id("ec"), rule_id="LAT-002", rule_name="显式凭据远程使用异常",
            description=f"检测到 {len(explicit)} 次显式凭据使用，目标: {', '.join(targets[:3])}",
            level=ThreatLevel.HIGH, category="横向移动",
            mitre_attack="T1550.002", mitre_phase="横向移动",
            affected_events=[e.id for e in explicit], evidence=[e.message for e in explicit[:3]],
            recommendation="检查凭据使用模式、源 IP 和目标主机；仅凭 4648 不能直接定性 Pass-the-Hash，需要结合网络/RDP/SMB/EDR 证据。",
            timestamp=max(e.timestamp for e in explicit), confidence="medium",
        ))
    return alerts


def detect_web_attacks(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    web_attacks = [e for e in events if "web-attack" in e.tags]
    if not web_attacks:
        return alerts
    by_type: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in web_attacks:
        by_type[ev.rule_name or "未知攻击"].append(ev)
    mitre_map = {
        "SQL注入":"T1190","XSS攻击":"T1059.007","LFI/RFI":"T1083",
        "命令注入/代码执行":"T1059","RFI攻击":"T1190","路径遍历":"T1083",
        "Webshell特征":"T1505.003","安全扫描器":"T1595","时间盲注":"T1190",
        "路径/编码绕过":"T1140",
    }
    for attack_type, evts in by_type.items():
        max_event_level = max((e.level for e in evts), key=lambda lvl: lvl.score)
        level = max_event_level
        if len(evts) >= 10 and level.score < ThreatLevel.HIGH.score:
            level = ThreatLevel.HIGH
        ips = sorted(set(e.ip for e in evts if e.ip))
        event_rule_ids = sorted(set(e.rule_id for e in evts if e.rule_id))
        alert_rule_id = event_rule_ids[0] if len(event_rule_ids) == 1 else f"WEB-{attack_type[:4].upper()}"
        remediation = next((str(e.details.get("rule_remediation")) for e in evts if e.details.get("rule_remediation")), "")
        confidence_hint = next((str(e.details.get("rule_confidence")) for e in evts if e.details.get("rule_confidence")), "")
        fp_hints = next((str(e.details.get("rule_false_positive_hints")) for e in evts if e.details.get("rule_false_positive_hints")), "")
        evidence = [f"类型: {attack_type}", f"次数: {len(evts)}",
                    f"来源IP: {', '.join(ips[:3])}", f"示例: {evts[0].message}"]
        if fp_hints:
            evidence.append(f"误报提示: {fp_hints.replace('|', ', ')}")
        alerts.append(DetectionAlert(
            id="a"+gen_id("wa"), rule_id=alert_rule_id,
            rule_name=f"Web攻击: {attack_type}",
            description=f"检测到 {len(evts)} 次 {attack_type} 攻击尝试",
            level=level, category="Web攻击",
            mitre_attack=mitre_map.get(attack_type,"T1190"), mitre_phase="初始访问",
            affected_events=[e.id for e in evts],
            evidence=evidence,
            recommendation=remediation or f"修复 {attack_type} 漏洞，部署 WAF，封锁攻击源 IP",
            timestamp=max(e.timestamp for e in evts),
            confidence=confidence_hint or ("high" if level.score >= ThreatLevel.HIGH.score else "medium"),
        ))
    return alerts


def detect_reconnaissance(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    volume_events = [e for e in events if e.category == "流量异常" and any(t in e.tags for t in ("scanning", "ddos"))]
    if volume_events:
        has_ddos = any("ddos" in e.tags for e in volume_events)
        ips = sorted(set(e.ip for e in volume_events if e.ip))
        level = ThreatLevel.CRITICAL if has_ddos else ThreatLevel.MEDIUM
        alerts.append(DetectionAlert(
            id="a"+gen_id("rv"), rule_id="RECON-003" if not has_ddos else "RECON-004",
            rule_name="DDoS/高频请求" if has_ddos else "自动化扫描/高频访问",
            description=f"检测到 {len(ips)} 个 IP 存在异常高频 Web 请求",
            level=level, category="侦察", mitre_attack="T1595", mitre_phase="侦察",
            affected_events=[e.id for e in volume_events],
            evidence=[e.message for e in volume_events[:5]],
            recommendation="结合访问路径和业务基线确认是否为扫描、爬取或洪泛攻击，必要时限速或封锁源 IP",
            timestamp=max(e.timestamp for e in volume_events), confidence="medium",
        ))

    scan_events = [e for e in events if e.category != "流量异常" and any(t in e.tags for t in ("scanning","scanner"))]
    if len(scan_events) >= config.THRESHOLDS.scanner_min_events:
        scan_ips = sorted(set(e.ip for e in scan_events if e.ip))
        alerts.append(DetectionAlert(
            id="a"+gen_id("rc"), rule_id="RECON-001", rule_name="自动化扫描/侦察",
            description=f"检测到来自 {len(scan_ips)} 个 IP 的自动化扫描，共 {len(scan_events)} 个请求",
            level=ThreatLevel.MEDIUM, category="侦察",
            mitre_attack="T1595", mitre_phase="侦察",
            affected_events=[e.id for e in scan_events],
            evidence=[f"扫描IP: {', '.join(scan_ips[:5])}", f"请求数: {len(scan_events)}"],
            recommendation="封锁扫描源 IP，检查是否有漏洞被成功利用",
            timestamp=max(e.timestamp for e in scan_events), confidence="medium",
        ))
    recon_events = [e for e in events if "recon" in e.tags]
    if len(recon_events) >= config.THRESHOLDS.recon_min_events:
        alerts.append(DetectionAlert(
            id="a"+gen_id("rf"), rule_id="RECON-002", rule_name="敏感文件/路径探测",
            description=f"检测到 {len(recon_events)} 次敏感文件探测",
            level=ThreatLevel.MEDIUM, category="侦察",
            mitre_attack="T1083", mitre_phase="侦察",
            affected_events=[e.id for e in recon_events],
            evidence=[e.message for e in recon_events[:3]],
            recommendation="确保敏感文件不可公开访问，部署蜜罐文件",
            timestamp=max(e.timestamp for e in recon_events), confidence="medium",
        ))
    return alerts


def detect_cn_hvv(events: List[LogEvent]) -> List[DetectionAlert]:
    """国内护网/重保常见场景增强检测。"""
    alerts = []

    hvv_events = [e for e in events if "cn-hvv" in e.tags]
    if hvv_events:
        ips = sorted(set(e.ip for e in hvv_events if e.ip))
        names = sorted(set(e.rule_name or e.category for e in hvv_events))
        alerts.append(DetectionAlert(
            id="a"+gen_id("hv"), rule_id="CN-HVV-001", rule_name="护网/重保高频漏洞利用",
            description=f"检测到 {len(hvv_events)} 条国内实战高频漏洞或 Webshell 相关痕迹",
            level=ThreatLevel.CRITICAL, category="护网画像",
            mitre_attack="T1190", mitre_phase="初始访问",
            affected_events=[e.id for e in hvv_events],
            evidence=[
                f"类型: {', '.join(names[:5])}",
                f"来源IP: {', '.join(ips[:5]) or '?'}",
                f"示例: {hvv_events[0].message}",
            ],
            recommendation="优先核查命中路径是否存在真实漏洞或 Webshell，检查同源 IP 后续登录、命令执行、文件上传和出网行为",
            timestamp=max(e.timestamp for e in hvv_events), confidence="high",
        ))

    failed_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    success_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.ip and any(t in ev.tags for t in ("failed-login", "failed-logon")):
            failed_by_ip[ev.ip].append(ev)
        if ev.ip and "successful-login" in ev.tags:
            success_by_ip[ev.ip].append(ev)

    for ip, successes in success_by_ip.items():
        failures = failed_by_ip.get(ip, [])
        if len(failures) < 5:
            continue
        evts = failures + successes
        alerts.append(DetectionAlert(
            id="a"+gen_id("hs"), rule_id="CN-HVV-002", rule_name="爆破后成功登录",
            description=f"来源 {ip} 在 {len(failures)} 次失败登录后出现 {len(successes)} 次成功登录",
            level=ThreatLevel.CRITICAL, category="护网画像",
            mitre_attack="T1078", mitre_phase="初始访问",
            affected_events=[e.id for e in evts],
            evidence=[
                f"失败次数: {len(failures)}",
                f"成功账户: {', '.join(sorted(set(e.user for e in successes if e.user))[:5]) or '?'}",
                f"时间: {min(e.timestamp for e in evts)} ~ {max(e.timestamp for e in evts)}",
            ],
            recommendation="立即核查成功登录账户、登录源和后续操作，必要时冻结账户并重置凭据",
            timestamp=max(e.timestamp for e in evts), confidence="high",
        ))

    return alerts


def detect_p0_security_events(events: List[LogEvent]) -> List[DetectionAlert]:
    """聚合 HVV/重保 P0 结构化日志里的高价值安全事件。"""
    alerts: List[DetectionAlert] = []

    _append_p0_alert(
        alerts, events,
        rule_id="P0-C2-001",
        rule_name="P0 可疑命令控制/外联",
        category="命令控制",
        mitre_attack="T1071",
        mitre_phase="命令控制",
        predicate=lambda e: "c2" in e.tags or "dns-tunnel" in e.tags,
        recommendation="优先核查源主机进程、DNS/代理/防火墙同时间窗口外联，必要时隔离主机并封禁域名/IP",
    )
    _append_p0_alert(
        alerts, events,
        rule_id="P0-EXFIL-001",
        rule_name="P0 疑似数据外传",
        category="数据外传",
        mitre_attack="T1041",
        mitre_phase="数据外传",
        predicate=lambda e: "exfiltration" in e.tags,
        recommendation="核查外发账号、源主机、目的地址和传输对象，结合 DLP/代理/防火墙确认数据范围",
    )
    _append_p0_alert(
        alerts, events,
        rule_id="P0-BASTION-001",
        rule_name="P0 堡垒机高危命令/文件操作",
        category="执行",
        mitre_attack="T1059",
        mitre_phase="执行",
        predicate=lambda e: "bastion-command" in e.tags,
        recommendation="回放堡垒机会话，确认命令授权来源，核查目标主机文件落地、进程执行和后续外联",
    )
    _append_p0_alert(
        alerts, events,
        rule_id="P0-FW-001",
        rule_name="P0 防火墙敏感端口暴露/访问",
        category="横向移动",
        mitre_attack="T1021",
        mitre_phase="横向移动",
        predicate=lambda e: "exposed-service" in e.tags,
        recommendation="核查策略是否符合重保基线，确认来源是否可信，必要时收敛公网/跨区高危端口访问",
    )
    _append_p0_alert(
        alerts, events,
        rule_id="P0-EDR-001",
        rule_name="P0 EDR/XDR 高危终端告警",
        category="主机告警",
        mitre_attack="T1204",
        mitre_phase="执行",
        predicate=lambda e: "edr" in e.tags and e.level.score >= ThreatLevel.HIGH.score,
        recommendation="优先查看 EDR 进程树、文件 Hash、网络连接和处置动作，必要时隔离终端并导出取证包",
    )

    return alerts


def _append_p0_alert(
    alerts: List[DetectionAlert],
    events: List[LogEvent],
    rule_id: str,
    rule_name: str,
    category: str,
    mitre_attack: str,
    mitre_phase: str,
    predicate,
    recommendation: str,
) -> None:
    evts = [e for e in events if predicate(e)]
    if not evts:
        return
    max_level = max((e.level for e in evts), key=lambda lvl: lvl.score)
    if max_level.score < ThreatLevel.HIGH.score:
        max_level = ThreatLevel.HIGH
    ips = sorted(set(e.ip for e in evts if e.ip))
    hosts = sorted(set(e.host for e in evts if e.host))
    evidence = [
        f"事件数: {len(evts)}",
        f"IP: {', '.join(ips[:5]) or '?'}",
        f"主机/目标: {', '.join(hosts[:5]) or '?'}",
        f"示例: {evts[0].message}",
    ]
    alerts.append(DetectionAlert(
        id="a"+gen_id("p0"),
        rule_id=rule_id,
        rule_name=rule_name,
        description=f"{rule_name}，共 {len(evts)} 条事件",
        level=max_level,
        category=category,
        mitre_attack=mitre_attack,
        mitre_phase=mitre_phase,
        affected_events=[e.id for e in evts],
        evidence=evidence,
        recommendation=recommendation,
        timestamp=max(e.timestamp for e in evts),
        confidence="high" if max_level.score >= ThreatLevel.HIGH.score else "medium",
    ))


def _target_account(event: LogEvent) -> str:
    return event.details.get("target_account") or event.details.get("target_user") or event.details.get("account") or event.user or ""


def _account_key(value: str) -> str:
    value = str(value or "").strip().strip("\\/")
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]
    if "/" in value:
        value = value.rsplit("/", 1)[-1]
    return value.lower()


def _matches_windows_account(event: LogEvent, account_key: str, sid: str) -> bool:
    if sid:
        for key in ("member_sid", "target_sid", "TargetSid", "MemberSid"):
            if str(event.details.get(key) or "").strip().lower() == sid.lower():
                return True
    candidates = [
        event.details.get("account"),
        event.details.get("account_name"),
        event.details.get("target_account"),
        event.details.get("target_user"),
        event.details.get("member_account"),
        event.details.get("member_name"),
        event.user,
    ]
    return bool(account_key and any(_account_key(str(candidate or "")) == account_key for candidate in candidates))


def _account_events_between(
    candidates: List[LogEvent],
    start: LogEvent,
    end: LogEvent,
    account_key: str,
    sid: str,
) -> List[LogEvent]:
    matched = []
    for event in candidates:
        after_start = _seconds_between(start, event)
        before_end = _seconds_between(event, end)
        if after_start is None or before_end is None:
            continue
        if 0 <= after_start and 0 <= before_end and _matches_windows_account(event, account_key, sid):
            matched.append(event)
    return matched


def _account_events_before(
    candidates: List[LogEvent],
    anchor: LogEvent,
    account_key: str,
    sid: str,
    window_seconds: int,
) -> List[LogEvent]:
    matched = []
    for event in candidates:
        if event.id == anchor.id or event.event_id not in ("4720", "4726"):
            continue
        delta = _seconds_between(event, anchor)
        if delta is None:
            continue
        if 0 <= delta <= window_seconds and _matches_windows_account(event, account_key, sid):
            matched.append(event)
    return matched


def _dedup_events_by_id(events: List[LogEvent]) -> List[LogEvent]:
    seen: Set[str] = set()
    result = []
    for event in events:
        if event.id in seen:
            continue
        seen.add(event.id)
        result.append(event)
    return result


def _best_remote_workstation(events: List[LogEvent], local_host: Optional[str]) -> str:
    local = _account_key(local_host or "")
    candidates = []
    for event in events:
        workstation = event.details.get("source_workstation") or event.details.get("workstation") or event.details.get("Workstation")
        value = str(workstation or "").strip()
        if not value or value in {"-", "localhost"}:
            continue
        if local and _account_key(value) == local:
            continue
        candidates.append(value)
    return sorted(set(candidates))[0] if candidates else ""


def _seconds_between(first: LogEvent, second: LogEvent) -> Optional[float]:
    left = _event_datetime(first)
    right = _event_datetime(second)
    if left is None or right is None:
        return None
    return (right - left).total_seconds()


def _event_datetime(event: LogEvent) -> Optional[datetime.datetime]:
    value = event.timestamp
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def _dedup_alerts(alerts: List[DetectionAlert]) -> List[DetectionAlert]:
    """以 (rule_id, 影响事件集合) 为去重 key。

    早期实现用 description 前 50 字做 key，对于不同 IP 但同类描述的告警会
    误删（例如 "检测到 X 次..." 这种通用句式），所以改成基于 affected_events
    的精确去重。
    """
    seen: Set = set()
    result = []
    for a in alerts:
        key = (a.rule_id, tuple(sorted(a.affected_events)))
        if key not in seen:
            seen.add(key)
            result.append(a)
    return result


def _build_timeline(events: List[LogEvent]) -> List[TimelineEntry]:
    significant = [e for e in events if e.level.score >= ThreatLevel.MEDIUM.score or e.mitre_attack]
    def ts_epoch(ts: str) -> float:
        if not ts:
            return 0.0
        s = ts.replace("Z", "+00:00")
        try:
            return datetime.datetime.fromisoformat(s).timestamp()
        except Exception:
            return 0.0

    significant.sort(key=lambda e: (-e.level.score, -ts_epoch(e.timestamp), e.id))
    return [TimelineEntry(timestamp=e.timestamp, level=e.level, category=e.category,
                          message=e.message, event_id=e.id, source_file=e.source_file,
                          mitre_attack=e.mitre_attack)
            for e in significant[:config.THRESHOLDS.timeline_max_items]]


def _build_attack_chain(events: List[LogEvent], alerts: List[DetectionAlert]) -> List[AttackChainEntry]:
    PHASE_MAP = {
        "T1595":"侦察","T1083":"侦察","T1190":"初始访问","T1078":"初始访问",
        "T1059":"执行","T1218":"执行","T1543":"持久化","T1053":"持久化",
        "T1136":"持久化","T1547":"持久化","T1548":"权限提升","T1098":"权限提升",
        "T1070":"防御规避","T1562":"防御规避","T1140":"防御规避",
        "T1003":"凭据访问","T1110":"凭据访问","T1558":"凭据访问",
        "T1021":"横向移动","T1550":"横向移动","T1071":"命令控制","T1505":"命令控制",
    }
    phases: Dict[str, Dict] = {p: {"count":0,"level":ThreatLevel.INFO,"techniques":set()}
                                for p in ["侦察","初始访问","执行","持久化","权限提升","防御规避","凭据访问","横向移动","命令控制"]}

    def update(mitre: str, level: ThreatLevel):
        prefix = mitre.split(".")[0]
        phase  = PHASE_MAP.get(prefix) or PHASE_MAP.get(mitre)
        if phase and phase in phases:
            phases[phase]["count"] += 1
            phases[phase]["techniques"].add(mitre)
            if level.score > phases[phase]["level"].score:
                phases[phase]["level"] = level

    for ev in events:
        if ev.mitre_attack: update(ev.mitre_attack, ev.level)
    for al in alerts:
        if al.mitre_attack: update(al.mitre_attack, al.level)

    return [AttackChainEntry(phase=p, event_count=d["count"], level=d["level"],
                             techniques=sorted(d["techniques"]))
            for p, d in phases.items() if d["count"] > 0]


def _calc_risk_score(
    events: List[LogEvent],
    alerts: List[DetectionAlert],
    incidents=None,
    attack_chain: Optional[List[AttackChainEntry]] = None,
) -> int:
    incidents = incidents or []
    attack_chain = attack_chain or []
    if not events and not alerts and not incidents:
        return 0

    event_score = min(
        18,
        sum(1 for e in events if e.level == ThreatLevel.CRITICAL) * 7
        + sum(1 for e in events if e.level == ThreatLevel.HIGH) * 4
        + sum(1 for e in events if e.level == ThreatLevel.MEDIUM) * 1,
    )

    alert_weights = {
        ThreatLevel.CRITICAL: 34,
        ThreatLevel.HIGH: 22,
        ThreatLevel.MEDIUM: 12,
        ThreatLevel.LOW: 5,
        ThreatLevel.INFO: 1,
    }
    alert_bases = sorted((alert_weights.get(a.level, 0) for a in alerts), reverse=True)
    alert_score = 0
    if alert_bases:
        alert_score += alert_bases[0]
        decay_factors = (0.6, 0.35, 0.2, 0.1)
        for idx, base in enumerate(alert_bases[1:5]):
            factor = decay_factors[idx] if idx < len(decay_factors) else 0.1
            alert_score += int(round(base * factor))
        alert_score = min(52, alert_score)

    incident_weights = {
        ThreatLevel.CRITICAL: 26,
        ThreatLevel.HIGH: 18,
        ThreatLevel.MEDIUM: 10,
        ThreatLevel.LOW: 4,
        ThreatLevel.INFO: 0,
    }
    incident_bases = sorted((incident_weights.get(item.level, 0) for item in incidents), reverse=True)
    incident_score = 0
    if incident_bases:
        incident_score += incident_bases[0]
        for idx, base in enumerate(incident_bases[1:4]):
            factor = (0.5, 0.25, 0.15)[idx]
            incident_score += int(round(base * factor))
        incident_score = min(30, incident_score)

    confidence_score = min(
        10,
        sum(4 for item in incidents if item.confidence == "high")
        + sum(2 for item in incidents if item.confidence == "medium"),
    )

    active_phases = {item.phase for item in attack_chain if item.event_count > 0}
    phase_score = min(12, len(active_phases) * 3)
    if {"执行", "持久化", "横向移动"} & active_phases:
        phase_score += 3
    if {"凭据访问", "命令控制"} & active_phases:
        phase_score += 3
    phase_score = min(18, phase_score)

    special_score = 0
    if any(a.rule_id.startswith("EVAS") for a in alerts):
        special_score += 8
    if any(a.rule_id.startswith("CRED") for a in alerts):
        special_score += 8
    if any(a.rule_id.startswith("LAT") or a.rule_id == "WIN-CHAIN-001" for a in alerts):
        special_score += 8
    if any(a.rule_id.startswith("PERS") for a in alerts):
        special_score += 5
    if any(a.rule_id.startswith(("WEB", "P0-", "CN-HVV")) for a in alerts):
        special_score += 4
    special_score = min(18, special_score)

    if not alerts and not incidents:
        # 没有检测结论时只给“观察分”，避免单靠事件量把风险抬得过高。
        observation_score = event_score + min(6, len(active_phases) * 2)
        return min(28, observation_score)

    score = event_score + alert_score + incident_score + confidence_score + phase_score + special_score
    return min(100, score)


def _gen_recommendations(alerts: List[DetectionAlert]) -> List[str]:
    recs = []
    seen: Set[str] = set()
    def add(r: str):
        if r not in seen:
            seen.add(r); recs.append(r)
    if any(a.rule_id.startswith(("BRUTE","SPRAY")) for a in alerts):
        add("【紧急】封锁攻击源 IP，启用账户锁定策略（5次失败锁定15分钟），部署多因素认证 (MFA)")
    if any(a.rule_id.startswith("EVAS") for a in alerts):
        add("【紧急】立即备份所有现有日志，将日志转发到独立 SIEM，防止进一步清除")
    if any(a.rule_id.startswith("CRED") for a in alerts):
        add("【紧急】假设所有凭据已泄露，强制重置所有账户密码，启用 Windows Credential Guard")
    if any(a.rule_id.startswith("PRIV") for a in alerts):
        add("【高危】审查特权账户使用，实施最小权限原则，检查所有新增的管理员账户")
    if any(a.rule_id == "WIN-CHAIN-001" for a in alerts):
        add("【严重】禁用可疑新建账号，移出管理员组，回溯来源 IP/工作站的 RDP、NTLM、EDR 与防火墙日志")
    if any(a.rule_id.startswith("PERS") for a in alerts):
        add("【高危】检查并删除所有可疑的服务、计划任务和用户账户")
    if any(a.rule_id.startswith("LAT") for a in alerts):
        add("【高危】隔离受影响主机，检查网络分段，审查所有横向移动路径")
    if any(a.rule_id.startswith("WEB") for a in alerts):
        add("【高危】部署 WAF，修复已识别的 Web 漏洞，检查是否有数据泄露")
    if any(a.rule_id.startswith("P0-C2") for a in alerts):
        add("【高危】核查 DNS/代理/防火墙外联链路，定位源主机进程并封禁恶意域名或 IP")
    if any(a.rule_id.startswith("P0-EXFIL") for a in alerts):
        add("【高危】核查疑似外传流量对应账号、文件和业务系统，评估敏感数据影响范围")
    if any(a.rule_id.startswith("P0-BASTION") for a in alerts):
        add("【高危】回放堡垒机会话，确认高危命令是否授权，检查目标主机后续进程和文件变化")
    if any(a.rule_id.startswith("P0-FW") for a in alerts):
        add("【高危】收敛公网或跨区敏感端口访问，复核防火墙/NAT 策略和资产暴露面")
    if any(a.rule_id.startswith("P0-EDR") for a in alerts):
        add("【高危】优先处置 EDR/XDR 高危终端告警，隔离失陷主机并导出进程树和样本 Hash")
    if any(a.rule_id.startswith("EXEC") for a in alerts):
        add("【中危】启用应用白名单 (AppLocker/WDAC)，限制 PowerShell 执行策略")
    if not recs:
        add("持续监控系统日志，保持安全补丁更新，定期进行安全审计")
    return recs


_DEFAULT_DETECTOR_REGISTRY = DetectorRegistry()
_DEFAULT_DETECTORS_REGISTERED = False


def get_default_detector_registry() -> DetectorRegistry:
    _ensure_default_detectors()
    return _DEFAULT_DETECTOR_REGISTRY


def register_detector(spec: DetectorSpec) -> None:
    get_default_detector_registry().register(spec)


def list_detector_names(profile: Optional[str] = None) -> List[str]:
    return get_default_detector_registry().names(profile)


def _ensure_default_detectors() -> None:
    global _DEFAULT_DETECTORS_REGISTERED
    if _DEFAULT_DETECTORS_REGISTERED:
        return
    for spec in (
        DetectorSpec("brute-force", detect_brute_force),
        DetectorSpec("password-spray", detect_password_spray),
        DetectorSpec("windows-account-remote-access-chain", detect_windows_account_remote_access_chain),
        DetectorSpec("privilege-escalation", detect_privilege_escalation),
        DetectorSpec("persistence", detect_persistence),
        DetectorSpec("defense-evasion", detect_defense_evasion),
        DetectorSpec("credential-access", detect_credential_access),
        DetectorSpec("suspicious-execution", detect_suspicious_execution),
        DetectorSpec("lateral-movement", detect_lateral_movement),
        DetectorSpec("web-attacks", detect_web_attacks),
        DetectorSpec("reconnaissance", detect_reconnaissance),
        DetectorSpec("p0-security", detect_p0_security_events),
        DetectorSpec("cn-hvv", detect_cn_hvv, profiles=normalize_profiles(("cn-hvv",))),
    ):
        _DEFAULT_DETECTOR_REGISTRY.register(spec)
    _DEFAULT_DETECTORS_REGISTERED = True
