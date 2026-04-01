"""
威胁检测引擎核心逻辑
"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import List, Dict, Set

from ..models import (
    LogEvent, DetectionAlert, TimelineEntry, AttackChainEntry,
    AnalysisSummary, ThreatLevel
)
from ..utils.helpers import gen_id


def run_detection(events: List[LogEvent]) -> AnalysisSummary:
    alerts: List[DetectionAlert] = []
    alerts += detect_brute_force(events)
    alerts += detect_password_spray(events)
    alerts += detect_privilege_escalation(events)
    alerts += detect_persistence(events)
    alerts += detect_defense_evasion(events)
    alerts += detect_credential_access(events)
    alerts += detect_suspicious_execution(events)
    alerts += detect_lateral_movement(events)
    alerts += detect_web_attacks(events)
    alerts += detect_reconnaissance(events)
    alerts = _dedup_alerts(alerts)

    lvl_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda a: lvl_order.get(a.level.value, 9))

    timeline     = _build_timeline(events)
    attack_chain = _build_attack_chain(events, alerts)
    risk_score   = _calc_risk_score(events, alerts)
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
    )


def detect_brute_force(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    failed_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if any(t in ev.tags for t in ("failed-login", "failed-logon")) and ev.ip:
            failed_by_ip[ev.ip].append(ev)
    for ip, evts in failed_by_ip.items():
        n = len(evts)
        if n < 5:
            continue
        level = ThreatLevel.CRITICAL if n >= 50 else ThreatLevel.HIGH if n >= 20 else ThreatLevel.MEDIUM
        users = sorted(set(e.user for e in evts if e.user))
        ts_sorted = sorted(evts, key=lambda e: e.timestamp)
        alerts.append(DetectionAlert(
            id="a"+gen_id("bf"), rule_id="BRUTE-001", rule_name="暴力破解攻击",
            description=f"来自 {ip} 的暴力破解，共失败 {n} 次，目标: {', '.join(users[:5])}{'...' if len(users)>5 else ''}",
            level=level, category="暴力破解", mitre_attack="T1110.001", mitre_phase="凭据访问",
            affected_events=[e.id for e in evts],
            evidence=[f"攻击源IP: {ip}", f"失败次数: {n}", f"目标账户数: {len(users)}",
                      f"时间: {ts_sorted[0].timestamp} ~ {ts_sorted[-1].timestamp}"],
            recommendation=f"立即封锁 IP {ip}，检查是否有成功登录，启用账户锁定策略和 MFA",
            timestamp=ts_sorted[-1].timestamp, confidence="high" if n >= 20 else "medium",
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
        if len(unique_users) < 5:
            continue
        avg = len(evts) / len(unique_users)
        if avg > 3:
            continue
        alerts.append(DetectionAlert(
            id="a"+gen_id("sp"), rule_id="SPRAY-001", rule_name="密码喷洒攻击",
            description=f"来自 {ip} 的密码喷洒，针对 {len(unique_users)} 个账户，平均每账户 {avg:.1f} 次",
            level=ThreatLevel.HIGH, category="密码喷洒", mitre_attack="T1110.003", mitre_phase="凭据访问",
            affected_events=[e.id for e in evts],
            evidence=[f"攻击源IP: {ip}", f"目标账户数: {len(unique_users)}", f"总尝试: {len(evts)}",
                      f"目标: {', '.join(list(unique_users)[:5])}"],
            recommendation="密码喷洒绕过锁定策略，检查所有目标账户是否有成功登录，实施异常登录检测",
            timestamp=max(e.timestamp for e in evts), confidence="high",
        ))
    return alerts


def detect_privilege_escalation(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    group_events = [e for e in events if any(t in e.tags for t in ("group-add",)) and e.event_id in ("4728","4732","4756")]
    for ev in group_events:
        alerts.append(DetectionAlert(
            id="a"+gen_id("pe"), rule_id="PRIV-001", rule_name="账户添加到特权组",
            description=ev.message, level=ThreatLevel.HIGH, category="权限提升",
            mitre_attack="T1098.001", mitre_phase="权限提升", affected_events=[ev.id],
            evidence=[ev.message, f"操作者: {ev.user or '?'}", f"时间: {ev.timestamp}"],
            recommendation="验证此操作是否经过授权，检查添加的账户是否为合法管理员",
            timestamp=ev.timestamp, confidence="high",
        ))
    sudo_denied = [e for e in events if "sudo-denied" in e.tags]
    if len(sudo_denied) >= 3:
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
    for ev in [e for e in events if "account-creation" in e.tags]:
        alerts.append(DetectionAlert(
            id="a"+gen_id("pa"), rule_id="PERS-003", rule_name="创建新用户账户",
            description=ev.message, level=ThreatLevel.HIGH, category="持久化",
            mitre_attack="T1136", mitre_phase="持久化", affected_events=[ev.id],
            evidence=[ev.message, f"时间: {ev.timestamp}"],
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
    mimi = [e for e in events if "malware-indicator" in e.tags or
            re.search(r'mimikatz|lsadump|sekurlsa|kerberos::ptt|privilege::debug',
                      e.message + e.raw_line, re.I)]
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
    explicit = [e for e in events if "explicit-creds" in e.tags]
    if len(explicit) >= 3:
        targets = sorted(set(e.details.get("TargetServerName","") for e in explicit if e.details.get("TargetServerName")))
        alerts.append(DetectionAlert(
            id="a"+gen_id("ec"), rule_id="LAT-002", rule_name="显式凭据横向移动 (Pass-the-Hash 指示器)",
            description=f"检测到 {len(explicit)} 次显式凭据使用，目标: {', '.join(targets[:3])}",
            level=ThreatLevel.HIGH, category="横向移动",
            mitre_attack="T1550.002", mitre_phase="横向移动",
            affected_events=[e.id for e in explicit], evidence=[e.message for e in explicit[:3]],
            recommendation="检查凭据使用模式，确认是否存在 Pass-the-Hash，审查网络访问日志",
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
        critical_count = sum(1 for e in evts if e.level == ThreatLevel.CRITICAL)
        level = (ThreatLevel.CRITICAL if critical_count > 0 else
                 ThreatLevel.HIGH if len(evts) >= 10 else ThreatLevel.MEDIUM)
        ips = sorted(set(e.ip for e in evts if e.ip))
        alerts.append(DetectionAlert(
            id="a"+gen_id("wa"), rule_id=f"WEB-{attack_type[:4].upper()}",
            rule_name=f"Web攻击: {attack_type}",
            description=f"检测到 {len(evts)} 次 {attack_type} 攻击尝试",
            level=level, category="Web攻击",
            mitre_attack=mitre_map.get(attack_type,"T1190"), mitre_phase="初始访问",
            affected_events=[e.id for e in evts],
            evidence=[f"类型: {attack_type}", f"次数: {len(evts)}",
                      f"来源IP: {', '.join(ips[:3])}", f"示例: {evts[0].message}"],
            recommendation=f"修复 {attack_type} 漏洞，部署 WAF，封锁攻击源 IP",
            timestamp=max(e.timestamp for e in evts),
            confidence="high" if critical_count > 0 else "medium",
        ))
    return alerts


def detect_reconnaissance(events: List[LogEvent]) -> List[DetectionAlert]:
    alerts = []
    scan_events = [e for e in events if any(t in e.tags for t in ("scanning","scanner"))]
    if len(scan_events) >= 5:
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
    if len(recon_events) >= 10:
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


def _dedup_alerts(alerts: List[DetectionAlert]) -> List[DetectionAlert]:
    seen: Set[str] = set()
    result = []
    for a in alerts:
        key = f"{a.rule_id}:{a.description[:50]}"
        if key not in seen:
            seen.add(key)
            result.append(a)
    return result


def _build_timeline(events: List[LogEvent]) -> List[TimelineEntry]:
    significant = [e for e in events if e.level.score >= ThreatLevel.MEDIUM.score or e.mitre_attack]
    significant.sort(key=lambda e: e.timestamp)
    return [TimelineEntry(timestamp=e.timestamp, level=e.level, category=e.category,
                          message=e.message, event_id=e.id, source_file=e.source_file,
                          mitre_attack=e.mitre_attack) for e in significant[:500]]


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


def _calc_risk_score(events: List[LogEvent], alerts: List[DetectionAlert]) -> int:
    score = 0
    score += sum(1 for e in events if e.level == ThreatLevel.CRITICAL) * 8
    score += sum(1 for e in events if e.level == ThreatLevel.HIGH)     * 4
    score += sum(1 for e in events if e.level == ThreatLevel.MEDIUM)   * 1
    score += sum(1 for a in alerts if a.level == ThreatLevel.CRITICAL) * 15
    score += sum(1 for a in alerts if a.level == ThreatLevel.HIGH)     * 8
    score += sum(1 for a in alerts if a.level == ThreatLevel.MEDIUM)   * 3
    if any(a.rule_id.startswith("EVAS") for a in alerts): score += 25
    if any(a.rule_id.startswith("CRED") for a in alerts): score += 25
    if any(a.rule_id == "BRUTE-001" for a in alerts):     score += 10
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
    if any(a.rule_id.startswith("PERS") for a in alerts):
        add("【高危】检查并删除所有可疑的服务、计划任务和用户账户")
    if any(a.rule_id.startswith("LAT") for a in alerts):
        add("【高危】隔离受影响主机，检查网络分段，审查所有横向移动路径")
    if any(a.rule_id.startswith("WEB") for a in alerts):
        add("【高危】部署 WAF，修复已识别的 Web 漏洞，检查是否有数据泄露")
    if any(a.rule_id.startswith("EXEC") for a in alerts):
        add("【中危】启用应用白名单 (AppLocker/WDAC)，限制 PowerShell 执行策略")
    if not recs:
        add("持续监控系统日志，保持安全补丁更新，定期进行安全审计")
    return recs
