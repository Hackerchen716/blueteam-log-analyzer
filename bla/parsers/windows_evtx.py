"""
Windows 事件日志解析器
支持格式:
  - XML 导出 (.xml)  — wevtutil epl Security Security.xml /lf:true
  - 二进制 EVTX (.evtx) — 需要 python-evtx 库（可选）
  - 纯文本事件导出

检测规则参考: Hayabusa / DeepBlueCLI / Sigma
"""

from __future__ import annotations
import re
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

from ..models import LogEvent, ParseResult, ParseStats, ThreatLevel
from ..utils.helpers import gen_id, normalize_timestamp, truncate

_LOGON_TYPE_MAP = {
    "2": "交互式",
    "3": "网络",
    "4": "批处理",
    "5": "服务",
    "7": "解锁",
    "8": "网络明文",
    "9": "新凭据",
    "10": "远程交互/RDP",
    "11": "缓存交互",
}


def _clean_win_value(value: str) -> str:
    value = (value or "").strip()
    return "" if value in ("-", "::1", "127.0.0.1", "::ffff:127.0.0.1") else value


def _pick_first(details: Dict[str, str], *keys: str) -> str:
    for key in keys:
        value = _clean_win_value(details.get(key, ""))
        if value:
            return value
    return ""


def _logon_type_label(logon_type: str) -> str:
    return _LOGON_TYPE_MAP.get((logon_type or "").strip(), "未知")


def _describe_network(details: Dict[str, str]) -> str:
    ip = _pick_first(details, "IpAddress", "SourceAddress")
    port = _pick_first(details, "IpPort")
    workstation = _pick_first(details, "WorkstationName")
    if ip and port:
        return f"{ip}:{port}"
    if ip:
        return ip
    if workstation:
        return workstation
    return "本地"


def _build_4624_message(details: Dict[str, str]) -> str:
    user = _pick_first(details, "TargetUserName", "SubjectUserName") or "?"
    domain = _pick_first(details, "TargetDomainName", "SubjectDomainName")
    domain_prefix = f"{domain}\\" if domain else ""
    logon_type = details.get("LogonType", "")
    logon_label = _logon_type_label(logon_type)
    auth_pkg = _pick_first(details, "AuthenticationPackageName")
    network = _describe_network(details)
    auth_part = f" 认证={auth_pkg}" if auth_pkg else ""
    return (
        f"登录成功: 账户={domain_prefix}{user} "
        f"登录类型={logon_type or '?'}({logon_label}) 来源={network}{auth_part}"
    )


def _build_4625_message(details: Dict[str, str]) -> str:
    user = _pick_first(details, "TargetUserName", "SubjectUserName") or "?"
    domain = _pick_first(details, "TargetDomainName", "SubjectDomainName")
    domain_prefix = f"{domain}\\" if domain else ""
    logon_type = details.get("LogonType", "")
    logon_label = _logon_type_label(logon_type)
    network = _describe_network(details)
    reason = _pick_first(details, "FailureReason")
    status = _pick_first(details, "Status")
    sub_status = _pick_first(details, "SubStatus")
    failure_bits = []
    if reason:
        failure_bits.append(reason)
    if status:
        failure_bits.append(f"Status={status}")
    if sub_status:
        failure_bits.append(f"SubStatus={sub_status}")
    failure_suffix = f" 失败原因={' | '.join(failure_bits)}" if failure_bits else ""
    return (
        f"登录失败: 账户={domain_prefix}{user} "
        f"登录类型={logon_type or '?'}({logon_label}) 来源={network}{failure_suffix}"
    )


def _augment_auth_details(eid: int, details: Dict[str, str]) -> None:
    if eid not in (4624, 4625):
        return

    details["account_name"] = _pick_first(details, "TargetUserName", "SubjectUserName")
    details["account_domain"] = _pick_first(details, "TargetDomainName", "SubjectDomainName")
    details["source_ip"] = _pick_first(details, "IpAddress", "SourceAddress")
    details["source_port"] = _pick_first(details, "IpPort")
    details["workstation"] = _pick_first(details, "WorkstationName")
    details["logon_type_label"] = _logon_type_label(details.get("LogonType", ""))
    details["logon_process"] = _pick_first(details, "LogonProcessName")
    details["auth_package"] = _pick_first(details, "AuthenticationPackageName")
    details["process_name"] = _pick_first(details, "ProcessName")
    details["failure_reason"] = _pick_first(details, "FailureReason")
    details["status_code"] = _pick_first(details, "Status")
    details["sub_status_code"] = _pick_first(details, "SubStatus")
    details["subject_user"] = _pick_first(details, "SubjectUserName")
    details["subject_domain"] = _pick_first(details, "SubjectDomainName")


def _augment_4688_details(eid: int, details: Dict[str, str]) -> None:
    if eid != 4688:
        return

    parent = _pick_first(details, "ParentProcessName", "CreatorProcessName")
    child_path = _pick_first(details, "NewProcessName", "ProcessName")
    child = ""
    if child_path:
        child = child_path.replace("/", "\\").rsplit("\\", 1)[-1]

    details["parent_process"] = parent
    details["child_process"] = child
    details["child_path"] = child_path
    details["command_line"] = _pick_first(details, "CommandLine")

# Windows 事件 ID 规则库
# 格式: event_id -> (level, category, message_fn, tags, mitre, rule_name)
_WIN_RULES: Dict[int, dict] = {
    # ── 认证 ──────────────────────────────────────────────
    4624: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logon"],
               mitre="T1078",      rule="登录成功",
               msg=_build_4624_message),
    4625: dict(level=ThreatLevel.MEDIUM,   cat="认证",    tags=["failed-logon","brute-force"],
               mitre="T1110.001",  rule="登录失败",
               msg=_build_4625_message),
    4648: dict(level=ThreatLevel.MEDIUM,   cat="认证",    tags=["explicit-creds","lateral-movement"],
               mitre="T1550",      rule="显式凭据登录",
               msg=lambda d: f"显式凭据登录: {d.get('SubjectUserName','?')} -> {d.get('TargetServerName','?')}"),
    4672: dict(level=ThreatLevel.INFO,     cat="权限",    tags=["privilege","admin"],
               mitre="T1078.002",  rule="特权账户登录",
               msg=lambda d: f"特权登录: {d.get('SubjectUserName','?')} 获得特殊权限"),
    4768: dict(level=ThreatLevel.INFO,     cat="Kerberos",tags=["kerberos","tgt"],
               mitre="T1558",      rule="Kerberos TGT 请求",
               msg=lambda d: f"Kerberos TGT: {d.get('TargetUserName','?')} 来自 {d.get('IpAddress','?')}"),
    4769: dict(level=ThreatLevel.INFO,     cat="Kerberos",tags=["kerberos","tgs"],
               mitre="T1558",      rule="Kerberos 服务票据",
               msg=lambda d: f"Kerberos TGS: {d.get('TargetUserName','?')} -> {d.get('ServiceName','?')}"),
    4771: dict(level=ThreatLevel.MEDIUM,   cat="Kerberos",tags=["kerberos","failed","brute-force"],
               mitre="T1110",      rule="Kerberos 预认证失败",
               msg=lambda d: f"Kerberos 预认证失败: {d.get('TargetUserName','?')} 来自 {d.get('IpAddress','?')}"),
    4776: dict(level=ThreatLevel.MEDIUM,   cat="认证",    tags=["ntlm","authentication"],
               mitre="T1110.001",  rule="NTLM 凭据校验",
               msg=lambda d: f"NTLM 校验: {d.get('TargetUserName','?')} 来自 {d.get('Workstation','?')} 状态={d.get('Status','0x0')}"),
    4634: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logoff"],
               mitre=None,         rule="账户注销",
               msg=lambda d: f"注销: 用户={d.get('TargetUserName','?')} 类型={d.get('LogonType','?')}"),
    4647: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logoff","user-initiated"],
               mitre=None,         rule="用户主动注销",
               msg=lambda d: f"用户主动注销: {d.get('TargetUserName','?')}"),
    4673: dict(level=ThreatLevel.MEDIUM,   cat="权限",    tags=["privilege","sensitive-call"],
               mitre="T1078.002",  rule="敏感特权调用",
               msg=lambda d: f"敏感特权调用: {d.get('SubjectUserName','?')} 服务={d.get('Service','?')}"),
    4740: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["account-lockout","brute-force"],
               mitre="T1110",      rule="账户锁定",
               msg=lambda d: f"账户被锁定: {d.get('TargetUserName','?')} 来自 {d.get('TargetDomainName','?')}"),
    4738: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["account-modified"],
               mitre="T1098",      rule="账户属性变更",
               msg=lambda d: f"账户属性变更: {d.get('TargetUserName','?')} 由 {d.get('SubjectUserName','?')}"),

    # ── 账户管理 ──────────────────────────────────────────
    4720: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["account-creation","persistence"],
               mitre="T1136",      rule="创建用户账户",
               msg=lambda d: f"创建新账户: {d.get('TargetUserName','?')} 由 {d.get('SubjectUserName','?')}"),
    4722: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["account-enabled"],
               mitre="T1078",      rule="账户已启用",
               msg=lambda d: f"账户启用: {d.get('TargetUserName','?')}"),
    4723: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["password-change"],
               mitre="T1098",      rule="密码修改",
               msg=lambda d: f"密码修改: {d.get('TargetUserName','?')}"),
    4724: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["password-reset","privilege-escalation"],
               mitre="T1098",      rule="密码重置",
               msg=lambda d: f"密码重置: {d.get('TargetUserName','?')} 由 {d.get('SubjectUserName','?')}"),
    4725: dict(level=ThreatLevel.MEDIUM,   cat="账户管理",tags=["account-disabled"],
               mitre="T1531",      rule="账户已禁用",
               msg=lambda d: f"账户禁用: {d.get('TargetUserName','?')}"),
    4726: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["account-deletion"],
               mitre="T1531",      rule="删除用户账户",
               msg=lambda d: f"删除账户: {d.get('TargetUserName','?')}"),
    4728: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["group-add","privilege-escalation"],
               mitre="T1098.001",  rule="添加到全局组",
               msg=lambda d: f"添加到全局组: {d.get('MemberName','?')} -> {d.get('TargetUserName','?')}"),
    4732: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["group-add","privilege-escalation"],
               mitre="T1098.001",  rule="添加到本地组",
               msg=lambda d: f"添加到本地组: {d.get('MemberName','?')} -> {d.get('TargetUserName','?')}"),
    4756: dict(level=ThreatLevel.HIGH,     cat="账户管理",tags=["group-add","privilege-escalation"],
               mitre="T1098.001",  rule="添加到通用组",
               msg=lambda d: f"添加到通用组: {d.get('MemberName','?')} -> {d.get('TargetUserName','?')}"),

    # ── 进程 ──────────────────────────────────────────────
    4688: dict(level=ThreatLevel.INFO,     cat="进程",    tags=["process-creation"],
               mitre="T1059",      rule="进程创建",
               msg=lambda d: f"进程创建: {d.get('NewProcessName','?')} 参数: {truncate(d.get('CommandLine',''),80)}"),
    4689: dict(level=ThreatLevel.INFO,     cat="进程",    tags=["process-exit"],
               mitre=None,         rule="进程退出",
               msg=lambda d: f"进程退出: {d.get('ProcessName','?')}"),

    # ── 服务 ──────────────────────────────────────────────
    7045: dict(level=ThreatLevel.HIGH,     cat="服务",    tags=["service-install","persistence"],
               mitre="T1543.003",  rule="安装新服务",
               msg=lambda d: f"安装服务: {d.get('ServiceName','?')} 路径={d.get('ImagePath','?')}"),
    7036: dict(level=ThreatLevel.INFO,     cat="服务",    tags=["service-state"],
               mitre=None,         rule="服务状态变更",
               msg=lambda d: f"服务状态: {d.get('param1','?')} -> {d.get('param2','?')}"),

    # ── 计划任务 ──────────────────────────────────────────
    4698: dict(level=ThreatLevel.HIGH,     cat="计划任务",tags=["scheduled-task","persistence"],
               mitre="T1053.005",  rule="创建计划任务",
               msg=lambda d: f"创建计划任务: {d.get('TaskName','?')} 由 {d.get('SubjectUserName','?')}"),
    4702: dict(level=ThreatLevel.MEDIUM,   cat="计划任务",tags=["scheduled-task","persistence"],
               mitre="T1053.005",  rule="修改计划任务",
               msg=lambda d: f"修改计划任务: {d.get('TaskName','?')}"),
    4699: dict(level=ThreatLevel.MEDIUM,   cat="计划任务",tags=["scheduled-task"],
               mitre="T1053.005",  rule="删除计划任务",
               msg=lambda d: f"删除计划任务: {d.get('TaskName','?')}"),

    # ── 日志/审计 ─────────────────────────────────────────
    1102: dict(level=ThreatLevel.CRITICAL, cat="日志操作",tags=["log-cleared","defense-evasion","anti-forensics"],
               mitre="T1070.001",  rule="安全日志清除",
               msg=lambda d: f"安全审计日志已被清除！操作者: {d.get('SubjectUserName','?')}"),
    104:  dict(level=ThreatLevel.CRITICAL, cat="日志操作",tags=["log-cleared","defense-evasion","anti-forensics"],
               mitre="T1070.001",  rule="系统日志清除",
               msg=lambda d: "系统日志已被清除！"),
    4719: dict(level=ThreatLevel.CRITICAL, cat="策略",    tags=["audit-policy","defense-evasion"],
               mitre="T1562.002",  rule="审计策略修改",
               msg=lambda d: f"审计策略被修改: {d.get('SubjectUserName','?')}"),

    # ── PowerShell ────────────────────────────────────────
    4103: dict(level=ThreatLevel.MEDIUM,   cat="PowerShell",tags=["powershell","execution"],
               mitre="T1059.001",  rule="PowerShell 模块日志",
               msg=lambda d: f"PS模块: {truncate(d.get('Payload',''),100)}"),
    4104: dict(level=ThreatLevel.MEDIUM,   cat="PowerShell",tags=["powershell","script-block","execution"],
               mitre="T1059.001",  rule="PowerShell 脚本块",
               msg=lambda d: f"PS脚本块: {truncate(d.get('ScriptBlockText',''),100)}"),

    # ── 网络 ──────────────────────────────────────────────
    5156: dict(level=ThreatLevel.INFO,     cat="网络",    tags=["network","connection"],
               mitre="T1071",      rule="网络连接允许",
               msg=lambda d: f"网络连接: {d.get('Application','?')} -> {d.get('DestAddress','?')}:{d.get('DestPort','?')}"),
    5157: dict(level=ThreatLevel.MEDIUM,   cat="网络",    tags=["network","blocked"],
               mitre=None,         rule="网络连接阻止",
               msg=lambda d: f"连接阻止: {d.get('Application','?')} -> {d.get('DestAddress','?')}:{d.get('DestPort','?')}"),

    # ── RDP ───────────────────────────────────────────────
    4778: dict(level=ThreatLevel.MEDIUM,   cat="RDP",     tags=["rdp","lateral-movement"],
               mitre="T1021.001",  rule="RDP 会话重连",
               msg=lambda d: f"RDP重连: {d.get('AccountName','?')} 来自 {d.get('ClientAddress','?')}"),
    4779: dict(level=ThreatLevel.INFO,     cat="RDP",     tags=["rdp"],
               mitre="T1021.001",  rule="RDP 会话断开",
               msg=lambda d: f"RDP断开: {d.get('AccountName','?')}"),

    # ── 文件共享 / 横向移动 ───────────────────────────────
    5140: dict(level=ThreatLevel.MEDIUM,   cat="文件共享",tags=["smb","lateral-movement","file-share"],
               mitre="T1021.002",  rule="文件共享访问",
               msg=lambda d: f"文件共享访问: {d.get('SubjectUserName','?')} -> {d.get('ShareName','?')} 来自 {d.get('IpAddress','?')}"),
    5145: dict(level=ThreatLevel.MEDIUM,   cat="文件共享",tags=["smb","lateral-movement","file-share"],
               mitre="T1021.002",  rule="共享对象访问",
               msg=lambda d: f"共享对象访问: {d.get('SubjectUserName','?')} -> {d.get('ShareName','?')}/{d.get('RelativeTargetName','?')}"),

    # ── Sysmon ────────────────────────────────────────────
    1:    dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","process-creation"],
               mitre="T1059",      rule="Sysmon 进程创建",
               msg=lambda d: f"[Sysmon] 进程: {d.get('Image','?')} 参数: {truncate(d.get('CommandLine',''),80)}"),
    3:    dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","network"],
               mitre="T1071",      rule="Sysmon 网络连接",
               msg=lambda d: f"[Sysmon] 网络: {d.get('Image','?')} -> {d.get('DestinationIp','?')}:{d.get('DestinationPort','?')}"),
    7:    dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","image-load","dll-injection"],
               mitre="T1055",      rule="Sysmon 镜像加载",
               msg=lambda d: f"[Sysmon] DLL加载: {d.get('ImageLoaded','?')} by {d.get('Image','?')}"),
    8:    dict(level=ThreatLevel.HIGH,     cat="Sysmon",  tags=["sysmon","remote-thread","injection"],
               mitre="T1055",      rule="Sysmon 远程线程",
               msg=lambda d: f"[Sysmon] 远程线程: {d.get('SourceImage','?')} -> {d.get('TargetImage','?')}"),
    10:   dict(level=ThreatLevel.HIGH,     cat="Sysmon",  tags=["sysmon","process-access","lsass"],
               mitre="T1003.001",  rule="Sysmon 进程访问",
               msg=lambda d: f"[Sysmon] 进程访问: {d.get('SourceImage','?')} -> {d.get('TargetImage','?')}"),
    11:   dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","file-creation"],
               mitre=None,         rule="Sysmon 文件创建",
               msg=lambda d: f"[Sysmon] 文件创建: {d.get('TargetFilename','?')}"),
    12:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","registry"],
               mitre="T1547",      rule="Sysmon 注册表操作",
               msg=lambda d: f"[Sysmon] 注册表: {d.get('EventType','?')} {d.get('TargetObject','?')}"),
    13:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","registry","persistence"],
               mitre="T1547",      rule="Sysmon 注册表修改",
               msg=lambda d: f"[Sysmon] 注册表修改: {d.get('TargetObject','?')} = {truncate(d.get('Details',''),50)}"),
    15:   dict(level=ThreatLevel.MEDIUM,   cat="Sysmon",  tags=["sysmon","ads","defense-evasion"],
               mitre="T1564.004",  rule="Sysmon ADS 创建",
               msg=lambda d: f"[Sysmon] ADS创建: {d.get('TargetFilename','?')}"),
    22:   dict(level=ThreatLevel.INFO,     cat="Sysmon",  tags=["sysmon","dns"],
               mitre="T1071.004",  rule="Sysmon DNS 查询",
               msg=lambda d: f"[Sysmon] DNS: {d.get('Image','?')} 查询 {d.get('QueryName','?')}"),
    25:   dict(level=ThreatLevel.HIGH,     cat="Sysmon",  tags=["sysmon","process-tampering"],
               mitre="T1055",      rule="Sysmon 进程篡改",
               msg=lambda d: f"[Sysmon] 进程篡改: {d.get('Image','?')}"),
}

# 高危进程/命令关键词 -> 动态升级级别
_DANGEROUS_CMDS = re.compile(
    r'mimikatz|meterpreter|cobalt.?strike|empire|powersploit|invoke-mimikatz|'
    r'invoke-expression.*download|net\.webclient|downloadstring|downloadfile|'
    r'bypass.*execution|encodedcommand|-enc\s|base64.*decode|'
    r'lsadump|sekurlsa|kerberos::ptt|privilege::debug|'
    r'procdump.*lsass|tasklist.*lsass|rundll32.*comsvcs',
    re.IGNORECASE
)

_LOLBINS = re.compile(
    r'mshta\.exe|wscript\.exe|cscript\.exe|'
    r'regsvr32.*scrobj|rundll32.*javascript|'
    r'certutil.*-decode|certutil.*-urlcache|'
    r'bitsadmin.*transfer|forfiles.*cmd|'
    r'pcalua.*-a|syncappvpublishingserver',
    re.IGNORECASE
)


def _classify_event(eid: int, details: Dict[str, str], channel: str) -> Tuple[ThreatLevel, str, str, list, Optional[str], Optional[str]]:
    """返回 (level, category, message, tags, mitre, rule_name)"""
    rule = _WIN_RULES.get(eid)
    if not rule:
        return ThreatLevel.INFO, channel or "Windows", f"事件 ID {eid}", [], None, None

    level = rule["level"]
    msg   = rule["msg"](details)
    tags  = list(rule["tags"])

    # 动态级别升级
    if eid == 4625:
        lt = _safe_int(details.get("LogonType", "0"))
        if lt in (3, 10):
            level = ThreatLevel.HIGH  # 网络/RDP 失败登录更危险

    if eid in (4688, 1):
        cmd = details.get("CommandLine", "") + details.get("NewProcessName", "") + details.get("Image", "")
        if _DANGEROUS_CMDS.search(cmd):
            level = ThreatLevel.CRITICAL
            tags.append("malware-indicator")
        elif _LOLBINS.search(cmd):
            level = ThreatLevel.HIGH
            tags.append("lolbin")

    if eid == 4104:
        script = details.get("ScriptBlockText", "")
        if _DANGEROUS_CMDS.search(script):
            level = ThreatLevel.CRITICAL
            tags.append("malware-indicator")
        elif re.search(r'invoke-|iex\s*\(|base64|webclient|downloadstring', script, re.I):
            level = ThreatLevel.HIGH

    if eid == 10:  # Sysmon 进程访问
        target = details.get("TargetImage", "").lower()
        if "lsass" in target:
            level = ThreatLevel.CRITICAL
            tags.append("lsass-dump")

    return level, rule["cat"], msg, tags, rule.get("mitre"), rule.get("rule")


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _parse_xml_event_with_error(xml_text: str, source_file: str) -> Tuple[Optional[LogEvent], Optional[Exception]]:
    """解析单个 <Event> XML 块，并返回异常对象（如有）便于上层统计错误数。"""
    try:
        return _parse_xml_event(xml_text, source_file), None
    except Exception as e:  # noqa: BLE001 — XML 行级失败不应中断整个分析
        return None, e


def _parse_xml_event(xml_text: str, source_file: str) -> Optional[LogEvent]:
    """解析单个 <Event> XML 块。

    解析异常会向上抛出，由 :func:`_parse_xml_event_with_error` 捕获并记入
    ``ParseStats.parse_errors``，避免静默丢事件。
    """

    xml_clean = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', xml_text)
    root = ET.fromstring(xml_clean)

    sys_el = root.find("System")
    if sys_el is None:
        return None

    def gtag(tag: str) -> str:
        el = sys_el.find(tag)
        return el.text.strip() if el is not None and el.text else ""

    eid_str = gtag("EventID") or ""
    eid = int(eid_str) if eid_str.isdigit() else 0
    ts_raw = ""
    tc = sys_el.find("TimeCreated")
    if tc is not None:
        ts_raw = tc.get("SystemTime", "")
    computer = gtag("Computer")
    channel  = gtag("Channel")

    # EventData
    details: Dict[str, str] = {}
    ed = root.find("EventData")
    if ed is not None:
        for data in ed.findall("Data"):
            name = data.get("Name", "")
            val  = data.text or ""
            if name:
                details[name] = val.strip()

    _augment_auth_details(eid, details)
    _augment_4688_details(eid, details)

    user    = details.get("account_name") or details.get("TargetUserName") or details.get("SubjectUserName") or ""
    ip      = details.get("source_ip") or details.get("IpAddress") or details.get("SourceAddress") or ""
    process = details.get("NewProcessName") or details.get("ProcessName") or details.get("Image") or ""

    level, cat, msg, tags, mitre, rule_name = _classify_event(eid, details, channel)

    return LogEvent(
        id          = gen_id("win"),
        timestamp   = normalize_timestamp(ts_raw),
        level       = level,
        category    = cat,
        source      = f"{channel} (EID:{eid_str})",
        source_file = source_file,
        message     = msg,
        raw_line    = xml_text[:300],
        event_id    = eid_str,
        user        = user or None,
        host        = computer or None,
        ip          = ip or None,
        process     = process or None,
        details     = details,
        tags        = tags,
        mitre_attack= mitre,
        rule_id     = f"WIN-{eid_str}",
        rule_name   = rule_name,
    )


def parse_windows_xml(content: str, source_file: str) -> ParseResult:
    """解析 Windows XML 事件日志"""
    t0 = time.time()
    events: List[LogEvent] = []
    parse_errors = 0

    # 逐块提取 <Event>...</Event>
    pattern = re.compile(r'<Event[\s>][\s\S]*?</Event>', re.IGNORECASE)
    for m in pattern.finditer(content):
        ev, err = _parse_xml_event_with_error(m.group(), source_file)
        if ev:
            events.append(ev)
        elif err:
            parse_errors += 1

    stats = _compute_stats(events)
    stats.parse_errors = parse_errors
    return ParseResult(
        file_name      = source_file,
        log_type       = "Windows Event Log (XML)",
        events         = events,
        stats          = stats,
        parse_time_ms  = (time.time() - t0) * 1000,
        file_size_bytes= len(content.encode()),
    )


def parse_windows_evtx(path: str) -> ParseResult:
    """
    解析二进制 EVTX 文件（需要 python-evtx）
    如未安装则返回提示事件
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views  # noqa: F401  imported for side effects
        t0 = time.time()
        events: List[LogEvent] = []
        parse_errors = 0
        with evtx.Evtx(path) as log:
            for record in log.records():
                try:
                    xml_text = record.xml()
                except Exception:
                    parse_errors += 1
                    continue
                ev, err = _parse_xml_event_with_error(xml_text, path)
                if ev:
                    events.append(ev)
                elif err:
                    parse_errors += 1
        stats = _compute_stats(events)
        stats.parse_errors = parse_errors
        return ParseResult(
            file_name     = path,
            log_type      = "Windows EVTX (Binary)",
            events        = events,
            stats         = stats,
            parse_time_ms = (time.time() - t0) * 1000,
        )
    except ImportError:
        hint = LogEvent(
            id="hint-evtx", timestamp="", level=ThreatLevel.INFO,
            category="提示", source="Parser", source_file=path,
            message=(
                "检测到 .evtx 二进制格式。\n"
                "方法1 (推荐): pip install python-evtx 后重新运行\n"
                "方法2: wevtutil epl Security out.xml /lf:true  (Windows)\n"
                "方法3: python-evtx 附带的 evtx_dump.py 转换为 XML"
            ),
            raw_line="",
            details={}, tags=["info"],
        )
        stats = _compute_stats([])
        return ParseResult(file_name=path, log_type="Windows EVTX (需转换)", events=[hint], stats=stats)


def _compute_stats(events: List[LogEvent]) -> ParseStats:
    from ..parsers.stats import compute_stats
    return compute_stats(events)
