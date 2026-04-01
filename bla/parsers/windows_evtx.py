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

# Windows 事件 ID 规则库
# 格式: event_id -> (level, category, message_fn, tags, mitre, rule_name)
_WIN_RULES: Dict[int, dict] = {
    # ── 认证 ──────────────────────────────────────────────
    4624: dict(level=ThreatLevel.INFO,     cat="认证",    tags=["logon"],
               mitre="T1078",      rule="登录成功",
               msg=lambda d: f"登录成功: 用户={d.get('TargetUserName','?')} 类型={d.get('LogonType','?')} 来源={d.get('IpAddress',d.get('WorkstationName','本地'))}"),
    4625: dict(level=ThreatLevel.MEDIUM,   cat="认证",    tags=["failed-logon","brute-force"],
               mitre="T1110.001",  rule="登录失败",
               msg=lambda d: f"登录失败: 用户={d.get('TargetUserName','?')} 来源={d.get('IpAddress','?')} 类型={d.get('LogonType','?')}"),
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
        lt = int(details.get("LogonType", "0"))
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


def _parse_xml_event(xml_text: str, source_file: str) -> Optional[LogEvent]:
    """解析单个 <Event> XML 块"""
    try:
        # 去掉命名空间简化解析
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

        user    = details.get("SubjectUserName") or details.get("TargetUserName") or ""
        ip      = details.get("IpAddress") or details.get("SourceAddress") or ""
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
    except Exception:
        return None


def parse_windows_xml(content: str, source_file: str) -> ParseResult:
    """解析 Windows XML 事件日志"""
    t0 = time.time()
    events: List[LogEvent] = []

    # 逐块提取 <Event>...</Event>
    pattern = re.compile(r'<Event[\s>][\s\S]*?</Event>', re.IGNORECASE)
    for m in pattern.finditer(content):
        ev = _parse_xml_event(m.group(), source_file)
        if ev:
            events.append(ev)

    stats = _compute_stats(events)
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
        import Evtx.Views as e_views
        t0 = time.time()
        events: List[LogEvent] = []
        with evtx.Evtx(path) as log:
            for record in log.records():
                xml_text = record.xml()
                ev = _parse_xml_event(xml_text, path)
                if ev:
                    events.append(ev)
        stats = _compute_stats(events)
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
